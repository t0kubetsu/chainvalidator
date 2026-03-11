#!/usr/bin/env python3
"""
DNSSEC Chain-of-Trust Validator
================================

Validates the full chain: Trust Anchor → . → TLD → SLD → domain.

CLI usage
---------
.. code-block:: shell

    python chainvalidator.py example.com
    python chainvalidator.py example.com --type AAAA
    python chainvalidator.py example.com --type MX --timeout 10
    python chainvalidator.py example.com -l DEBUG
    python chainvalidator.py example.com -l WARNING   # errors/warnings only
    python chainvalidator.py example.com -l ERROR     # silent on success

Module usage
------------
.. code-block:: python

    from chainvalidator import DNSSECChecker, validate
    import logging

    # The module uses the "chainvalidator" logger — attach a handler as needed:
    logging.getLogger("chainvalidator").setLevel(logging.DEBUG)

    # High-level one-shot helper
    result = validate("example.com", record_type="A")
    # result.status   → "secure" | "insecure" | "bogus"
    # result.errors   → list[str]
    # result.warnings → list[str]

    # Low-level checker
    checker = DNSSECChecker("example.com", record_type="A")
    ok = checker.check()   # True=secure, None=insecure, False=bogus

Log levels
----------
.. list-table::
   :header-rows: 1

   * - Level
     - Content
   * - ``DEBUG``
     - Per-query detail: NS chosen, keytag listings, raw DS wire, RRSIG expiry
   * - ``INFO``
     - Chain-of-trust milestones: zone headers, DS/DNSKEY matches, final verdict
   * - ``WARNING``
     - Insecure delegations, NXDOMAIN, unsigned zones
   * - ``ERROR``
     - Validation failures (bogus chain)

Exit codes (CLI)
----------------
.. list-table::
   :header-rows: 1

   * - Code
     - Meaning
   * - ``0``
     - Fully secure
   * - ``1``
     - Bogus / validation failed
   * - ``2``
     - Insecure delegation (chain not anchored end-to-end)

Requirements
------------
.. code-block:: shell

    pip install dnspython[dnssec] requests
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import logging
import secrets
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.resolver
import dns.rrset
import requests
from dns.rdata import Rdata

# ─── Logger ──────────────────────────────────────────────────────────────────
# No handler is attached here so that library callers retain full control.
# The CLI configures a StreamHandler in main() based on --log-level.

logger = logging.getLogger("chainvalidator")

GREEN = "\u2705"
YELLOW = "\u26a0\ufe0f"
RED = "\u274c"

ALGORITHM_MAP: dict[int, str] = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    12: "ECC-GOST",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "Ed25519",
    16: "Ed448",
}
"""Mapping of DNSSEC algorithm numbers (RFC 8624) to human-readable names."""

DIGEST_MAP: dict[int, str] = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST R 34.11-94",
    4: "SHA-384",
}
"""Mapping of DS digest type numbers (RFC 4034 §5.1) to human-readable names."""

ROOT_SERVERS: dict[str, str] = {
    "a.root-servers.net": "198.41.0.4",
    "b.root-servers.net": "170.247.170.2",
    "c.root-servers.net": "192.33.4.12",
    "d.root-servers.net": "199.7.91.13",
    "e.root-servers.net": "192.203.230.10",
    "f.root-servers.net": "192.5.5.241",
    "g.root-servers.net": "192.112.36.4",
    "h.root-servers.net": "198.97.190.53",
    "i.root-servers.net": "192.36.148.17",
    "j.root-servers.net": "192.58.128.30",
    "k.root-servers.net": "193.0.14.129",
    "l.root-servers.net": "199.7.83.42",
    "m.root-servers.net": "202.12.27.33",
}
"""All 13 IANA root name servers with their IPv4 addresses."""

DNS_TIMEOUT: float = 5.0
"""Default per-query UDP/TCP timeout in seconds."""

DNS_PORT: int = 53
"""Standard DNS port."""


def _pick_root_server() -> tuple[str, str]:
    """Select a root name server at random using a cryptographically secure RNG.

    :returns: A ``(hostname, ipv4_address)`` tuple chosen from
        :data:`ROOT_SERVERS`, e.g. ``("k.root-servers.net", "193.0.14.129")``.
    """
    names = list(ROOT_SERVERS.keys())
    name = names[secrets.randbelow(len(names))]
    return name, ROOT_SERVERS[name]


# ─── Public module API ────────────────────────────────────────────────────────


@dataclass
class ValidationResult:
    """Structured result returned by :func:`validate`.

    :param domain: The fully-qualified domain name that was checked.
    :param record_type: The DNS record type that was validated (e.g. ``"A"``).
    :param status: One of ``"secure"``, ``"insecure"``, or ``"bogus"``.
    :param errors: Validation error messages; non-empty only when
        *status* is ``"bogus"``.
    :param warnings: Advisory messages; non-empty when *status* is
        ``"insecure"``.
    """

    domain: str
    record_type: str
    status: str  # "secure" | "insecure" | "bogus"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_secure(self) -> bool:
        """``True`` when the full chain of trust is verified."""
        return self.status == "secure"

    @property
    def is_insecure(self) -> bool:
        """``True`` when the delegation chain has an unsigned gap."""
        return self.status == "insecure"

    @property
    def is_bogus(self) -> bool:
        """``True`` when cryptographic validation has failed."""
        return self.status == "bogus"


def validate(
    domain: str,
    record_type: str = "A",
    timeout: float = DNS_TIMEOUT,
) -> ValidationResult:
    """Validate the DNSSEC chain of trust for *domain*.

    This is the recommended entry-point for programmatic use.  It wraps
    :class:`DNSSECChecker` and returns a :class:`ValidationResult` instead
    of a raw boolean.

    Diagnostic output is emitted via the ``"chainvalidator"``
    :mod:`logging` logger.  Attach a handler and set the desired level
    before calling if you want to capture it:

    .. code-block:: python

        import logging
        logging.getLogger("chainvalidator").setLevel(logging.INFO)

    :param domain: Domain name to validate, e.g. ``"example.com"``.
    :param record_type: DNS record type to validate at the leaf
        (default ``"A"``).
    :param timeout: Per-query UDP/TCP timeout in seconds (default
        :data:`DNS_TIMEOUT`).
    :returns: A :class:`ValidationResult`; never raises on DNS or network
        errors — those are captured in :attr:`~ValidationResult.errors`.
    :raises ValueError: If *domain* or *record_type* is syntactically invalid.
    """
    checker = DNSSECChecker(domain, record_type=record_type, timeout=timeout)
    raw = checker.check()
    if raw is True:
        status = "secure"
    elif raw is None:
        status = "insecure"
    else:
        status = "bogus"

    return ValidationResult(
        domain=checker.domain.rstrip("."),
        record_type=record_type.upper(),
        status=status,
        errors=list(checker.errors),
        warnings=list(checker.warnings),
    )


# ─── Low-level DNS helpers ────────────────────────────────────────────────────


def _udp_query(
    qname: str | dns.name.Name,
    rdtype: int,
    nameserver: str,
    port: int = DNS_PORT,
    timeout: float = DNS_TIMEOUT,
) -> dns.message.Message:
    """Send a DNSSEC-enabled UDP query, retrying over TCP on truncation.

    Large RRsets such as DNSKEY frequently exceed the 512-byte UDP limit
    even with EDNS0, so a transparent TCP fallback is essential.

    :param qname: Query name (string or :class:`dns.name.Name`).
    :param rdtype: RR type code (e.g. :data:`dns.rdatatype.DNSKEY`).
    :param nameserver: IPv4 address of the target nameserver.
    :param port: DNS port (default :data:`DNS_PORT`).
    :param timeout: Per-attempt timeout in seconds.
    :returns: The parsed DNS response message.
    :raises RuntimeError: On UDP or TCP transport failure.
    """
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    try:
        resp = dns.query.udp(q, nameserver, timeout=timeout, port=port)
    except Exception as exc:
        raise RuntimeError(
            f"UDP query for {qname}/{dns.rdatatype.to_text(rdtype)} "
            f"to {nameserver} failed: {exc}"
        ) from exc
    if resp.flags & dns.flags.TC:
        logger.debug(
            "  Response truncated; retrying %s/%s over TCP",
            qname,
            dns.rdatatype.to_text(rdtype),
        )
        try:
            resp = dns.query.tcp(q, nameserver, timeout=timeout, port=port)
        except Exception as exc:
            raise RuntimeError(
                f"TCP fallback for {qname}/{dns.rdatatype.to_text(rdtype)} "
                f"to {nameserver} failed: {exc}"
            ) from exc
    return resp


def _extract_rrsets(
    response: dns.message.Message, rdtype: int
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Scan all sections of *response* and return the target RRset plus its RRSIG.

    :param response: A parsed DNS response message.
    :param rdtype: The RR type to search for.
    :returns: A ``(rrset, rrsig_rrset)`` tuple; either element may be
        ``None`` if absent from the response.
    """
    rrset = rrsig = None
    for section in (response.answer, response.authority, response.additional):
        for rr in section:
            if rr.rdtype == rdtype and rrset is None:
                rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG and rrsig is None:
                for sig in rr:
                    if sig.type_covered == rdtype:
                        rrsig = rr
                        break
    return rrset, rrsig


def _get_ds_from_parent(
    zone: str, parent_ns: str, timeout: float = DNS_TIMEOUT
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query *parent_ns* for the DS RRset of *zone* and its covering RRSIG.

    :param zone: Child zone name (e.g. ``"example.com."``).
    :param parent_ns: IPv4 address of the parent zone's nameserver.
    :param timeout: Per-query timeout in seconds.
    :returns: ``(ds_rrset, rrsig_rrset)``; either may be ``None``.
    :raises RuntimeError: On transport failure.
    """
    resp = _udp_query(zone, dns.rdatatype.DS, parent_ns, timeout=timeout)
    return _extract_rrsets(resp, dns.rdatatype.DS)


def _get_dnskey(
    zone: str, ns: str, timeout: float = DNS_TIMEOUT
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query *ns* for the DNSKEY RRset of *zone* and its covering RRSIG.

    :param zone: Zone name (e.g. ``"example.com."``).
    :param ns: IPv4 address of an authoritative nameserver for *zone*.
    :param timeout: Per-query timeout in seconds.
    :returns: ``(dnskey_rrset, rrsig_rrset)``; either may be ``None``.
    :raises RuntimeError: On transport failure.
    """
    resp = _udp_query(zone, dns.rdatatype.DNSKEY, ns, timeout=timeout)
    return _extract_rrsets(resp, dns.rdatatype.DNSKEY)


# ─── Formatting helpers ───────────────────────────────────────────────────────


def _fmt_ds(ds: Rdata) -> str:
    """Return a concise human-readable label for a DS record.

    :param ds: A DS :class:`~dns.rdata.Rdata` object.
    :returns: A string such as ``"DS=12345/SHA-256"``.
    """
    digest_name = DIGEST_MAP.get(ds.digest_type, str(ds.digest_type))
    return f"DS={ds.key_tag}/{digest_name}"


def _fmt_dnskey(dnskey: Rdata) -> str:
    """Return a concise human-readable label for a DNSKEY record.

    :param dnskey: A DNSKEY :class:`~dns.rdata.Rdata` object.
    :returns: A string such as ``"DNSKEY=12345/SEP"`` (SEP suffix only for
        key-signing keys with the Secure Entry Point flag set).
    """
    tag = dns.dnssec.key_id(dnskey)
    sep = "/SEP" if dnskey.flags & 0x0001 else ""
    return f"DNSKEY={tag}{sep}"


def _fmt_rrsig(rrsig: Rdata) -> str:
    """Return a concise human-readable label for an RRSIG record.

    :param rrsig: An RRSIG :class:`~dns.rdata.Rdata` object.
    :returns: A string such as ``"RRSIG=12345"``.
    """
    return f"RRSIG={rrsig.key_tag}"


def _algo_name(alg: int) -> str:
    """Resolve a DNSSEC algorithm number to its mnemonic name.

    :param alg: Algorithm number as defined in RFC 8624.
    :returns: The mnemonic string (e.g. ``"ECDSAP256SHA256"``) or
        ``"ALG<n>"`` for unknown values.
    """
    return ALGORITHM_MAP.get(alg, f"ALG{alg}")


# ─── Validation helpers ───────────────────────────────────────────────────────


def _ds_matches_dnskey(ds: Rdata, dnskey: Rdata, zone: str) -> bool:
    """Check whether *ds* is a valid cryptographic hash of *dnskey*.

    Delegates to :func:`dns.dnssec.make_ds` and compares digests.

    :param ds: The DS record to verify.
    :param dnskey: The DNSKEY record to hash.
    :param zone: The owner zone name, needed to compute the canonical form.
    :returns: ``True`` if the digests match, ``False`` otherwise.
    """
    try:
        computed = dns.dnssec.make_ds(zone, dnskey, ds.digest_type)
        return computed.digest == ds.digest
    except Exception:
        return False


def _validate_rrsig_over_rrset(
    rrset: dns.rrset.RRset,
    rrsig_rrset: dns.rrset.RRset,
    dnskeys: dns.rrset.RRset,
    zone: str,
) -> tuple[bool, Optional[int]]:
    """Attempt to validate *rrsig_rrset* over *rrset* using any key in *dnskeys*.

    Each DNSKEY in *dnskeys* is tried in turn; validation succeeds as soon
    as one key verifies the signature.

    :param rrset: The signed RRset.
    :param rrsig_rrset: The RRSIG RRset covering *rrset*.
    :param dnskeys: The DNSKEY RRset from which to try keys.
    :param zone: The zone name (used to look up keys by owner name).
    :returns: ``(True, key_tag)`` on success, ``(False, None)`` on failure.
    """
    zone_name = dns.name.from_text(zone)
    for dnskey in dnskeys:
        key_tag = dns.dnssec.key_id(dnskey)
        try:
            key_rrset = dns.rrset.from_rdata(zone_name, dnskeys.ttl, dnskey)
            dns.dnssec.validate(rrset, rrsig_rrset, {zone_name: key_rrset})
            return True, key_tag
        except (dns.exception.ValidationFailure, Exception):
            continue
    return False, None


# ─── NSEC3 helpers (RFC 5155) ─────────────────────────────────────────────────

# base32hex alphabet (RFC 4648 §7) used by NSEC3 owner names
_B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_TO_B32HEX = str.maketrans(_B32_STD, _B32_HEX)
_FROM_B32HEX = str.maketrans(_B32_HEX, _B32_STD)


def _nsec3_hash(name: str, salt_hex: str, iterations: int) -> str:
    """Compute the NSEC3 hash of a DNS name as specified in RFC 5155 §5.

    The algorithm is iterated SHA-1 over the wire-format name concatenated
    with the salt, repeated ``iterations + 1`` times in total.

    :param name: The DNS name to hash (canonicalised to wire format internally).
    :param salt_hex: Hex-encoded salt string, or ``"-"`` / empty for no salt.
    :param iterations: Number of *additional* hash iterations (0 = one pass).
    :returns: The hash as an uppercase base32hex string with no padding,
        matching the owner-name prefix used in NSEC3 RRs.
    """
    wire = dns.name.from_text(name).canonicalize().to_wire()
    salt = bytes.fromhex(salt_hex) if salt_hex and salt_hex != "-" else b""
    digest = wire
    for _ in range(iterations + 1):
        digest = hashlib.sha1(digest + salt).digest()
    b32std = base64.b32encode(digest).decode().upper().rstrip("=")
    return b32std.translate(_TO_B32HEX)


def _nsec3_covers(owner_b32: str, next_b32: str, target_b32: str) -> bool:
    """Return ``True`` if *target_b32* falls in the NSEC3 interval ``(owner, next)``.

    Handles the wrap-around case for the last record in the chain, whose
    interval spans ``(owner, end] ∪ [start, next)``.

    :param owner_b32: Base32hex hash of the NSEC3 owner name.
    :param next_b32: Base32hex hash of the next name in the chain.
    :param target_b32: Base32hex hash of the name being tested.
    :returns: ``True`` if *target_b32* is covered by this NSEC3 record.
    """
    o, n, t = owner_b32.upper(), next_b32.upper(), target_b32.upper()
    if o < n:
        return o < t < n
    else:
        return t > o or t < n


def _nsec3_owner_hash(rr: dns.rrset.RRset, zone: str) -> str:
    """Extract the base32hex hash label from an NSEC3 owner name.

    NSEC3 owner names have the form ``<hash>.<zone>``, e.g.
    ``JFFEHCP1SILLDV4FFBNLF8GMEBOCAP8O.example.com.``
    This function strips the zone suffix and returns the hash label in
    uppercase base32hex.

    :param rr: An NSEC3 RRset whose owner name contains the hash label.
    :param zone: The zone name used to strip the suffix.
    :returns: The uppercase hash label, e.g.
        ``"JFFEHCP1SILLDV4FFBNLF8GMEBOCAP8O"``.
    """
    owner = rr.name.to_text().upper()
    zone_suffix = "." + zone.upper().rstrip(".") + "."
    if owner.endswith(zone_suffix):
        return owner[: -len(zone_suffix)]
    return owner.split(".")[0]


# ─── Main checker class ───────────────────────────────────────────────────────


class DNSSECChecker:
    """Full DNSSEC chain-of-trust validator.

    Walks the delegation path Trust Anchor → ``.`` → TLD → … → target zone
    and validates each DS → DNSKEY → RRSIG link in turn.

    All diagnostic output is emitted via the ``"chainvalidator"``
    :mod:`logging` logger at the following levels:

    * ``DEBUG``   — per-query detail: NS selection, keytag listings,
      raw DS wire data, RRSIG expiry dates.
    * ``INFO``    — chain-of-trust milestones: zone section headers,
      DS/DNSKEY match confirmations, final verdict.
    * ``WARNING`` — insecure delegations, unsigned zones, NXDOMAIN.
    * ``ERROR``   — hard validation failures (bogus chain).

    :param domain: The domain name to validate.
    :param record_type: DNS record type to validate at the leaf
        (default ``"A"``).
    :param timeout: Per-query UDP/TCP timeout in seconds
        (default :data:`DNS_TIMEOUT`).
    :raises ValueError: If *domain* is not a valid two-label-or-more name,
        or if *record_type* is not a recognised RR type.
    """

    def __init__(
        self,
        domain: str,
        record_type: str = "A",
        timeout: float = DNS_TIMEOUT,
    ) -> None:
        try:
            parsed = dns.name.from_text(domain)
        except dns.exception.DNSException as exc:
            raise ValueError(f"Invalid domain name '{domain}': {exc}") from exc

        non_empty_labels = [lbl for lbl in parsed.labels if lbl]
        if len(non_empty_labels) < 2:
            raise ValueError(
                f"'{domain}' is not a valid fully-qualified domain name. "
                f"Please include a TLD, e.g. '{domain}.com'."
            )

        self.domain: str = parsed.to_text()
        """Canonical domain name with trailing dot."""

        self.timeout: float = timeout
        """Per-query timeout passed to all DNS transport calls."""

        valid_types = {t.name for t in dns.rdatatype.RdataType}
        if record_type.upper() not in valid_types:
            raise ValueError(
                f"Unknown record type '{record_type}'. "
                f"Known types: {', '.join(sorted(valid_types))}"
            )
        self.rdtype: int = dns.rdatatype.from_text(record_type)
        """Numeric RR type code for the leaf record to validate."""

        self.errors: list[str] = []
        """Accumulated error messages; non-empty implies a bogus result."""

        self.warnings: list[str] = []
        """Accumulated warning messages; non-empty implies an insecure result."""

    # ── Public entry point ────────────────────────────────────────────────────

    def check(self) -> Optional[bool]:
        """Run the full chain-of-trust validation.

        Fetches the IANA trust anchor, walks the delegation hierarchy from
        the root down to the target zone, and validates the leaf RRset.

        :returns:
            * ``True``  — chain is fully secure.
            * ``None``  — chain has an insecure delegation (not fully anchored).
            * ``False`` — chain is bogus (cryptographic failure or hard error).
        """
        domain_label = self.domain.rstrip(".")
        logger.info("=" * 70)
        logger.info("  DNSSEC Validation for: %s", domain_label)
        logger.info("=" * 70)

        zones = self._build_zone_list(self.domain)
        logger.debug("  Zone hierarchy: %s", " -> ".join(zones))

        trust_anchor_ds = self._load_trust_anchor()
        if not trust_anchor_ds:
            self._fail("Could not load IANA trust anchor")
            return False

        validated_keys: dict[str, dns.rrset.RRset] = {}

        if not self._check_root(trust_anchor_ds, validated_keys):
            return False

        for i in range(1, len(zones)):
            parent_zone = zones[i - 1]
            child_zone = zones[i]
            ok = self._check_zone(
                parent_zone=parent_zone,
                child_zone=child_zone,
                parent_validated_keys=validated_keys[parent_zone],
                validated_keys=validated_keys,
            )
            if not ok:
                return False

        target_zone = zones[-1]
        self._check_final_rrset(
            target_zone, validated_keys[target_zone], validated_keys=validated_keys
        )

        logger.info("=" * 70)
        if self.errors:
            logger.error("%s  Validation FAILED -- %d error(s)", RED, len(self.errors))
            for e in self.errors:
                logger.error("     * %s", e)
        elif self.warnings:
            logger.warning(
                "%s   Validation completed with WARNINGS -- chain is NOT fully secure",
                YELLOW,
            )
        else:
            logger.info("%s  Full chain-of-trust validated successfully!", GREEN)

        if self.warnings:
            logger.warning("%s   %d warning(s):", YELLOW, len(self.warnings))
            for w in self.warnings:
                logger.warning("     * %s", w)
        logger.info("=" * 70)

        if self.errors:
            return False
        if self.warnings:
            return None
        return True

    # ── Zone list builder ─────────────────────────────────────────────────────

    def _build_zone_list(self, fqdn: str) -> list[str]:
        """Detect real zone cuts by walking the DNS hierarchy iteratively.

        Queries the root for each candidate zone label in turn, checking
        whether the parent returns an NS delegation (real zone) or a SOA
        (name lives inside the current zone).  Populates
        ``self._zone_ns_map`` as a side-effect so downstream helpers always
        query the correct authoritative server.

        Examples::

            "example.com."     -> ['.', 'com.', 'example.com.']
            "www.example.com." -> ['.', 'com.', 'example.com.']

        :param fqdn: Fully-qualified domain name to analyse.
        :returns: Ordered list of zone apexes from root to the innermost
            zone that contains *fqdn*.
        """
        name = dns.name.from_text(fqdn)
        labels = name.labels

        candidates: list[str] = []
        for i in range(len(labels) - 1, 0, -1):
            zone = dns.name.Name(labels[i - 1 :]).to_text()
            if zone != ".":
                candidates.append(zone)

        self._zone_ns_map: dict[str, list[tuple[str, str]]] = {}
        root_ns = [_pick_root_server()]
        self._zone_ns_map["."] = root_ns
        logger.debug("  Selected root server: %s (%s)", root_ns[0][0], root_ns[0][1])

        zones = ["."]
        current_ns_list: list[tuple[str, str]] = root_ns

        for candidate in candidates:
            ns_list = self._follow_delegation(candidate, current_ns_list[0][1])
            if ns_list:
                zones.append(candidate)
                self._zone_ns_map[candidate] = ns_list
                current_ns_list = ns_list
                logger.debug(
                    "  Zone cut confirmed at %s -- NS: %s",
                    candidate,
                    ", ".join(n for n, _ in ns_list),
                )
            else:
                logger.debug(
                    "  %s is not a zone apex; lives inside current zone", candidate
                )

        return zones

    def _follow_delegation(
        self, candidate: str, parent_ns_ip: str
    ) -> list[tuple[str, str]]:
        """Probe *parent_ns_ip* to determine whether *candidate* is a zone apex.

        A zone apex is identified by the presence of NS records either in
        the ANSWER section (authoritative ``aa=1`` response) or the
        AUTHORITY section (referral).  A SOA in AUTHORITY means *candidate*
        is just a name inside the current zone.

        :param candidate: The zone name being tested.
        :param parent_ns_ip: IPv4 address of the parent zone's nameserver.
        :returns: A list of ``(ns_name, ip)`` pairs if *candidate* is its
            own zone; an empty list otherwise.
        """
        try:
            resp = _udp_query(candidate, dns.rdatatype.NS, parent_ns_ip)
        except RuntimeError as exc:
            logger.debug("  NS probe for %s failed: %s", candidate, exc)
            return []

        candidate_name = dns.name.from_text(candidate)
        ns_names: list[str] = []
        glue: dict[str, str] = {}

        for rr in resp.answer:
            if rr.rdtype == dns.rdatatype.NS and rr.name == candidate_name:
                ns_names = [r.target.to_text() for r in rr]
                break

        if not ns_names:
            for rr in resp.authority:
                if rr.rdtype == dns.rdatatype.NS and rr.name == candidate_name:
                    ns_names = [r.target.to_text() for r in rr]
                    break
                if rr.rdtype == dns.rdatatype.SOA:
                    return []

        if not ns_names:
            return []

        for rr in resp.additional:
            if rr.rdtype == dns.rdatatype.A:
                glue[rr.name.to_text()] = rr[0].address

        result: list[tuple[str, str]] = []
        for ns_name in ns_names:
            if ns_name in glue:
                result.append((ns_name, glue[ns_name]))
            else:
                try:
                    ans = dns.resolver.resolve(ns_name, "A")
                    result.append((ns_name, ans[0].address))
                    logger.debug(
                        "  Resolved %s -> %s (no glue)", ns_name, ans[0].address
                    )
                except Exception as exc:
                    logger.debug("  Could not resolve NS %s: %s", ns_name, exc)
        return result

    # ── Trust anchor ──────────────────────────────────────────────────────────

    def _load_trust_anchor(self) -> list[Rdata]:
        """Fetch and parse the IANA root trust anchor from ``root-anchors.xml``.

        Only KeyDigest entries with ``Flags=257`` (KSK / SEP bit) that are
        currently within their ``validFrom`` / ``validUntil`` window are
        returned.

        :returns: A list of active DS :class:`~dns.rdata.Rdata` records, or
            an empty list on failure (error is also recorded via :meth:`_fail`).
        """
        logger.info("-" * 70)
        logger.info("  Trust Anchor (IANA root-anchors.xml)")
        logger.info("-" * 70)

        try:
            xml_data = requests.get(
                "https://data.iana.org/root-anchors/root-anchors.xml",
                timeout=self.timeout * 2,
            ).content
            logger.debug("  Fetched root-anchors.xml (%d bytes)", len(xml_data))
        except Exception as exc:
            self._fail(f"Could not fetch root-anchors.xml: {exc}")
            return []

        now = datetime.now(timezone.utc)
        active: list[Rdata] = []

        for kd in ET.fromstring(xml_data).findall(".//KeyDigest"):
            valid_from = kd.attrib.get("validFrom")
            valid_until = kd.attrib.get("validUntil")
            flags_el = kd.find("Flags")
            if flags_el is None:
                continue
            if int(flags_el.text) != 257:
                continue
            keytag = int(kd.find("KeyTag").text)
            algorithm = int(kd.find("Algorithm").text)
            digest_type = int(kd.find("DigestType").text)
            digest = kd.find("Digest").text.strip().lower()

            if valid_from and datetime.fromisoformat(valid_from) > now:
                logger.debug("  Skipping future trust anchor DS=%s", keytag)
                continue
            if valid_until and datetime.fromisoformat(valid_until) < now:
                logger.debug("  Skipping expired trust anchor DS=%s", keytag)
                continue

            ds = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DS,
                f"{keytag} {algorithm} {digest_type} {digest}",
            )
            active.append(ds)
            logger.info(
                "  %s Trust anchor DS=%s/%s (algorithm %s) -- active",
                GREEN,
                keytag,
                DIGEST_MAP.get(digest_type, str(digest_type)),
                _algo_name(algorithm),
            )

        if not active:
            self._fail("No active trust anchor DS records found")
        return active

    # ── Root zone check ───────────────────────────────────────────────────────

    def _check_root(
        self,
        trust_anchor_ds: list[Rdata],
        validated_keys: dict,
    ) -> bool:
        """Validate the root zone DNSKEY RRset against the trust anchor.

        Verifies that at least one trust anchor DS matches a root DNSKEY, and
        that the DNSKEY RRset is self-signed by one of those keys.

        :param trust_anchor_ds: Active DS records from :meth:`_load_trust_anchor`.
        :param validated_keys: Shared dict updated in-place with the root
            DNSKEY RRset on success.
        :returns: ``True`` on success; ``False`` after recording an error.
        """
        logger.info("-" * 70)
        logger.info("  Zone: . (root)")
        logger.info("-" * 70)

        root_ns_name, root_ns_ip = _pick_root_server()
        logger.debug("  Fetching DNSKEY for . from %s (%s)", root_ns_name, root_ns_ip)

        try:
            dnskey_rrset, rrsig_rrset = _get_dnskey(".", root_ns_ip, self.timeout)
        except RuntimeError as exc:
            self._fail(str(exc))
            return False

        if not dnskey_rrset:
            self._fail("No DNSKEY records found for root zone")
            return False

        logger.info("  %s Found %d DNSKEY record(s) for .", GREEN, len(dnskey_rrset))
        for dk in dnskey_rrset:
            tag = dns.dnssec.key_id(dk)
            kind = "KSK/SEP" if dk.flags & 0x0001 else "ZSK"
            logger.debug(
                "      keytag=%s  type=%s  algorithm=%s",
                tag,
                kind,
                _algo_name(dk.algorithm),
            )

        any_matched = False
        for ta_ds in trust_anchor_ds:
            for dnskey in dnskey_rrset:
                if _ds_matches_dnskey(ta_ds, dnskey, "."):
                    logger.info(
                        "  %s %s verifies %s",
                        GREEN,
                        _fmt_ds(ta_ds),
                        _fmt_dnskey(dnskey),
                    )
                    any_matched = True

        if not any_matched:
            self._fail("No trust anchor DS matched any root DNSKEY")
            return False

        if not rrsig_rrset:
            self._fail("No RRSIG found over root DNSKEY RRset")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            dnskey_rrset, rrsig_rrset, dnskey_rrset, "."
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s/SEP verifies the DNSKEY RRset",
                GREEN,
                _fmt_rrsig(rrsig_rrset[0]),
                key_tag_used,
            )
        else:
            self._fail("RRSIG over root DNSKEY RRset could not be validated")
            return False

        validated_keys["."] = dnskey_rrset
        return True

    # ── Per-zone check ────────────────────────────────────────────────────────

    def _check_zone(
        self,
        parent_zone: str,
        child_zone: str,
        parent_validated_keys: dns.rrset.RRset,
        validated_keys: dict,
    ) -> bool:
        """Validate the DS -> DNSKEY -> RRSIG chain for a single delegation.

        Steps performed:

        1. Fetch the DS RRset for *child_zone* from *parent_zone* and verify
           its RRSIG using the parent's validated keys.
        2. Fetch the DNSKEY RRset from *child_zone*'s own nameservers.
        3. Confirm at least one DS matches a DNSKEY.
        4. Verify the DNSKEY RRset's self-signature.

        If no DS is present the delegation is marked insecure but processing
        continues so the rest of the hierarchy can still be examined.

        :param parent_zone: Name of the parent zone (e.g. ``"com."``).
        :param child_zone: Name of the child zone (e.g. ``"example.com."``).
        :param parent_validated_keys: Trusted DNSKEY RRset for *parent_zone*,
            used to verify the DS RRSIG.
        :param validated_keys: Shared dict updated in-place with the child's
            DNSKEY RRset on success.
        :returns: ``True`` on success or insecure delegation;
            ``False`` after recording a hard error.
        """
        logger.info("-" * 70)
        logger.info("  Zone: %s  (parent: %s)", child_zone, parent_zone)
        logger.info("-" * 70)

        parent_ns_ip = self._get_ns_ip_for_zone(parent_zone, validated_keys)
        if not parent_ns_ip:
            self._fail(f"Could not find a nameserver for parent zone {parent_zone}")
            return False

        logger.info("  [DS check: %s -> %s]", parent_zone, child_zone)
        logger.debug("  Querying %s NS for %s DS records", parent_zone, child_zone)

        try:
            ds_rrset, ds_rrsig = _get_ds_from_parent(
                child_zone, parent_ns_ip, self.timeout
            )
        except RuntimeError as exc:
            self._fail(str(exc))
            return False

        if not ds_rrset:
            return self._handle_insecure_delegation(
                child_zone, parent_ns_ip, validated_keys
            )

        logger.info(
            "  %s Found %d DS record(s) for %s", GREEN, len(ds_rrset), child_zone
        )
        for ds in ds_rrset:
            logger.info("      %s  algorithm=%s", _fmt_ds(ds), _algo_name(ds.algorithm))
            logger.debug(
                "      %s IN DS ( %s %s %s %s )",
                child_zone,
                ds.key_tag,
                ds.algorithm,
                ds.digest_type,
                ds.digest.hex(),
            )

        if not ds_rrsig:
            self._fail(f"No RRSIG found over {child_zone} DS RRset in {parent_zone}")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            ds_rrset, ds_rrsig, parent_validated_keys, parent_zone
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s verifies the DS RRset",
                GREEN,
                _fmt_rrsig(ds_rrsig[0]),
                key_tag_used,
            )
        else:
            self._fail(
                f"RRSIG over {child_zone} DS RRset could not be validated "
                f"using {parent_zone} keys"
            )
            return False

        child_ns_list = self._resolve_ns_for_child(child_zone, parent_ns_ip)
        if not child_ns_list:
            self._fail(f"Could not resolve any nameserver for {child_zone}")
            return False

        logger.info("  [DNSKEY check: %s]", child_zone)
        dnskey_rrset = rrsig_rrset = None
        for ns_name, ns_ip in child_ns_list:
            logger.debug("  Querying %s (%s) for %s DNSKEY", ns_name, ns_ip, child_zone)
            try:
                dnskey_rrset, rrsig_rrset = _get_dnskey(child_zone, ns_ip, self.timeout)
                if dnskey_rrset:
                    break
            except RuntimeError as exc:
                logger.debug("  DNSKEY query to %s failed: %s", ns_ip, exc)
                continue

        if not dnskey_rrset:
            self._fail(f"No DNSKEY records found for {child_zone}")
            return False

        logger.info(
            "  %s Found %d DNSKEY record(s) for %s",
            GREEN,
            len(dnskey_rrset),
            child_zone,
        )
        for dk in dnskey_rrset:
            tag = dns.dnssec.key_id(dk)
            kind = "KSK/SEP" if dk.flags & 0x0001 else "ZSK"
            logger.debug(
                "      keytag=%s  type=%s  algorithm=%s",
                tag,
                kind,
                _algo_name(dk.algorithm),
            )

        any_matched = False
        for ds in ds_rrset:
            for dnskey in dnskey_rrset:
                if _ds_matches_dnskey(ds, dnskey, child_zone):
                    logger.info(
                        "  %s %s verifies %s",
                        GREEN,
                        _fmt_ds(ds),
                        _fmt_dnskey(dnskey),
                    )
                    any_matched = True

        if not any_matched:
            self._fail(f"No DS record for {child_zone} matched any DNSKEY")
            return False

        if not rrsig_rrset:
            self._fail(f"No RRSIG found over {child_zone} DNSKEY RRset")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            dnskey_rrset, rrsig_rrset, dnskey_rrset, child_zone
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s/SEP verifies the DNSKEY RRset",
                GREEN,
                _fmt_rrsig(rrsig_rrset[0]),
                key_tag_used,
            )
        else:
            self._fail(f"RRSIG over {child_zone} DNSKEY RRset could not be validated")
            return False

        validated_keys[child_zone] = dnskey_rrset
        return True

    def _handle_insecure_delegation(
        self,
        child_zone: str,
        parent_ns_ip: str,
        validated_keys: dict,
    ) -> bool:
        """Handle a delegation with no DS record (insecure island of security).

        Still fetches the child's DNSKEY RRset and verifies internal
        self-consistency, but records a warning because the chain is not
        anchored to the root trust anchor.

        :param child_zone: The zone with no DS in the parent.
        :param parent_ns_ip: IPv4 address of the parent NS, used to resolve
            the child's nameservers.
        :param validated_keys: Shared dict updated in-place with the child's
            DNSKEY RRset (or ``None`` for an unsigned zone).
        :returns: Always ``True`` — insecure is not a hard failure.
        """
        self._warn(
            f"No DS records for {child_zone} in parent zone "
            f"-- delegation is INSECURE (island of security)."
        )
        child_ns_list = self._resolve_ns_for_child(child_zone, parent_ns_ip)
        if not child_ns_list:
            self._fail(f"Could not resolve any nameserver for {child_zone}")
            return False

        logger.info("  [DNSKEY check (insecure): %s]", child_zone)
        dnskey_rrset = rrsig_rrset = None
        for ns_name, ns_ip in child_ns_list:
            logger.debug("  Querying %s (%s) for %s DNSKEY", ns_name, ns_ip, child_zone)
            try:
                dnskey_rrset, rrsig_rrset = _get_dnskey(child_zone, ns_ip, self.timeout)
                if dnskey_rrset:
                    break
            except RuntimeError as exc:
                logger.debug("  DNSKEY query to %s failed: %s", ns_ip, exc)
                continue

        if not dnskey_rrset:
            self._warn(f"No DNSKEY records found for {child_zone} -- zone is unsigned")
            validated_keys[child_zone] = None
            return True

        logger.warning(
            "  %s   Found %d DNSKEY record(s) for %s (unanchored)",
            YELLOW,
            len(dnskey_rrset),
            child_zone,
        )
        for dk in dnskey_rrset:
            tag = dns.dnssec.key_id(dk)
            kind = "KSK/SEP" if dk.flags & 0x0001 else "ZSK"
            logger.debug(
                "      keytag=%s  type=%s  algorithm=%s",
                tag,
                kind,
                _algo_name(dk.algorithm),
            )

        if rrsig_rrset:
            ok, key_tag_used = _validate_rrsig_over_rrset(
                dnskey_rrset, rrsig_rrset, dnskey_rrset, child_zone
            )
            if ok:
                logger.warning(
                    "  %s   %s and DNSKEY=%s/SEP verifies the DNSKEY RRset "
                    "(internal only -- not anchored to root)",
                    YELLOW,
                    _fmt_rrsig(rrsig_rrset[0]),
                    key_tag_used,
                )
            else:
                self._warn(
                    f"RRSIG over {child_zone} DNSKEY RRset could not be "
                    f"validated internally"
                )

        validated_keys[child_zone] = dnskey_rrset
        return True

    # ── Final record validation ───────────────────────────────────────────────

    def _check_final_rrset(
        self,
        zone: str,
        zone_dnskeys: dns.rrset.RRset,
        qname: Optional[str] = None,
        depth: int = 0,
        validated_keys: Optional[dict] = None,
    ) -> bool:
        """Validate the target RRset for *qname* using *zone_dnskeys*.

        Handles four response cases:

        1. **Direct answer** — the requested RR type is present; verify its
           RRSIG and check expiry.
        2. **CNAME** — validate the CNAME RRset, then follow the chain
           recursively (guarded by *depth* to prevent infinite loops).
        3. **NODATA** — NOERROR with empty answer and NSEC in authority;
           verify the NSEC denial proof and signed SOA.
        4. **NXDOMAIN** — verify the signed SOA and optional NSEC3
           closest-encloser proof.

        :param zone: Authoritative zone name for *qname*.
        :param zone_dnskeys: Trusted DNSKEY RRset for *zone*.
        :param qname: Name to query; defaults to :attr:`domain`.
        :param depth: Current CNAME recursion depth (max 8).
        :param validated_keys: Shared dict of already-validated zone DNSKEYs,
            passed through to CNAME follow-up walks.
        :returns: ``True`` if the RRset is validated (or proven absent);
            ``False`` after recording an error.
        """
        MAX_CNAME_DEPTH = 8
        if depth > MAX_CNAME_DEPTH:
            self._fail("CNAME chain too deep (> 8 hops) -- possible loop")
            return False

        if qname is None:
            qname = self.domain

        rdtype_text = dns.rdatatype.to_text(self.rdtype)

        logger.info("-" * 70)
        logger.info("  Record validation: %s %s", qname, rdtype_text)
        logger.info("-" * 70)

        ns_list = self._get_authoritative_ns(zone, zone_dnskeys)
        if not ns_list:
            self._fail(f"Could not find authoritative NS for {zone}")
            return False

        raw_resp = None
        for ns_name, ns_ip in ns_list:
            logger.debug(
                "  Querying %s (%s) for %s %s", ns_name, ns_ip, qname, rdtype_text
            )
            try:
                raw_resp = _udp_query(qname, self.rdtype, ns_ip, timeout=self.timeout)
                break
            except RuntimeError as exc:
                logger.debug("  Query to %s failed: %s", ns_ip, exc)
                continue

        if raw_resp is None:
            self._fail(f"No response for {qname} {rdtype_text}")
            return False

        rrset = rrsig_rrset = None
        cname_rrset = cname_rrsig = None

        for rr in raw_resp.answer:
            if rr.rdtype == self.rdtype and rrset is None:
                rrset = rr
            elif rr.rdtype == dns.rdatatype.CNAME and cname_rrset is None:
                cname_rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG:
                for sig in rr:
                    if sig.type_covered == self.rdtype and rrsig_rrset is None:
                        rrsig_rrset = rr
                    elif (
                        sig.type_covered == dns.rdatatype.CNAME and cname_rrsig is None
                    ):
                        cname_rrsig = rr

        if rrset:
            return self._validate_direct_rrset(
                rrset, rrsig_rrset, zone_dnskeys, zone, qname, rdtype_text
            )

        if cname_rrset:
            return self._follow_cname(
                cname_rrset,
                cname_rrsig,
                zone_dnskeys,
                zone,
                qname,
                depth,
                validated_keys,
            )

        return self._handle_negative_response(
            raw_resp, zone, zone_dnskeys, qname, rdtype_text
        )

    def _validate_direct_rrset(
        self,
        rrset: dns.rrset.RRset,
        rrsig_rrset: Optional[dns.rrset.RRset],
        zone_dnskeys: dns.rrset.RRset,
        zone: str,
        qname: str,
        rdtype_text: str,
    ) -> bool:
        """Validate a directly-answered RRset and its RRSIG, including expiry.

        :param rrset: The RRset returned in the answer section.
        :param rrsig_rrset: The covering RRSIG RRset, or ``None`` if absent.
        :param zone_dnskeys: Trusted keys for the zone.
        :param zone: Authoritative zone name.
        :param qname: Query name (for log messages).
        :param rdtype_text: Human-readable RR type (for log messages).
        :returns: ``True`` on successful validation; ``False`` on failure.
        """
        logger.info("  %s Found %d %s record(s):", GREEN, len(rrset), rdtype_text)
        for r in rrset:
            logger.info(
                "      %s %s IN %s %s",
                qname,
                rrset.ttl,
                rdtype_text,
                r.to_text(),
            )

        if not rrsig_rrset:
            self._fail(f"No RRSIG found over {qname} {rdtype_text} RRset")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            rrset, rrsig_rrset, zone_dnskeys, zone
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s verifies the %s RRset",
                GREEN,
                _fmt_rrsig(rrsig_rrset[0]),
                key_tag_used,
                rdtype_text,
            )
        else:
            self._fail(f"RRSIG over {qname} {rdtype_text} RRset could not be validated")
            return False

        for sig in rrsig_rrset:
            exp = datetime.fromtimestamp(sig.expiration, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            if exp < now:
                self._fail(
                    f"RRSIG over {rdtype_text} RRset is EXPIRED "
                    f"(expired {exp.isoformat()})"
                )
                return False
            days_left = (exp - now).days
            logger.debug(
                "  %s RRSIG expires %s (%d days remaining)",
                GREEN,
                exp.strftime("%Y-%m-%d"),
                days_left,
            )
        return True

    def _follow_cname(
        self,
        cname_rrset: dns.rrset.RRset,
        cname_rrsig: Optional[dns.rrset.RRset],
        zone_dnskeys: dns.rrset.RRset,
        zone: str,
        qname: str,
        depth: int,
        validated_keys: Optional[dict],
    ) -> bool:
        """Validate a CNAME RRset and recursively validate its target.

        Already-validated zones are reused from *validated_keys* to avoid
        redundant re-walking of the root and TLD zones.

        :param cname_rrset: The CNAME RRset from the answer section.
        :param cname_rrsig: The covering RRSIG RRset, or ``None`` if absent.
        :param zone_dnskeys: Trusted keys for the current zone.
        :param zone: Authoritative zone name for *qname*.
        :param qname: The original query name that resolved to a CNAME.
        :param depth: Current recursion depth.
        :param validated_keys: Shared dict of already-validated zone DNSKEYs.
        :returns: ``True`` if the full CNAME chain validates; ``False`` on error.
        """
        cname_target = cname_rrset[0].target.to_text()
        logger.info("  %s %s is a CNAME to %s", GREEN, qname, cname_target)

        if not cname_rrsig:
            self._fail(f"No RRSIG found over {qname} CNAME RRset")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            cname_rrset, cname_rrsig, zone_dnskeys, zone
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s verifies the CNAME RRset",
                GREEN,
                _fmt_rrsig(cname_rrsig[0]),
                key_tag_used,
            )
        else:
            self._fail(f"RRSIG over {qname} CNAME RRset could not be validated")
            return False

        logger.info("  Following CNAME -> %s", cname_target)
        target_zones = self._build_zone_list(cname_target)

        shared_keys: dict[str, dns.rrset.RRset] = (
            validated_keys if validated_keys is not None else {}
        )

        for i in range(1, len(target_zones)):
            parent = target_zones[i - 1]
            child = target_zones[i]
            if child in shared_keys:
                logger.debug("  Skipping already-validated zone %s", child)
                continue
            ok = self._check_zone(
                parent_zone=parent,
                child_zone=child,
                parent_validated_keys=shared_keys[parent],
                validated_keys=shared_keys,
            )
            if not ok:
                return False

        target_zone = target_zones[-1]
        return self._check_final_rrset(
            zone=target_zone,
            zone_dnskeys=shared_keys[target_zone],
            qname=cname_target,
            depth=depth + 1,
            validated_keys=shared_keys,
        )

    def _handle_negative_response(
        self,
        raw_resp: dns.message.Message,
        zone: str,
        zone_dnskeys: dns.rrset.RRset,
        qname: str,
        rdtype_text: str,
    ) -> bool:
        """Dispatch NODATA and NXDOMAIN responses to their respective handlers.

        :param raw_resp: The full DNS response message.
        :param zone: Authoritative zone name.
        :param zone_dnskeys: Trusted keys for *zone*.
        :param qname: The queried name (for log messages).
        :param rdtype_text: Human-readable RR type (for log messages).
        :returns: Result from the appropriate denial-proof handler, or
            ``False`` if neither NSEC nor NXDOMAIN applies.
        """
        nsec_rrset = nsec_rrsig = None
        for rr in raw_resp.authority:
            if rr.rdtype == dns.rdatatype.NSEC and rr.name == dns.name.from_text(qname):
                nsec_rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG:
                for sig in rr:
                    if sig.type_covered == dns.rdatatype.NSEC and nsec_rrsig is None:
                        nsec_rrsig = rr

        if nsec_rrset and raw_resp.rcode() == dns.rcode.NOERROR:
            return self._validate_nodata_nsec(
                nsec_rrset, nsec_rrsig, zone_dnskeys, zone, qname, rdtype_text, raw_resp
            )

        if raw_resp.rcode() == dns.rcode.NXDOMAIN:
            return self._validate_nxdomain(raw_resp, zone, zone_dnskeys, qname)

        logger.error("  %s No %s record found for %s", RED, rdtype_text, qname)
        self._fail(f"No {rdtype_text} record for {qname}")
        return False

    def _validate_nodata_nsec(
        self,
        nsec_rrset: dns.rrset.RRset,
        nsec_rrsig: Optional[dns.rrset.RRset],
        zone_dnskeys: dns.rrset.RRset,
        zone: str,
        qname: str,
        rdtype_text: str,
        raw_resp: dns.message.Message,
    ) -> bool:
        """Validate an NSEC NODATA denial proof (RFC 4035 §5.4).

        Confirms that the NSEC RRset is properly signed and that the
        requested RR type is absent from its type bitmap.  Also verifies
        the signed SOA for zone integrity.

        :param nsec_rrset: The NSEC RRset from the authority section.
        :param nsec_rrsig: The covering RRSIG, or ``None``.
        :param zone_dnskeys: Trusted keys for *zone*.
        :param zone: Authoritative zone name.
        :param qname: The queried name.
        :param rdtype_text: Human-readable RR type.
        :param raw_resp: Full response, used to extract the SOA.
        :returns: ``True`` on successful proof validation; ``False`` on error.
        """
        logger.info("  Checking NSEC NODATA proof for %s %s", qname, rdtype_text)

        if not nsec_rrsig:
            self._fail(f"No RRSIG found over {qname} NSEC RRset")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            nsec_rrset, nsec_rrsig, zone_dnskeys, zone
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s verifies the NSEC RRset",
                GREEN,
                _fmt_rrsig(nsec_rrsig[0]),
                key_tag_used,
            )
        else:
            self._fail(f"RRSIG over {qname} NSEC RRset could not be validated")
            return False

        nsec_rd = list(nsec_rrset)[0]
        rdtype_val = int(self.rdtype)
        window_num = rdtype_val >> 8
        bit_index = rdtype_val & 0xFF
        type_in_bitmap = False
        for win, bitmap in nsec_rd.windows:
            if win == window_num:
                byte_idx, bit_pos = divmod(bit_index, 8)
                if byte_idx < len(bitmap) and bitmap[byte_idx] & (0x80 >> bit_pos):
                    type_in_bitmap = True

        if type_in_bitmap:
            self._fail(
                f"NSEC bitmap includes {rdtype_text} but no answer was returned "
                f"for {qname}"
            )
            return False

        logger.info(
            "  %s NSEC proves no %s records exist for %s",
            GREEN,
            rdtype_text,
            qname,
        )

        soa_rrset = soa_rrsig = None
        for rr in raw_resp.authority:
            if rr.rdtype == dns.rdatatype.SOA and soa_rrset is None:
                soa_rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG:
                for sig in rr:
                    if sig.type_covered == dns.rdatatype.SOA and soa_rrsig is None:
                        soa_rrsig = rr

        if soa_rrset and soa_rrsig:
            ok, key_tag_used = _validate_rrsig_over_rrset(
                soa_rrset, soa_rrsig, zone_dnskeys, zone
            )
            if ok:
                logger.info(
                    "  %s %s and DNSKEY=%s verifies the SOA RRset",
                    GREEN,
                    _fmt_rrsig(soa_rrsig[0]),
                    key_tag_used,
                )
            else:
                self._fail(f"RRSIG over {zone} SOA RRset could not be validated")
                return False
        else:
            logger.debug("  No signed SOA in NODATA response for %s", qname)

        return True

    def _validate_nxdomain(
        self,
        raw_resp: dns.message.Message,
        zone: str,
        zone_dnskeys: dns.rrset.RRset,
        qname: str,
    ) -> bool:
        """Validate an NXDOMAIN response and its denial-of-existence proof.

        Verifies the signed SOA (zone integrity) and, if NSEC3 records are
        present, the closest-encloser proof per RFC 5155 §8.3.

        :param raw_resp: The NXDOMAIN response message.
        :param zone: Authoritative zone name.
        :param zone_dnskeys: Trusted keys for *zone*.
        :param qname: The queried name (for log messages).
        :returns: Always ``False`` -- NXDOMAIN is recorded as a warning and
            the name is treated as non-existent.
        """
        logger.info("  Zone %s returns NXDOMAIN for %s", zone, qname)

        soa_rrset = soa_rrsig = None
        for rr in raw_resp.authority:
            if rr.rdtype == dns.rdatatype.SOA and soa_rrset is None:
                soa_rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG:
                for sig in rr:
                    if sig.type_covered == dns.rdatatype.SOA and soa_rrsig is None:
                        soa_rrsig = rr

        if soa_rrset and soa_rrsig:
            ok, key_tag_used = _validate_rrsig_over_rrset(
                soa_rrset, soa_rrsig, zone_dnskeys, zone
            )
            if ok:
                logger.info(
                    "  %s %s and DNSKEY=%s verifies the SOA RRset",
                    GREEN,
                    _fmt_rrsig(soa_rrsig[0]),
                    key_tag_used,
                )
            else:
                self._fail(f"RRSIG over {zone} SOA RRset could not be validated")
                return False
        else:
            logger.debug("  No signed SOA in NXDOMAIN response for %s", qname)

        nsec3_rrs = [
            rr for rr in raw_resp.authority if rr.rdtype == dns.rdatatype.NSEC3
        ]
        if nsec3_rrs:
            logger.debug(
                "  Found %d NSEC3 record(s); validating denial proof", len(nsec3_rrs)
            )
            if not self._validate_nsec3_nxdomain(
                qname, zone, raw_resp.authority, zone_dnskeys
            ):
                return False

        self._warn(f"NXDOMAIN: {qname} does not exist in zone {zone}")
        return False

    def _validate_nsec3_nxdomain(
        self,
        qname: str,
        zone: str,
        authority: list,
        zone_dnskeys: dns.rrset.RRset,
    ) -> bool:
        """Validate an NSEC3 denial-of-existence proof for an NXDOMAIN response.

        Implements the closest-encloser proof from RFC 5155 §8.3:

        1. **Closest encloser** -- an NSEC3 whose hash exactly matches an
           ancestor of *qname* that exists in the zone.
        2. **Next closer name** -- an NSEC3 whose hash interval covers the
           hash of the one-label-longer name just below the closest encloser.
        3. **Wildcard** -- an NSEC3 whose hash interval covers the hash of
           ``*.closest_encloser``, proving no wildcard can expand.

        All matched NSEC3 RRsets must have their RRSIG validated.

        :param qname: The non-existent queried name.
        :param zone: Authoritative zone name.
        :param authority: The authority section of the NXDOMAIN response.
        :param zone_dnskeys: Trusted keys for *zone*.
        :returns: ``True`` if the proof is valid; ``False`` after recording an error.
        """
        nsec3_map: dict[str, tuple[dns.rrset.RRset, object]] = {}
        nsec3_rrsigs: dict[str, dns.rrset.RRset] = {}

        for rr in authority:
            if rr.rdtype == dns.rdatatype.NSEC3:
                h = _nsec3_owner_hash(rr, zone)
                nsec3_map[h] = (rr, list(rr)[0])
            elif rr.rdtype == dns.rdatatype.RRSIG:
                for sig in rr:
                    if sig.type_covered == dns.rdatatype.NSEC3:
                        h = _nsec3_owner_hash(rr, zone)
                        nsec3_rrsigs[h] = rr

        if not nsec3_map:
            return True

        first_rd = next(iter(nsec3_map.values()))[1]
        iterations = first_rd.iterations
        salt_hex = first_rd.salt.hex() if first_rd.salt else "-"
        logger.debug(
            "  NSEC3 parameters: iterations=%d, salt=%s",
            iterations,
            "-" if salt_hex == "-" else salt_hex,
        )

        def validate_nsec3_rrset(owner_hash: str, label: str) -> bool:
            """Validate the RRSIG over the NSEC3 RRset identified by *owner_hash*.

            :param owner_hash: Base32hex hash identifying the NSEC3 record.
            :param label: Human-readable description for log/error messages.
            :returns: ``True`` on success; ``False`` after recording an error.
            """
            if owner_hash not in nsec3_map:
                return False
            rrset = nsec3_map[owner_hash][0]
            rrsig = nsec3_rrsigs.get(owner_hash)
            if not rrsig:
                self._fail(f"No RRSIG over NSEC3 record covering {label}")
                return False
            ok, key_tag = _validate_rrsig_over_rrset(rrset, rrsig, zone_dnskeys, zone)
            if ok:
                logger.info(
                    "  %s %s and DNSKEY=%s verifies the NSEC3 RRset (%s)",
                    GREEN,
                    _fmt_rrsig(rrsig[0]),
                    key_tag,
                    label,
                )
            else:
                self._fail(
                    f"RRSIG over NSEC3 record for {label} could not be validated"
                )
            return ok

        def find_covering(target_hash: str) -> Optional[str]:
            """Return the owner hash of the NSEC3 record that covers *target_hash*.

            :param target_hash: Base32hex hash to search for.
            :returns: The matching owner hash, or ``None`` if none covers it.
            """
            for owner_hash, (_, rd) in nsec3_map.items():
                next_hash = base64.b32encode(rd.next).decode().upper().rstrip("=")
                next_hash = next_hash.translate(_TO_B32HEX)
                if _nsec3_covers(owner_hash, next_hash, target_hash):
                    return owner_hash
            return None

        qname_stripped = qname.rstrip(".")
        labels = qname_stripped.split(".")
        closest_encloser: Optional[str] = None

        for i in range(len(labels)):
            candidate = ".".join(labels[i:]) + "."
            h = _nsec3_hash(candidate, salt_hex, iterations)
            if h in nsec3_map:
                closest_encloser = candidate
                logger.info(
                    "  %s Closest encloser: %s (hash %s...)",
                    GREEN,
                    candidate,
                    h[:16],
                )
                if not validate_nsec3_rrset(h, f"closest encloser {candidate}"):
                    return False
                break

        if closest_encloser is None:
            closest_encloser = zone if zone.endswith(".") else zone + "."
            logger.debug(
                "  No closest-encloser hash match; falling back to zone apex %s",
                closest_encloser,
            )

        ce_labels = closest_encloser.rstrip(".").split(".")
        q_labels = qname_stripped.split(".")
        ce_depth = len(ce_labels)
        if len(q_labels) > ce_depth:
            next_closer = ".".join(q_labels[-(ce_depth + 1) :]) + "."
            nc_hash = _nsec3_hash(next_closer, salt_hex, iterations)
            covering = find_covering(nc_hash)
            if covering:
                logger.info(
                    "  %s Next closer name %s (hash %s...) is covered by NSEC3",
                    GREEN,
                    next_closer,
                    nc_hash[:16],
                )
                if not validate_nsec3_rrset(covering, f"next closer {next_closer}"):
                    return False
            else:
                self._fail(f"No NSEC3 record covers next closer name {next_closer}")
                return False

        wildcard = "*." + closest_encloser
        wc_hash = _nsec3_hash(wildcard, salt_hex, iterations)
        wc_covering = find_covering(wc_hash)
        if wc_hash in nsec3_map:
            self._fail(f"Wildcard {wildcard} exists but NXDOMAIN was returned")
            return False
        if wc_covering:
            logger.info(
                "  %s Wildcard %s (hash %s...) is covered by NSEC3 -- no wildcard expansion",
                GREEN,
                wildcard,
                wc_hash[:16],
            )
            if not validate_nsec3_rrset(wc_covering, f"wildcard {wildcard}"):
                return False
        else:
            logger.debug(
                "  No wildcard cover found for %s -- opt-out may be in use", wildcard
            )

        return True

    # ── Nameserver helpers ────────────────────────────────────────────────────

    def _get_ns_ip_for_zone(self, zone: str, validated_keys: dict) -> Optional[str]:
        """Return an authoritative IPv4 address for *zone*.

        Uses ``self._zone_ns_map`` populated during :meth:`_build_zone_list`
        to ensure the correct authoritative server is always queried.

        :param zone: Zone name to look up.
        :param validated_keys: Unused; retained for a uniform helper signature.
        :returns: An IPv4 address string, or ``None`` if unavailable.
        """
        ns_map = getattr(self, "_zone_ns_map", {})
        if zone in ns_map and ns_map[zone]:
            return ns_map[zone][0][1]
        if zone == ".":
            _, ip = _pick_root_server()
            return ip
        return None

    def _resolve_ns_for_child(
        self, child_zone: str, parent_ns_ip: str
    ) -> list[tuple[str, str]]:
        """Ask the parent NS for the NS delegation of *child_zone* and resolve IPs.

        Prefers glue records from the additional section; falls back to the
        system resolver for any NS without glue.

        :param child_zone: The child zone whose nameservers are needed.
        :param parent_ns_ip: IPv4 address of the parent zone's nameserver.
        :returns: A list of ``(ns_name, ip)`` pairs; empty on failure.
        """
        try:
            resp = _udp_query(
                child_zone, dns.rdatatype.NS, parent_ns_ip, timeout=self.timeout
            )
        except RuntimeError as exc:
            logger.debug(
                "  NS query for %s to %s failed: %s", child_zone, parent_ns_ip, exc
            )
            return []

        ns_names: list[str] = []
        for section in (resp.answer, resp.authority):
            for rr in section:
                if rr.rdtype == dns.rdatatype.NS:
                    ns_names = [r.target.to_text() for r in rr]
                    break
            if ns_names:
                break

        glue: dict[str, str] = {}
        for rr in resp.additional:
            if rr.rdtype == dns.rdatatype.A:
                glue[rr.name.to_text()] = rr[0].address

        result: list[tuple[str, str]] = []
        for name in ns_names:
            if name in glue:
                result.append((name, glue[name]))
            else:
                try:
                    ans = dns.resolver.resolve(name, "A")
                    result.append((name, ans[0].address))
                    logger.debug(
                        "  Resolved NS %s -> %s (no glue)", name, ans[0].address
                    )
                except Exception as exc:
                    logger.debug("  Could not resolve NS %s: %s", name, exc)
        return result

    def _get_authoritative_ns(
        self, zone: str, zone_dnskeys: dns.rrset.RRset
    ) -> list[tuple[str, str]]:
        """Return the cached authoritative NS list for *zone*.

        Uses ``self._zone_ns_map`` to guarantee the actual authoritative
        servers are queried rather than whatever the stub resolver returns.

        :param zone: Zone name to look up.
        :param zone_dnskeys: Unused; retained for a uniform helper signature.
        :returns: A list of ``(ns_name, ip)`` pairs, or a freshly picked root
            server if *zone* is ``"."``.
        """
        ns_map = getattr(self, "_zone_ns_map", {})
        if zone in ns_map and ns_map[zone]:
            return ns_map[zone]
        if zone == ".":
            return [_pick_root_server()]
        return []

    # ── Error / warning recording ─────────────────────────────────────────────

    def _fail(self, msg: str) -> None:
        """Record a hard validation error and emit it at ``ERROR`` level.

        :param msg: Human-readable description of the failure.
        """
        self.errors.append(msg)
        logger.error("  %s ERROR: %s", RED, msg)

    def _warn(self, msg: str) -> None:
        """Record an advisory warning and emit it at ``WARNING`` level.

        :param msg: Human-readable description of the insecure condition.
        """
        self.warnings.append(msg)
        logger.warning("  %s  WARNING: %s", YELLOW, msg)


# ─── CLI ──────────────────────────────────────────────────────────────────────

_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR"]
_DEFAULT_LOG_LEVEL = "INFO"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chainvalidator",
        description=(
            "DNSSEC Chain-of-Trust Validator\n\n"
            "Validates the full chain: Trust Anchor -> . -> TLD -> SLD -> domain"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
log levels:
  DEBUG    per-query detail (NS chosen, keytag listings, RRSIG expiry ...)
  INFO     chain-of-trust milestones -- default
  WARNING  insecure delegations and unsigned zones only
  ERROR    failures only (silent on success)

examples:
  %(prog)s example.com
  %(prog)s example.com -t AAAA
  %(prog)s example.com -t MX --timeout 10
  %(prog)s example.com -l DEBUG
  %(prog)s example.com -l WARNING

exit codes:
  0  fully secure
  2  insecure delegation (chain not anchored end-to-end)
  1  bogus / validation failed
        """,
    )

    parser.add_argument(
        "domain",
        metavar="DOMAIN",
        help="domain name to validate (e.g. example.com)",
    )
    parser.add_argument(
        "-t",
        "--type",
        metavar="TYPE",
        dest="record_type",
        default="A",
        help="DNS record type to validate at the leaf (default: A)",
    )
    parser.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=float,
        default=DNS_TIMEOUT,
        help=f"per-query UDP/TCP timeout in seconds (default: {DNS_TIMEOUT})",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        metavar="LEVEL",
        dest="log_level",
        default=_DEFAULT_LOG_LEVEL,
        choices=_LOG_LEVELS,
        help=(
            f"logging verbosity: {', '.join(_LOG_LEVELS)} "
            f"(default: {_DEFAULT_LOG_LEVEL})"
        ),
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry-point.

    Parses *argv* (or ``sys.argv[1:]`` when ``None``), configures the
    ``"chainvalidator"`` logger with a plain ``StreamHandler`` on stdout,
    and runs :class:`DNSSECChecker`.

    :param argv: Argument list; pass an explicit list for testing, e.g.
        ``main(["example.com", "-l", "DEBUG"])``.
    :returns: Exit code -- ``0`` (secure), ``1`` (bogus), or ``2`` (insecure).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, args.log_level))

    try:
        checker = DNSSECChecker(
            args.domain,
            record_type=args.record_type,
            timeout=args.timeout,
        )
    except ValueError as exc:
        parser.error(str(exc))

    raw = checker.check()

    if raw is True:
        return 0  # secure
    elif raw is None:
        return 2  # insecure
    else:
        return 1  # bogus


if __name__ == "__main__":
    sys.exit(main())
