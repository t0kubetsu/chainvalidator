#!/usr/bin/env python3
"""
DNSSEC Chain-of-Trust Validator

Validates the full chain: Trust Anchor → . → TLD → SLD → domain

CLI usage
---------
    python chainvalidator.py example.com
    python chainvalidator.py example.com --type AAAA
    python chainvalidator.py example.com --type MX --timeout 10
    python chainvalidator.py example.com -l DEBUG
    python chainvalidator.py example.com -l WARNING   # errors/warnings only
    python chainvalidator.py example.com -l ERROR     # silent on success

Module usage
------------
    from chainvalidator import DNSSECChecker, validate
    import logging

    # The module uses the "dnssec" logger — attach a handler as needed:
    logging.getLogger("dnssec").setLevel(logging.DEBUG)

    # High-level one-shot helper
    result = validate("example.com", record_type="A")
    # result.status   → "secure" | "insecure" | "bogus"
    # result.errors   → list[str]
    # result.warnings → list[str]

    # Low-level checker (same interface as before)
    checker = DNSSECChecker("example.com", record_type="A")
    ok = checker.check()   # True=secure, None=insecure, False=bogus

Log levels used internally
--------------------------
    DEBUG    — per-query detail (NS chosen, keytag listings, RRSIG expiry …)
    INFO     — chain-of-trust milestones (zone headers, DS/DNSKEY matches)
    WARNING  — insecure delegations, NXDOMAIN, unsigned zones
    ERROR    — validation failures (bogus chain)

Exit codes (CLI)
----------------
    0  – fully secure
    2  – insecure delegation (chain not anchored end-to-end)
    1  – bogus / validation failed

Requirements
------------
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
# A single named logger for the whole module.  No handler is attached here so
# that library callers retain full control.  The CLI configures a handler in
# main() based on --log-level.

logger = logging.getLogger("chainvalidator")

GREEN = "✅"
YELLOW = "⚠️"
RED = "❌"

ALGORITHM_MAP = {
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

DIGEST_MAP = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST R 34.11-94",
    4: "SHA-384",
}

# All 13 root name servers (IANA)
ROOT_SERVERS = {
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

DNS_TIMEOUT = 5  # seconds per UDP query (overridable via CLI / validate())
DNS_PORT = 53


def _pick_root_server() -> tuple[str, str]:
    """Randomly select a root name server using a cryptographically secure RNG.

    Returns:
        A (name, ip) tuple, e.g. ("k.root-servers.net", "193.0.14.129").
    """
    names = list(ROOT_SERVERS.keys())
    name = names[secrets.randbelow(len(names))]
    return name, ROOT_SERVERS[name]


# ─── Public module API ────────────────────────────────────────────────────────


@dataclass
class ValidationResult:
    """Structured result returned by :func:`validate`.

    Attributes
    ----------
    domain:
        The fully-qualified domain name that was checked.
    record_type:
        The DNS record type that was validated (e.g. ``"A"``).
    status:
        One of ``"secure"``, ``"insecure"``, or ``"bogus"``.
    errors:
        List of error messages (non-empty only when *status* is ``"bogus"``).
    warnings:
        List of warning messages (non-empty when *status* is ``"insecure"``).
    """

    domain: str
    record_type: str
    status: str  # "secure" | "insecure" | "bogus"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_secure(self) -> bool:
        return self.status == "secure"

    @property
    def is_insecure(self) -> bool:
        return self.status == "insecure"

    @property
    def is_bogus(self) -> bool:
        return self.status == "bogus"


def validate(
    domain: str,
    record_type: str = "A",
    timeout: float = DNS_TIMEOUT,
) -> ValidationResult:
    """Validate the DNSSEC chain of trust for *domain*.

    This is the recommended entry-point when using the module
    programmatically.  It is a thin wrapper around :class:`DNSSECChecker`
    that returns a :class:`ValidationResult` instead of a raw boolean.

    Output is emitted via the ``"chainvalidator"`` :mod:`logging` logger.  Attach a
    handler and set the desired level before calling if you want to see it::

        import logging
        logging.getLogger("chainvalidator").setLevel(logging.INFO)

    Parameters
    ----------
    domain:
        The domain name to validate (e.g. ``"example.com"``).
    record_type:
        DNS record type to validate at the leaf (default ``"A"``).
    timeout:
        Per-query UDP/TCP timeout in seconds (default ``5``).

    Returns
    -------
    ValidationResult
        Always returns a result; never raises on DNS / network errors
        (those are captured in ``result.errors``).
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
    """Send a DNSSEC-enabled UDP query, falling back to TCP if the response
    is truncated (TC flag set).  Large RRsets such as DNSKEY frequently
    exceed the 512-byte UDP limit even with EDNS0."""
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    try:
        resp = dns.query.udp(q, nameserver, timeout=timeout, port=port)
    except Exception as exc:
        raise RuntimeError(
            f"UDP query for {qname}/{dns.rdatatype.to_text(rdtype)} "
            f"to {nameserver} failed: {exc}"
        ) from exc
    if resp.flags & dns.flags.TC:
        # Response was truncated — retry over TCP
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
    """Return (rrset, rrsig_rrset) from any section of a response."""
    rrset = rrsig = None
    for section in (response.answer, response.authority, response.additional):
        for rr in section:
            if rr.rdtype == rdtype and rrset is None:
                rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG and rrsig is None:
                # Check RRSIG covers rdtype
                for sig in rr:
                    if sig.type_covered == rdtype:
                        rrsig = rr
                        break
    return rrset, rrsig


def _get_ds_from_parent(
    zone: str, parent_ns: str, timeout: float = DNS_TIMEOUT
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query parent_ns for zone's DS records + covering RRSIG."""
    resp = _udp_query(zone, dns.rdatatype.DS, parent_ns)
    return _extract_rrsets(resp, dns.rdatatype.DS)


def _get_dnskey(
    zone: str, ns: str, timeout: float = DNS_TIMEOUT
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query ns for zone's DNSKEY records + covering RRSIG."""
    resp = _udp_query(zone, dns.rdatatype.DNSKEY, ns)
    return _extract_rrsets(resp, dns.rdatatype.DNSKEY)


# ─── Formatting helpers ───────────────────────────────────────────────────────


def _fmt_ds(ds: Rdata) -> str:
    digest_name = DIGEST_MAP.get(ds.digest_type, str(ds.digest_type))
    return f"DS={ds.key_tag}/{digest_name}"


def _fmt_dnskey(dnskey: Rdata) -> str:
    tag = dns.dnssec.key_id(dnskey)
    sep = "/SEP" if dnskey.flags & 0x0001 else ""
    return f"DNSKEY={tag}{sep}"


def _fmt_rrsig(rrsig: Rdata) -> str:
    return f"RRSIG={rrsig.key_tag}"


def _algo_name(alg: int) -> str:
    return ALGORITHM_MAP.get(alg, f"ALG{alg}")


# ─── Validation helpers ───────────────────────────────────────────────────────


def _ds_matches_dnskey(ds: Rdata, dnskey: Rdata, zone: str) -> bool:
    """Return True if ds is a valid hash of dnskey."""
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
    """
    Try to validate rrsig_rrset over rrset using any key in dnskeys.
    Returns (success, key_tag_used).
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
    """Compute the NSEC3 hash of a DNS name (RFC 5155 §5).

    Returns the hash as an uppercase base32hex string (no padding),
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
    """Return True if target_b32 falls in the half-open interval
    (owner_b32, next_b32), with wrap-around for the last record in the chain."""
    o, n, t = owner_b32.upper(), next_b32.upper(), target_b32.upper()
    if o < n:  # normal interval
        return o < t < n
    else:  # last record wraps around: covers (o, end] ∪ [start, n)
        return t > o or t < n


def _nsec3_owner_hash(rr: dns.rrset.RRset, zone: str) -> str:
    """Extract the base32hex hash prefix from an NSEC3 owner name.

    NSEC3 owner names look like:
        JFFEHCP1SILLDV4FFBNLF8GMEBOCAP8O.example.com.
    We strip the zone suffix and return the hash label in uppercase.
    """
    owner = rr.name.to_text().upper()
    zone_suffix = "." + zone.upper().rstrip(".") + "."
    if owner.endswith(zone_suffix):
        return owner[: -len(zone_suffix)]
    # fallback: first label
    return owner.split(".")[0]


# ─── Main checker class ───────────────────────────────────────────────────────


class DNSSECChecker:
    """Full DNSSEC chain-of-trust validator.

    Walks: Trust Anchor → root (.) → TLD → ... → target zone
    and validates each DS → DNSKEY → RRSIG link.

    All diagnostic output is emitted via the ``"chainvalidator"`` :mod:`logging`
    logger at the following levels:

    * ``DEBUG``   — per-query detail (NS chosen, keytag listings, RRSIG expiry)
    * ``INFO``    — chain-of-trust milestones (zone headers, DS/DNSKEY matches)
    * ``WARNING`` — insecure delegations, NXDOMAIN, unsigned zones
    * ``ERROR``   — validation failures (bogus chain)

    Parameters
    ----------
    domain:
        The domain name to validate.
    record_type:
        DNS record type to validate at the leaf (default ``"A"``).
    timeout:
        Per-query UDP/TCP timeout in seconds (default ``5``).
    """

    def __init__(
        self,
        domain: str,
        record_type: str = "A",
        timeout: float = DNS_TIMEOUT,
    ):
        # Validate the domain name before doing anything
        try:
            parsed = dns.name.from_text(domain)
        except dns.exception.DNSException as exc:
            raise ValueError(f"Invalid domain name '{domain}': {exc}") from exc

        # Must have at least two labels (name + TLD), e.g. "example.com"
        # A bare single-label name like "example" is not a valid public domain.
        non_empty_labels = [l for l in parsed.labels if l]  # noqa: E741
        if len(non_empty_labels) < 2:
            raise ValueError(
                f"'{domain}' is not a valid fully-qualified domain name. "
                f"Please include a TLD, e.g. '{domain}.com'."
            )

        self.domain = parsed.to_text()  # canonical with trailing dot
        self.timeout = timeout

        valid_types = {t.name for t in dns.rdatatype.RdataType}
        if record_type.upper() not in valid_types:
            raise ValueError(
                f"Unknown record type '{record_type}'. "
                f"Known types: {', '.join(sorted(valid_types))}"
            )
        self.rdtype = dns.rdatatype.from_text(record_type)
        self.errors: list[str] = []
        self.warnings: list[str] = []

    # ── Public entry point ────────────────────────────────────────────────────

    def check(self) -> bool:
        """Run the full chain-of-trust validation.

        Returns
        -------
        True
            Chain is fully secure.
        None
            Chain has an insecure delegation (not fully anchored).
        False
            Chain is bogus (validation failure or hard error).
        """
        domain_label = self.domain.rstrip(".")
        logger.info("=" * 70)
        logger.info("  DNSSEC Validation for: %s", domain_label)
        logger.info("=" * 70)

        # Build zone hierarchy: ['.', 'com.', 'example.com.']
        zones = self._build_zone_list(self.domain)

        # Load trust anchor DS for root
        trust_anchor_ds = self._load_trust_anchor()
        if not trust_anchor_ds:
            self._fail("Could not load IANA trust anchor")
            return False

        # We'll track the validated DNSKEY rrset per zone so we can
        # verify the DS in the child zone is signed by the parent's ZSK.
        # Structure: zone → (dnskey_rrset, rrsig_rrset)
        validated_keys: dict[str, dns.rrset.RRset] = {}

        # ── Step 1: Root zone ─────────────────────────────────────────────────
        if not self._check_root(trust_anchor_ds, validated_keys):
            return False

        # ── Steps 2..N: Each zone in the hierarchy ────────────────────────────
        for i in range(1, len(zones)):
            parent_zone = zones[i - 1]  # e.g. "."
            child_zone = zones[i]  # e.g. "com."
            ok = self._check_zone(
                parent_zone=parent_zone,
                child_zone=child_zone,
                parent_validated_keys=validated_keys[parent_zone],
                validated_keys=validated_keys,
            )
            if not ok:
                return False

        # ── Final: Validate the A/AAAA/etc. record itself ─────────────────────
        target_zone = zones[-1]
        self._check_final_rrset(
            target_zone, validated_keys[target_zone], validated_keys=validated_keys
        )

        logger.info("=" * 70)
        if self.errors:
            logger.error("%s  Validation FAILED — %d error(s)", RED, len(self.errors))
            for e in self.errors:
                logger.error("     • %s", e)
        elif self.warnings:
            # Warnings mean something is degraded (e.g. insecure delegation)
            # but not outright broken — do NOT claim full success
            logger.warning(
                "%s   Validation completed with WARNINGS — chain is NOT fully secure",
                YELLOW,
            )
        else:
            logger.info("%s  Full chain-of-trust validated successfully!", GREEN)

        if self.warnings:
            logger.warning("%s   %d warning(s):", YELLOW, len(self.warnings))
            for w in self.warnings:
                logger.warning("     • %s", w)
        logger.info("=" * 70)

        if self.errors:
            return False  # bogus
        if self.warnings:
            return None  # insecure
        return True  # fully secure

    # ── Zone list builder ─────────────────────────────────────────────────────

    def _build_zone_list(self, fqdn: str) -> list[str]:
        """
        Walk the DNS hierarchy from root down to fqdn using a proper iterative
        resolver, detecting real zone cuts via NS delegations.

        Returns both the ordered zone list AND populates self._zone_ns_map with
        the authoritative NS IPs for each zone, so downstream methods can query
        the correct servers.

            example.com     → ['.', 'com.', 'example.com.']
            www.example.com → ['.', 'com.', 'example.com.']
        """
        name = dns.name.from_text(fqdn)
        labels = name.labels  # e.g. (b'www', b'example', b'com', b'')

        # Ordered candidate zones from TLD down to fqdn itself
        candidates: list[str] = []
        for i in range(len(labels) - 1, 0, -1):
            zone = dns.name.Name(labels[i - 1 :]).to_text()
            if zone != ".":
                candidates.append(zone)

        # ns_map: zone → list of (name, ip) for its authoritative NS
        self._zone_ns_map: dict[str, list[tuple[str, str]]] = {}
        root_ns = [_pick_root_server()]
        self._zone_ns_map["."] = root_ns

        zones = ["."]
        # current_ns_list always holds the NS list of the innermost confirmed zone;
        # it is passed into _follow_delegation and replaced when a new zone is found.
        current_ns_list: list[tuple[str, str]] = root_ns

        for candidate in candidates:
            # Ask the current best NS: "do you delegate candidate?"
            # A real delegation returns NS records in the AUTHORITY section
            # (non-authoritative referral) with no SOA in AUTHORITY.
            # The zone apex itself returns NS in the ANSWER section (aa=1).
            ns_list = self._follow_delegation(candidate, current_ns_list[0][1])
            if ns_list:
                zones.append(candidate)
                self._zone_ns_map[candidate] = ns_list
                current_ns_list = ns_list
            # else: candidate is not a zone apex — it lives inside the current zone

        return zones

    def _follow_delegation(
        self, candidate: str, parent_ns_ip: str
    ) -> list[tuple[str, str]]:
        """
        Query parent_ns_ip for the NS records of *candidate*.

        Returns a list of (ns_name, ip) if *candidate* is its own zone
        (either a proper delegation referral OR an authoritative apex answer).
        Returns an empty list if *candidate* is just a name inside the
        current zone (i.e. the parent returns a SOA in AUTHORITY instead).
        """
        try:
            resp = _udp_query(candidate, dns.rdatatype.NS, parent_ns_ip)
        except RuntimeError:
            return []

        candidate_name = dns.name.from_text(candidate)

        # Collect NS names from ANSWER (apex, aa=1) or AUTHORITY (referral)
        ns_names: list[str] = []
        glue: dict[str, str] = {}

        # Check ANSWER first (authoritative apex)
        for rr in resp.answer:
            if rr.rdtype == dns.rdatatype.NS and rr.name == candidate_name:
                ns_names = [r.target.to_text() for r in rr]
                break

        # Then AUTHORITY (delegation referral from parent)
        if not ns_names:
            for rr in resp.authority:
                if rr.rdtype == dns.rdatatype.NS and rr.name == candidate_name:
                    ns_names = [r.target.to_text() for r in rr]
                    break
                # If authority has a SOA for an ancestor, candidate is NOT its own zone
                if rr.rdtype == dns.rdatatype.SOA:
                    return []

        if not ns_names:
            return []

        # Collect glue from ADDITIONAL
        for rr in resp.additional:
            if rr.rdtype == dns.rdatatype.A:
                glue[rr.name.to_text()] = rr[0].address

        # Resolve NS IPs (prefer glue, fall back to system resolver)
        result: list[tuple[str, str]] = []
        for ns_name in ns_names:
            if ns_name in glue:
                result.append((ns_name, glue[ns_name]))
            else:
                try:
                    ans = dns.resolver.resolve(ns_name, "A")
                    result.append((ns_name, ans[0].address))
                except Exception:
                    pass
        return result

    # ── Trust anchor ──────────────────────────────────────────────────────────

    def _load_trust_anchor(self) -> list[Rdata]:
        logger.info("─" * 70)
        logger.info("  Trust Anchor (IANA root-anchors.xml)")
        logger.info("─" * 70)

        try:
            xml_data = requests.get(
                "https://data.iana.org/root-anchors/root-anchors.xml",
                timeout=self.timeout * 2,
            ).content
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
                continue  # Only KSK / SEP
            keytag = int(kd.find("KeyTag").text)
            algorithm = int(kd.find("Algorithm").text)
            digest_type = int(kd.find("DigestType").text)
            digest = kd.find("Digest").text.strip().lower()

            if valid_from and datetime.fromisoformat(valid_from) > now:
                continue
            if valid_until and datetime.fromisoformat(valid_until) < now:
                continue

            ds = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DS,
                f"{keytag} {algorithm} {digest_type} {digest}",
            )
            active.append(ds)
            logger.info(
                "  %s Trust anchor DS=%s/%s (algorithm %s) — active",
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
        logger.info("─" * 70)
        logger.info("  Zone: . (root)")
        logger.info("─" * 70)

        # Pick a root server
        root_ns_name, root_ns_ip = _pick_root_server()
        logger.debug("  Fetching DNSKEY for . from %s (%s)", root_ns_name, root_ns_ip)

        # Fetch root DNSKEY + RRSIG
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

        # Verify each trust anchor DS against the root DNSKEYs
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

        # Verify RRSIG over the DNSKEY RRset
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

        # All root DNSKEYs are now trusted
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
        logger.info("─" * 70)
        logger.info("  Zone: %s  (parent: %s)", child_zone, parent_zone)
        logger.info("─" * 70)

        # ── 1. Get DS from parent ─────────────────────────────────────────────
        # Find a nameserver for the parent zone
        parent_ns_ip = self._get_ns_ip_for_zone(parent_zone, validated_keys)
        if not parent_ns_ip:
            self._fail(f"Could not find a nameserver for parent zone {parent_zone}")
            return False

        logger.info("  [DS check: %s → %s]", parent_zone, child_zone)
        logger.debug("  Querying %s NS for %s DS records", parent_zone, child_zone)

        try:
            ds_rrset, ds_rrsig = _get_ds_from_parent(
                child_zone, parent_ns_ip, self.timeout
            )
        except RuntimeError as exc:
            self._fail(str(exc))
            return False

        # ── No DS = insecure delegation ───────────────────────────────────────
        if not ds_rrset:
            self._warn(
                f"No DS records for {child_zone} in parent zone {parent_zone} "
                f"— delegation is INSECURE (island of security)."
            )
            # Still fetch and internally verify the child's DNSKEYs + RRSIGs,
            # but mark as insecure by NOT adding to validated_keys with full trust.
            child_ns_list = self._resolve_ns_for_child(child_zone, parent_ns_ip)
            if not child_ns_list:
                self._fail(f"Could not resolve any nameserver for {child_zone}")
                return False

            logger.info("  [DNSKEY check (insecure): %s]", child_zone)
            dnskey_rrset = rrsig_rrset = None
            for ns_name, ns_ip in child_ns_list:
                logger.debug(
                    "  Querying %s (%s) for %s DNSKEY", ns_name, ns_ip, child_zone
                )
                try:
                    dnskey_rrset, rrsig_rrset = _get_dnskey(
                        child_zone, ns_ip, self.timeout
                    )
                    if dnskey_rrset:
                        break
                except RuntimeError:
                    continue

            if not dnskey_rrset:
                # Zone has no DNSKEY at all — unsigned, nothing more to check
                self._warn(
                    f"No DNSKEY records found for {child_zone} — zone is unsigned"
                )
                validated_keys[child_zone] = None  # sentinel: unsigned zone
                return True  # not a hard failure, just unsigned

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

            # Verify internal RRSIG self-consistency even without DS anchor
            if rrsig_rrset:
                ok, key_tag_used = _validate_rrsig_over_rrset(
                    dnskey_rrset, rrsig_rrset, dnskey_rrset, child_zone
                )
                if ok:
                    logger.warning(
                        "  %s   %s and DNSKEY=%s/SEP verifies the DNSKEY RRset "
                        "(internal only — not anchored)",
                        YELLOW,
                        _fmt_rrsig(rrsig_rrset[0]),
                        key_tag_used,
                    )
                else:
                    self._warn(
                        f"RRSIG over {child_zone} DNSKEY RRset could not be "
                        f"validated internally"
                    )

            validated_keys[child_zone] = (
                dnskey_rrset  # store for RRset validation below
            )
            return True  # insecure but not bogus — continue

        # ── DS found: full secure validation ─────────────────────────────────
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

        # Verify RRSIG over DS using parent's validated keys
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

        # ── 2. Fetch child zone DNSKEY ────────────────────────────────────────
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
            except RuntimeError:
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

        # ── 3. Verify DS matches DNSKEY ───────────────────────────────────────
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

        # ── 4. Verify RRSIG over DNSKEY RRset ────────────────────────────────
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

    # ── Final record validation ───────────────────────────────────────────────

    def _check_final_rrset(
        self,
        zone: str,
        zone_dnskeys: dns.rrset.RRset,
        qname: Optional[str] = None,
        depth: int = 0,
        validated_keys: Optional[dict] = None,
    ) -> bool:
        """
        Validate the target RRset for qname in zone.

        If the authoritative server returns a CNAME instead of the requested
        type, we:
          1. Validate the CNAME RRset + RRSIG with the current zone's keys.
          2. Walk the zone chain for the CNAME target starting from root,
             reusing any already-validated zone keys (so root / TLD zones
             already walked are not re-checked from scratch).

        depth guards against infinite CNAME loops (max 8 hops).
        validated_keys is the shared dict of already-validated zone DNSKEYs;
        it is passed through so CNAME follow-ups can skip zones already done.
        """
        MAX_CNAME_DEPTH = 8
        if depth > MAX_CNAME_DEPTH:
            self._fail("CNAME chain too deep (> 8 hops) — possible loop")
            return False

        if qname is None:
            qname = self.domain  # e.g. "www.example.com."

        rdtype_text = dns.rdatatype.to_text(self.rdtype)

        logger.info("─" * 70)
        logger.info("  Record validation: %s %s", qname, rdtype_text)
        logger.info("─" * 70)

        ns_list = self._get_authoritative_ns(zone, zone_dnskeys)
        if not ns_list:
            self._fail(f"Could not find authoritative NS for {zone}")
            return False

        # ── Query for the requested rdtype ────────────────────────────────────
        raw_resp = None
        for ns_name, ns_ip in ns_list:
            logger.debug(
                "  Querying %s (%s) for %s %s", ns_name, ns_ip, qname, rdtype_text
            )
            try:
                raw_resp = _udp_query(qname, self.rdtype, ns_ip, timeout=self.timeout)
                break
            except RuntimeError:
                continue

        if raw_resp is None:
            self._fail(f"No response for {qname} {rdtype_text}")
            return False

        # ── Check answer section for the requested type OR a CNAME ───────────
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

        # ── Case 1: Got the record we wanted ──────────────────────────────────
        if rrset:
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
                self._fail(
                    f"RRSIG over {qname} {rdtype_text} RRset could not be validated"
                )
                return False

            # Check RRSIG expiry
            for sig in rrsig_rrset:
                exp = datetime.fromtimestamp(sig.expiration, tz=timezone.utc)
                now = datetime.now(tz=timezone.utc)
                if exp < now:
                    self._fail(
                        f"RRSIG over {rdtype_text} RRset is EXPIRED "
                        f"(expired {exp.isoformat()})"
                    )
                else:
                    days_left = (exp - now).days
                    logger.debug(
                        "  %s RRSIG expires %s (%d days remaining)",
                        GREEN,
                        exp.strftime("%Y-%m-%d"),
                        days_left,
                    )
            return True

        # ── Case 2: Got a CNAME — validate it, then follow the chain ─────────
        if cname_rrset:
            cname_target = cname_rrset[0].target.to_text()
            logger.info("  %s %s is a CNAME to %s", GREEN, qname, cname_target)

            # Validate the CNAME RRset with the current zone's keys
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

            # Walk the zone chain for the CNAME target, reusing any zones
            # already validated in this session (root, TLD, etc.)
            logger.info("  Following CNAME → %s", cname_target)
            target_zones = self._build_zone_list(cname_target)

            # Share the caller's validated_keys dict so already-done zones
            # (root, org., etc.) are not re-walked.
            shared_keys: dict[str, dns.rrset.RRset] = (
                validated_keys if validated_keys is not None else {}
            )

            for i in range(1, len(target_zones)):
                parent = target_zones[i - 1]
                child = target_zones[i]
                if child in shared_keys:
                    continue  # already validated in a prior walk
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

        # ── Case 3: NODATA — check NSEC denial proof ──────────────────────────
        nsec_rrset = nsec_rrsig = None
        for rr in raw_resp.authority:
            if rr.rdtype == dns.rdatatype.NSEC and rr.name == dns.name.from_text(qname):
                nsec_rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG:
                for sig in rr:
                    if sig.type_covered == dns.rdatatype.NSEC and nsec_rrsig is None:
                        nsec_rrsig = rr

        if nsec_rrset and raw_resp.rcode() == dns.rcode.NOERROR:
            logger.info("  Checking NSEC records for a NODATA response")

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

            # Confirm the NSEC bitmap does not include the requested type.
            # dnspython stores NSEC windows as a list of (window_num, bitmap_bytes).
            # rdtype = (window_num << 8) | bit_index_within_window
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
                # The type IS in the bitmap — the record should exist but wasn't returned
                self._fail(
                    f"NSEC bitmap includes {rdtype_text} but no answer was returned "
                    f"for {qname}"
                )
                return False

            logger.info(
                "  %s NSEC proves no records of type %s exist for %s",
                GREEN,
                rdtype_text,
                qname,
            )

            # Also validate the signed SOA in the authority section, which
            # confirms the zone's own integrity
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

            return True

        # ── Case 4: NXDOMAIN ──────────────────────────────────────────────────
        if raw_resp.rcode() == dns.rcode.NXDOMAIN:
            logger.info("  Zone %s returns NXDOMAIN for %s", zone, qname)

            # Validate signed SOA first (zone integrity)
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

            # Try NSEC3 proof of non-existence
            nsec3_rrs = [
                rr for rr in raw_resp.authority if rr.rdtype == dns.rdatatype.NSEC3
            ]
            if nsec3_rrs:
                if not self._validate_nsec3_nxdomain(
                    qname, zone, raw_resp.authority, zone_dnskeys
                ):
                    return False

            self._warn(f"NXDOMAIN: {qname} does not exist in zone {zone}")
            return False

        # No NSEC proof and no answer — genuine failure
        logger.error("  %s No %s record found for %s", RED, rdtype_text, qname)
        self._fail(f"No {rdtype_text} record for {qname}")
        return False

    def _validate_nsec3_nxdomain(
        self,
        qname: str,
        zone: str,
        authority: list,
        zone_dnskeys: dns.rrset.RRset,
    ) -> bool:
        """Validate NSEC3 denial-of-existence proof for an NXDOMAIN response.

        RFC 5155 §8.3 — closest encloser proof:
          1. Closest encloser match  — an NSEC3 whose hash exactly matches
             an ancestor of qname that *does* exist in the zone.
          2. Next closer name cover  — an NSEC3 whose hash range covers the
             hash of the one-label-longer name just below the closest encloser.
          3. Wildcard cover          — an NSEC3 whose hash range covers the
             hash of *.closest_encloser.

        All matched NSEC3 RRsets must have their RRSIG validated.
        """
        # Collect all NSEC3 rrsets and build a map: owner_hash → (rrset, rd)
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
            return True  # nothing to validate

        # Read hash parameters from the first NSEC3 record
        first_rd = next(iter(nsec3_map.values()))[1]
        iterations = first_rd.iterations
        salt_hex = first_rd.salt.hex() if first_rd.salt else "-"
        logger.debug(
            "  Checking NSEC3 records (iterations=%d, salt=%s)",
            iterations,
            "- " if salt_hex == "-" else salt_hex,
        )

        def validate_nsec3_rrset(owner_hash: str, label: str) -> bool:
            """Validate the RRSIG over the NSEC3 RRset identified by owner_hash."""
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
            """Return the owner_hash of the NSEC3 record that covers target_hash,
            or None if no record covers it."""
            for owner_hash, (_, rd) in nsec3_map.items():
                next_hash = base64.b32encode(rd.next).decode().upper().rstrip("=")
                next_hash = next_hash.translate(_TO_B32HEX)
                if _nsec3_covers(owner_hash, next_hash, target_hash):
                    return owner_hash
            return None

        # ── Closest encloser proof ────────────────────────────────────────────
        # Walk up from qname looking for an ancestor whose hash appears as an
        # NSEC3 owner name (exact match = exists in zone = closest encloser).
        qname_stripped = qname.rstrip(".")
        labels = qname_stripped.split(".")
        closest_encloser: Optional[str] = None

        for i in range(len(labels)):
            candidate = ".".join(labels[i:]) + "."
            h = _nsec3_hash(candidate, salt_hex, iterations)
            if h in nsec3_map:
                closest_encloser = candidate
                logger.info(
                    "  %s Closest encloser: %s (hash %s…)",
                    GREEN,
                    candidate,
                    h[:16],
                )
                if not validate_nsec3_rrset(h, f"closest encloser {candidate}"):
                    return False
                break

        if closest_encloser is None:
            # Fall back to zone apex as closest encloser
            closest_encloser = zone if zone.endswith(".") else zone + "."

        # ── Next closer name cover ────────────────────────────────────────────
        # The next closer name is the child of the closest encloser that is
        # on the path to qname (one label longer than closest_encloser).
        ce_labels = closest_encloser.rstrip(".").split(".")
        q_labels = qname_stripped.split(".")
        # number of labels in closest encloser
        ce_depth = len(ce_labels)
        if len(q_labels) > ce_depth:
            next_closer = ".".join(q_labels[-(ce_depth + 1) :]) + "."
            nc_hash = _nsec3_hash(next_closer, salt_hex, iterations)
            covering = find_covering(nc_hash)
            if covering:
                logger.info(
                    "  %s Next closer name %s (hash %s…) is covered by NSEC3",
                    GREEN,
                    next_closer,
                    nc_hash[:16],
                )
                if not validate_nsec3_rrset(covering, f"next closer {next_closer}"):
                    return False
            else:
                self._fail(f"No NSEC3 record covers next closer name {next_closer}")
                return False

        # ── Wildcard cover ────────────────────────────────────────────────────
        wildcard = "*." + closest_encloser
        wc_hash = _nsec3_hash(wildcard, salt_hex, iterations)
        wc_covering = find_covering(wc_hash)
        # Exact match means a wildcard exists — should not happen for NXDOMAIN
        if wc_hash in nsec3_map:
            self._fail(f"Wildcard {wildcard} exists but NXDOMAIN was returned")
            return False
        if wc_covering:
            logger.info(
                "  %s Wildcard %s (hash %s…) is covered by NSEC3 — no wildcard expansion",
                GREEN,
                wildcard,
                wc_hash[:16],
            )
            if not validate_nsec3_rrset(wc_covering, f"wildcard {wildcard}"):
                return False
        # (absence of wildcard cover is allowed when opt-out is in use)

        return True

    # ── Nameserver helpers ────────────────────────────────────────────────────

    def _get_ns_ip_for_zone(self, zone: str, validated_keys: dict) -> Optional[str]:
        """Return an authoritative NS IP for zone, using the map built during
        zone-list discovery so we always query the correct server."""
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
        """
        Ask the parent NS for the child zone's NS delegation,
        then resolve IPs.
        """
        try:
            resp = _udp_query(
                child_zone, dns.rdatatype.NS, parent_ns_ip, timeout=self.timeout
            )
        except RuntimeError:
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
                except Exception:
                    pass
        return result

    def _get_authoritative_ns(
        self, zone: str, zone_dnskeys: dns.rrset.RRset
    ) -> list[tuple[str, str]]:
        """Return the authoritative NS list for zone from the map built during
        zone-list discovery.  This guarantees we use the actual authoritative
        servers rather than whatever the system resolver happens to return."""
        ns_map = getattr(self, "_zone_ns_map", {})
        if zone in ns_map and ns_map[zone]:
            return ns_map[zone]
        # Fallback: should rarely be needed
        if zone == ".":
            return [_pick_root_server()]
        return []

    # ── Error / warning recording ─────────────────────────────────────────────

    def _fail(self, msg: str) -> None:
        self.errors.append(msg)
        logger.error("  %s ERROR: %s", RED, msg)

    def _warn(self, msg: str) -> None:
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
            "Validates the full chain: Trust Anchor → . → TLD → SLD → domain"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
log levels:
  DEBUG    per-query detail (NS chosen, keytag listings, RRSIG expiry …)
  INFO     chain-of-trust milestones — default
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
    """CLI entry-point.  Returns the exit code (0 / 1 / 2)."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Configure the "chainvalidator" logger for CLI use only.
    # Library callers who import the module get no handler by default
    # (standard Python logging practice — caller controls their own handlers).
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
