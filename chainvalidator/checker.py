"""Core DNSSEC chain-of-trust validator.

Contains :class:`DNSSECChecker`, which walks the delegation path
Trust Anchor → ``.`` → TLD → … → target zone and validates each
DS → DNSKEY → RRSIG link in turn.

All diagnostic output is emitted via the ``"chainvalidator"``
:mod:`logging` logger.  Callers control verbosity by attaching handlers
and setting levels on that logger; nothing is printed directly.

The class populates a :class:`~chainvalidator.models.DNSSECReport` as it
runs so that :mod:`chainvalidator.reporter` can render a structured summary.
"""

from __future__ import annotations

import base64
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

import dns.dnssec
import dns.exception
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import requests
from dns.rdata import Rdata

from chainvalidator.constants import (
    DIGEST_MAP,
    DNS_TIMEOUT,
    GREEN,
    RED,
    YELLOW,
    algo_name,
    pick_root_server,
)
from chainvalidator.dns_utils import (
    get_dnskey,
    get_ds_from_parent,
    udp_query,
)
from chainvalidator.dnssec_utils import (
    _TO_B32HEX,
    ds_matches_dnskey,
    fmt_dnskey,
    fmt_ds,
    fmt_rrsig,
    nsec3_covers,
    nsec3_hash,
    nsec3_owner_hash,
    validate_rrsig_over_rrset,
)
from chainvalidator.models import ChainLink, DNSSECReport, LeafResult, Status

logger = logging.getLogger("chainvalidator")


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
    :type domain: str
    :param record_type: DNS record type to validate at the leaf
        (default ``"A"``).
    :type record_type: str
    :param timeout: Per-query UDP/TCP timeout in seconds
        (default :data:`~chainvalidator.constants.DNS_TIMEOUT`).
    :type timeout: float
    :raises ValueError: If *domain* is not a valid two-label-or-more name,
        or if *record_type* is not a recognised RR type.
    """

    def __init__(
        self,
        domain: str,
        record_type: str = "A",
        timeout: float = DNS_TIMEOUT,
    ) -> None:
        """Initialise the checker.

        :param domain: The domain name to validate.
        :type domain: str
        :param record_type: DNS record type to validate at the leaf
            (default ``"A"``).
        :type record_type: str
        :param timeout: Per-query UDP/TCP timeout in seconds
            (default :data:`~chainvalidator.constants.DNS_TIMEOUT`).
        :type timeout: float
        :raises ValueError: If *domain* is not a valid two-label-or-more name,
            or if *record_type* is not a recognised RR type.
        """
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
        self.warnings: list[str] = []

        # Report object populated progressively during check()
        self.report: DNSSECReport = DNSSECReport(
            domain=self.domain.rstrip("."),
            record_type=record_type.upper(),
        )

        # Internal NS map populated by _build_zone_list
        self._zone_ns_map: dict[str, list[tuple[str, str]]] = {}

    # ── Public entry point ────────────────────────────────────────────────────

    def check(self) -> Optional[bool]:
        """Run the full chain-of-trust validation.

        :returns:
            ``True`` — chain is fully secure.
            ``None`` — chain has an insecure delegation.
            ``False`` — chain is bogus (cryptographic failure or hard error).
        :rtype: bool or None
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
            self._finalise()
            return False

        validated_keys: dict[str, dns.rrset.RRset] = {}

        if not self._check_root(trust_anchor_ds, validated_keys):
            self._finalise()
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
                self._finalise()
                return False

        target_zone = zones[-1]
        self._check_final_rrset(
            target_zone,
            validated_keys[target_zone],
            validated_keys=validated_keys,
        )
        # Note: _check_final_rrset records errors/warnings via _fail/_warn;
        # the final status is set by _finalise() below regardless of the
        # return value, so we intentionally do not short-circuit here.

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

        self._finalise()

        if self.errors:
            return False
        if self.warnings:
            return None
        return True

    # ── Zone list builder ─────────────────────────────────────────────────────

    def _build_zone_list(self, fqdn: str) -> list[str]:
        """Detect real zone cuts by walking the DNS hierarchy.

        :param fqdn: Fully-qualified domain name to analyse.
        :type fqdn: str
        :returns: Ordered list of zone apexes from root to the innermost zone.
        :rtype: list[str]
        """
        name = dns.name.from_text(fqdn)
        labels = name.labels
        candidates: list[str] = []
        for i in range(len(labels) - 1, 0, -1):
            zone = dns.name.Name(labels[i - 1 :]).to_text()
            if zone != ".":
                candidates.append(zone)

        root_ns = [pick_root_server()]
        self._zone_ns_map["."] = root_ns
        logger.debug("  Selected root server: %s (%s)", root_ns[0][0], root_ns[0][1])

        zones = ["."]
        current_ns_list = root_ns

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

        :param candidate: The zone name being tested.
        :type candidate: str
        :param parent_ns_ip: IPv4 address of the parent zone's nameserver.
        :type parent_ns_ip: str
        :returns: ``[(ns_name, ip), …]`` if *candidate* is its own zone; ``[]`` otherwise.
        :rtype: list[tuple[str, str]]
        """
        try:
            resp = udp_query(candidate, dns.rdatatype.NS, parent_ns_ip)
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

        :returns: A list of active DS :class:`~dns.rdata.Rdata` records, or
            ``[]`` on failure.
        :rtype: list[Rdata]
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
            label = f"DS={keytag}/{DIGEST_MAP.get(digest_type, str(digest_type))}"
            self.report.trust_anchor_keys.append(label)
            logger.info(
                "  %s Trust anchor %s (algorithm %s) -- active",
                GREEN,
                label,
                algo_name(algorithm),
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

        :param trust_anchor_ds: Active DS records from :meth:`_load_trust_anchor`.
        :param validated_keys: Shared dict updated in-place with root keys.
        :returns: ``True`` on success.
        :rtype: bool
        """
        logger.info("-" * 70)
        logger.info("  Zone: . (root)")
        logger.info("-" * 70)

        link = ChainLink(zone=".", parent_zone="", status=Status.SECURE)

        root_ns_name, root_ns_ip = pick_root_server()
        logger.debug("  Fetching DNSKEY for . from %s (%s)", root_ns_name, root_ns_ip)

        try:
            dnskey_rrset, rrsig_rrset = get_dnskey(".", root_ns_ip, self.timeout)
        except RuntimeError as exc:
            self._fail(str(exc))
            link.status = Status.BOGUS
            link.errors.append(str(exc))
            self.report.chain.append(link)
            return False

        if not dnskey_rrset:
            msg = "No DNSKEY records found for root zone"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        logger.info("  %s Found %d DNSKEY record(s) for .", GREEN, len(dnskey_rrset))
        for dk in dnskey_rrset:
            tag = dns.dnssec.key_id(dk)
            kind = "KSK/SEP" if dk.flags & 0x0001 else "ZSK"
            lbl = fmt_dnskey(dk)
            link.dnskeys.append(lbl)
            logger.debug(
                "      keytag=%s  type=%s  algorithm=%s",
                tag,
                kind,
                algo_name(dk.algorithm),
            )

        any_matched = False
        for ta_ds in trust_anchor_ds:
            for dnskey in dnskey_rrset:
                if ds_matches_dnskey(ta_ds, dnskey, "."):
                    match_lbl = f"{fmt_ds(ta_ds)} → {fmt_dnskey(dnskey)}"
                    link.ds_matched.append(match_lbl)
                    logger.info(
                        "  %s %s verifies %s", GREEN, fmt_ds(ta_ds), fmt_dnskey(dnskey)
                    )
                    any_matched = True

        if not any_matched:
            msg = "No trust anchor DS matched any root DNSKEY"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        if not rrsig_rrset:
            msg = "No RRSIG found over root DNSKEY RRset"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        ok, key_tag_used = validate_rrsig_over_rrset(
            dnskey_rrset, rrsig_rrset, dnskey_rrset, "."
        )
        if ok:
            link.rrsig_used = key_tag_used
            logger.info(
                "  %s %s and DNSKEY=%s/SEP verifies the DNSKEY RRset",
                GREEN,
                fmt_rrsig(rrsig_rrset[0]),
                key_tag_used,
            )
        else:
            msg = "RRSIG over root DNSKEY RRset could not be validated"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        validated_keys["."] = dnskey_rrset
        self.report.chain.append(link)
        return True

    # ── Per-zone check ────────────────────────────────────────────────────────

    def _check_zone(
        self,
        parent_zone: str,
        child_zone: str,
        parent_validated_keys: dns.rrset.RRset,
        validated_keys: dict,
    ) -> bool:
        """Validate the DS → DNSKEY → RRSIG chain for a single delegation.

        :param parent_zone: Name of the parent zone.
        :type parent_zone: str
        :param child_zone: Name of the child zone.
        :type child_zone: str
        :param parent_validated_keys: Trusted DNSKEY RRset for *parent_zone*.
        :type parent_validated_keys: dns.rrset.RRset
        :param validated_keys: Shared dict updated in-place with child keys.
        :type validated_keys: dict
        :returns: ``True`` on success or insecure delegation; ``False`` on hard error.
        :rtype: bool
        """
        logger.info("-" * 70)
        logger.info("  Zone: %s  (parent: %s)", child_zone, parent_zone)
        logger.info("-" * 70)

        link = ChainLink(zone=child_zone, parent_zone=parent_zone, status=Status.SECURE)

        parent_ns_ip = self._get_ns_ip_for_zone(parent_zone, validated_keys)
        if not parent_ns_ip:
            msg = f"Could not find a nameserver for parent zone {parent_zone}"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        logger.info("  [DS check: %s -> %s]", parent_zone, child_zone)

        try:
            ds_rrset, ds_rrsig = get_ds_from_parent(
                child_zone, parent_ns_ip, self.timeout
            )
        except RuntimeError as exc:
            self._fail(str(exc))
            link.status = Status.BOGUS
            link.errors.append(str(exc))
            self.report.chain.append(link)
            return False

        if not ds_rrset:
            return self._handle_insecure_delegation(
                child_zone, parent_ns_ip, validated_keys, link
            )

        logger.info(
            "  %s Found %d DS record(s) for %s", GREEN, len(ds_rrset), child_zone
        )
        for ds in ds_rrset:
            lbl = fmt_ds(ds)
            link.ds_records.append(lbl)
            logger.info("      %s  algorithm=%s", lbl, algo_name(ds.algorithm))
            logger.debug(
                "      %s IN DS ( %s %s %s %s )",
                child_zone,
                ds.key_tag,
                ds.algorithm,
                ds.digest_type,
                ds.digest.hex(),
            )

        if not ds_rrsig:
            msg = f"No RRSIG found over {child_zone} DS RRset in {parent_zone}"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        ok, key_tag_used = validate_rrsig_over_rrset(
            ds_rrset, ds_rrsig, parent_validated_keys, parent_zone
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s verifies the DS RRset",
                GREEN,
                fmt_rrsig(ds_rrsig[0]),
                key_tag_used,
            )
        else:
            msg = (
                f"RRSIG over {child_zone} DS RRset could not be validated "
                f"using {parent_zone} keys"
            )
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        child_ns_list = self._resolve_ns_for_child(child_zone, parent_ns_ip)
        if not child_ns_list:
            msg = f"Could not resolve any nameserver for {child_zone}"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        logger.info("  [DNSKEY check: %s]", child_zone)
        dnskey_rrset = rrsig_rrset = None
        for ns_name, ns_ip in child_ns_list:
            logger.debug("  Querying %s (%s) for %s DNSKEY", ns_name, ns_ip, child_zone)
            try:
                dnskey_rrset, rrsig_rrset = get_dnskey(child_zone, ns_ip, self.timeout)
                if dnskey_rrset:
                    break
            except RuntimeError as exc:
                logger.debug("  DNSKEY query to %s failed: %s", ns_ip, exc)
                continue

        if not dnskey_rrset:
            msg = f"No DNSKEY records found for {child_zone}"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        logger.info(
            "  %s Found %d DNSKEY record(s) for %s",
            GREEN,
            len(dnskey_rrset),
            child_zone,
        )
        for dk in dnskey_rrset:
            lbl = fmt_dnskey(dk)
            kind = "KSK/SEP" if dk.flags & 0x0001 else "ZSK"
            link.dnskeys.append(lbl)
            logger.debug(
                "      keytag=%s  type=%s  algorithm=%s",
                dns.dnssec.key_id(dk),
                kind,
                algo_name(dk.algorithm),
            )

        any_matched = False
        for ds in ds_rrset:
            for dnskey in dnskey_rrset:
                if ds_matches_dnskey(ds, dnskey, child_zone):
                    match_lbl = f"{fmt_ds(ds)} → {fmt_dnskey(dnskey)}"
                    link.ds_matched.append(match_lbl)
                    logger.info(
                        "  %s %s verifies %s", GREEN, fmt_ds(ds), fmt_dnskey(dnskey)
                    )
                    any_matched = True

        if not any_matched:
            msg = f"No DS record for {child_zone} matched any DNSKEY"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        if not rrsig_rrset:
            msg = f"No RRSIG found over {child_zone} DNSKEY RRset"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        ok, key_tag_used = validate_rrsig_over_rrset(
            dnskey_rrset, rrsig_rrset, dnskey_rrset, child_zone
        )
        if ok:
            link.rrsig_used = key_tag_used
            logger.info(
                "  %s %s and DNSKEY=%s/SEP verifies the DNSKEY RRset",
                GREEN,
                fmt_rrsig(rrsig_rrset[0]),
                key_tag_used,
            )
        else:
            msg = f"RRSIG over {child_zone} DNSKEY RRset could not be validated"
            self._fail(msg)
            link.status = Status.BOGUS
            link.errors.append(msg)
            self.report.chain.append(link)
            return False

        validated_keys[child_zone] = dnskey_rrset
        self.report.chain.append(link)
        return True

    def _handle_insecure_delegation(
        self,
        child_zone: str,
        parent_ns_ip: str,
        validated_keys: dict,
        link: ChainLink,
    ) -> bool:
        """Handle a delegation with no DS record (insecure island of security).

        :param child_zone: The zone with no DS in the parent.
        :param parent_ns_ip: IPv4 address of the parent NS.
        :param validated_keys: Shared dict updated in-place.
        :param link: :class:`ChainLink` for this zone, updated in-place.
        :returns: Always ``True`` — insecure is not a hard failure.
        :rtype: bool
        """
        msg = (
            f"No DS records for {child_zone} in parent zone "
            f"-- delegation is INSECURE (island of security)."
        )
        self._warn(msg)
        link.status = Status.INSECURE
        link.warnings.append(msg)

        child_ns_list = self._resolve_ns_for_child(child_zone, parent_ns_ip)
        if not child_ns_list:
            hard_msg = f"Could not resolve any nameserver for {child_zone}"
            self._fail(hard_msg)
            link.status = Status.BOGUS
            link.errors.append(hard_msg)
            self.report.chain.append(link)
            return False

        logger.info("  [DNSKEY check (insecure): %s]", child_zone)
        dnskey_rrset = rrsig_rrset = None
        for ns_name, ns_ip in child_ns_list:
            try:
                dnskey_rrset, rrsig_rrset = get_dnskey(child_zone, ns_ip, self.timeout)
                if dnskey_rrset:
                    break
            except RuntimeError as exc:
                logger.debug("  DNSKEY query to %s failed: %s", ns_ip, exc)
                continue

        if not dnskey_rrset:
            note = f"No DNSKEY records found for {child_zone} -- zone is unsigned"
            self._warn(note)
            link.notes.append(note)
            validated_keys[child_zone] = None
            self.report.chain.append(link)
            return True

        logger.warning(
            "  %s   Found %d DNSKEY record(s) for %s (unanchored)",
            YELLOW,
            len(dnskey_rrset),
            child_zone,
        )
        for dk in dnskey_rrset:
            lbl = fmt_dnskey(dk)
            kind = "KSK/SEP" if dk.flags & 0x0001 else "ZSK"
            link.dnskeys.append(lbl)
            logger.debug(
                "      keytag=%s  type=%s  algorithm=%s",
                dns.dnssec.key_id(dk),
                kind,
                algo_name(dk.algorithm),
            )

        if rrsig_rrset:
            ok, key_tag_used = validate_rrsig_over_rrset(
                dnskey_rrset, rrsig_rrset, dnskey_rrset, child_zone
            )
            if ok:
                link.rrsig_used = key_tag_used
                logger.warning(
                    "  %s   %s and DNSKEY=%s/SEP verifies DNSKEY RRset "
                    "(internal only -- not anchored to root)",
                    YELLOW,
                    fmt_rrsig(rrsig_rrset[0]),
                    key_tag_used,
                )
            else:
                note = (
                    f"RRSIG over {child_zone} DNSKEY RRset could not be "
                    f"validated internally"
                )
                self._warn(note)
                link.notes.append(note)

        validated_keys[child_zone] = dnskey_rrset
        self.report.chain.append(link)
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

        :param zone: Authoritative zone name for *qname*.
        :type zone: str
        :param zone_dnskeys: Trusted DNSKEY RRset for *zone*.
        :type zone_dnskeys: dns.rrset.RRset
        :param qname: Name to query; defaults to :attr:`domain`.
        :type qname: str or None
        :param depth: Current CNAME recursion depth (max 8).
        :type depth: int
        :param validated_keys: Shared dict of already-validated zone DNSKEYs.
        :type validated_keys: dict or None
        :returns: ``True`` if the RRset is validated; ``False`` on error.
        :rtype: bool
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

        leaf = LeafResult(qname=qname.rstrip("."), record_type=rdtype_text)
        if depth == 0:
            self.report.leaf = leaf

        ns_list = self._get_authoritative_ns(zone, zone_dnskeys)
        if not ns_list:
            msg = f"Could not find authoritative NS for {zone}"
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
            return False

        raw_resp = None
        for ns_name, ns_ip in ns_list:
            logger.debug(
                "  Querying %s (%s) for %s %s", ns_name, ns_ip, qname, rdtype_text
            )
            try:
                raw_resp = udp_query(qname, self.rdtype, ns_ip, timeout=self.timeout)
                break
            except RuntimeError as exc:
                logger.debug("  Query to %s failed: %s", ns_ip, exc)
                continue

        if raw_resp is None:
            msg = f"No response for {qname} {rdtype_text}"
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
            return False

        rrset = rrsig_rrset = cname_rrset = cname_rrsig = None

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
                rrset, rrsig_rrset, zone_dnskeys, zone, qname, rdtype_text, leaf
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
                leaf,
            )

        return self._handle_negative_response(
            raw_resp, zone, zone_dnskeys, qname, rdtype_text, leaf
        )

    def _validate_direct_rrset(
        self,
        rrset: dns.rrset.RRset,
        rrsig_rrset: Optional[dns.rrset.RRset],
        zone_dnskeys: dns.rrset.RRset,
        zone: str,
        qname: str,
        rdtype_text: str,
        leaf: LeafResult,
    ) -> bool:
        """Validate a directly-answered RRset and its RRSIG, including expiry.

        :param rrset: The RRset returned in the answer section.
        :param rrsig_rrset: The covering RRSIG RRset, or ``None``.
        :param zone_dnskeys: Trusted keys for the zone.
        :param zone: Authoritative zone name.
        :param qname: Query name (for log messages).
        :param rdtype_text: Human-readable RR type (for log messages).
        :param leaf: :class:`LeafResult` updated in-place.
        :returns: ``True`` on successful validation.
        :rtype: bool
        """
        logger.info("  %s Found %d %s record(s):", GREEN, len(rrset), rdtype_text)
        for r in rrset:
            txt = r.to_text()
            leaf.records.append(txt)
            logger.info("      %s %s IN %s %s", qname, rrset.ttl, rdtype_text, txt)

        if not rrsig_rrset:
            msg = f"No RRSIG found over {qname} {rdtype_text} RRset"
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
            return False

        ok, key_tag_used = validate_rrsig_over_rrset(
            rrset, rrsig_rrset, zone_dnskeys, zone
        )
        if ok:
            leaf.rrsig_used = key_tag_used
            logger.info(
                "  %s %s and DNSKEY=%s verifies the %s RRset",
                GREEN,
                fmt_rrsig(rrsig_rrset[0]),
                key_tag_used,
                rdtype_text,
            )
        else:
            msg = f"RRSIG over {qname} {rdtype_text} RRset could not be validated"
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
            return False

        for sig in rrsig_rrset:
            exp = datetime.fromtimestamp(sig.expiration, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            if exp < now:
                msg = (
                    f"RRSIG over {rdtype_text} RRset is EXPIRED "
                    f"(expired {exp.isoformat()})"
                )
                self._fail(msg)
                leaf.status = Status.BOGUS
                leaf.errors.append(msg)
                return False
            days_left = (exp - now).days
            leaf.rrsig_expires = exp.strftime("%Y-%m-%d")
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
        leaf: LeafResult,
    ) -> bool:
        """Validate a CNAME RRset and recursively validate its target.

        :param cname_rrset: The CNAME RRset.
        :param cname_rrsig: The covering RRSIG, or ``None``.
        :param zone_dnskeys: Trusted keys for the current zone.
        :param zone: Authoritative zone name for *qname*.
        :param qname: The original query name.
        :param depth: Current recursion depth.
        :param validated_keys: Shared dict of validated zone DNSKEYs.
        :param leaf: :class:`LeafResult` updated in-place.
        :returns: ``True`` if the full CNAME chain validates.
        :rtype: bool
        """
        cname_target = cname_rrset[0].target.to_text()
        leaf.cname_chain.append(cname_target.rstrip("."))
        logger.info("  %s %s is a CNAME to %s", GREEN, qname, cname_target)

        if not cname_rrsig:
            msg = f"No RRSIG found over {qname} CNAME RRset"
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
            return False

        ok, key_tag_used = validate_rrsig_over_rrset(
            cname_rrset, cname_rrsig, zone_dnskeys, zone
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s verifies the CNAME RRset",
                GREEN,
                fmt_rrsig(cname_rrsig[0]),
                key_tag_used,
            )
        else:
            msg = f"RRSIG over {qname} CNAME RRset could not be validated"
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
            return False

        logger.info("  Following CNAME -> %s", cname_target)
        target_zones = self._build_zone_list(cname_target)
        shared_keys = validated_keys if validated_keys is not None else {}

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
        leaf: LeafResult,
    ) -> bool:
        """Dispatch NODATA and NXDOMAIN responses to their handlers.

        :param raw_resp: The full DNS response message.
        :param zone: Authoritative zone name.
        :param zone_dnskeys: Trusted keys for *zone*.
        :param qname: The queried name.
        :param rdtype_text: Human-readable RR type.
        :param leaf: :class:`LeafResult` updated in-place.
        :returns: Result from the denial-proof handler.
        :rtype: bool
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
                nsec_rrset,
                nsec_rrsig,
                zone_dnskeys,
                zone,
                qname,
                rdtype_text,
                raw_resp,
                leaf,
            )

        if raw_resp.rcode() == dns.rcode.NXDOMAIN:
            return self._validate_nxdomain(raw_resp, zone, zone_dnskeys, qname, leaf)

        msg = f"No {rdtype_text} record for {qname}"
        logger.error("  %s No %s record found for %s", RED, rdtype_text, qname)
        self._fail(msg)
        leaf.status = Status.BOGUS
        leaf.errors.append(msg)
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
        leaf: LeafResult,
    ) -> bool:
        """Validate an NSEC NODATA denial proof (RFC 4035 §5.4).

        :param nsec_rrset: The NSEC RRset from the authority section.
        :param nsec_rrsig: The covering RRSIG, or ``None``.
        :param zone_dnskeys: Trusted keys for *zone*.
        :param zone: Authoritative zone name.
        :param qname: The queried name.
        :param rdtype_text: Human-readable RR type.
        :param raw_resp: Full response (used to extract the SOA).
        :param leaf: :class:`LeafResult` updated in-place.
        :returns: ``True`` on successful proof validation.
        :rtype: bool
        """
        logger.info("  Checking NSEC NODATA proof for %s %s", qname, rdtype_text)

        if not nsec_rrsig:
            msg = f"No RRSIG found over {qname} NSEC RRset"
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
            return False

        ok, key_tag_used = validate_rrsig_over_rrset(
            nsec_rrset, nsec_rrsig, zone_dnskeys, zone
        )
        if ok:
            logger.info(
                "  %s %s and DNSKEY=%s verifies the NSEC RRset",
                GREEN,
                fmt_rrsig(nsec_rrsig[0]),
                key_tag_used,
            )
        else:
            msg = f"RRSIG over {qname} NSEC RRset could not be validated"
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
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
            msg = (
                f"NSEC bitmap includes {rdtype_text} but no answer was returned "
                f"for {qname}"
            )
            self._fail(msg)
            leaf.status = Status.BOGUS
            leaf.errors.append(msg)
            return False

        note = f"NSEC proves no {rdtype_text} records exist for {qname}"
        logger.info("  %s %s", GREEN, note)
        leaf.notes.append(note)

        soa_rrset = soa_rrsig = None
        for rr in raw_resp.authority:
            if rr.rdtype == dns.rdatatype.SOA and soa_rrset is None:
                soa_rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG:
                for sig in rr:
                    if sig.type_covered == dns.rdatatype.SOA and soa_rrsig is None:
                        soa_rrsig = rr

        if soa_rrset and soa_rrsig:
            ok, key_tag_used = validate_rrsig_over_rrset(
                soa_rrset, soa_rrsig, zone_dnskeys, zone
            )
            if ok:
                logger.info(
                    "  %s %s and DNSKEY=%s verifies the SOA RRset",
                    GREEN,
                    fmt_rrsig(soa_rrsig[0]),
                    key_tag_used,
                )
            else:
                msg = f"RRSIG over {zone} SOA RRset could not be validated"
                self._fail(msg)
                leaf.status = Status.BOGUS
                leaf.errors.append(msg)
                return False

        return True

    def _validate_nxdomain(
        self,
        raw_resp: dns.message.Message,
        zone: str,
        zone_dnskeys: dns.rrset.RRset,
        qname: str,
        leaf: LeafResult,
    ) -> bool:
        """Validate an NXDOMAIN response and its denial-of-existence proof.

        :param raw_resp: The NXDOMAIN response message.
        :param zone: Authoritative zone name.
        :param zone_dnskeys: Trusted keys for *zone*.
        :param qname: The queried name.
        :param leaf: :class:`LeafResult` updated in-place.
        :returns: Always ``False`` — NXDOMAIN is a warning.
        :rtype: bool
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

        proof_valid = True

        if soa_rrset and soa_rrsig:
            ok, key_tag_used = validate_rrsig_over_rrset(
                soa_rrset, soa_rrsig, zone_dnskeys, zone
            )
            if ok:
                logger.info(
                    "  %s %s and DNSKEY=%s verifies the SOA RRset",
                    GREEN,
                    fmt_rrsig(soa_rrsig[0]),
                    key_tag_used,
                )
            else:
                msg = f"RRSIG over {zone} SOA RRset could not be validated"
                self._fail(msg)
                leaf.status = Status.BOGUS
                leaf.errors.append(msg)
                return False
        elif soa_rrset and not soa_rrsig:
            proof_valid = False

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
                leaf.status = Status.BOGUS
                return False

        msg = f"NXDOMAIN: {qname} does not exist in zone {zone}"
        leaf.nxdomain = True

        if proof_valid:
            note = f"Secure NXDOMAIN: {qname} does not exist (denial proof validated)"
            leaf.notes.append(note)
            leaf.status = Status.SECURE
            logger.info("  %s %s", GREEN, note)
        else:
            self._warn(msg)
            leaf.warnings.append(msg)
            leaf.status = Status.INSECURE

        return False

    def _validate_nsec3_nxdomain(
        self,
        qname: str,
        zone: str,
        authority: list,
        zone_dnskeys: dns.rrset.RRset,
    ) -> bool:
        """Validate an NSEC3 denial-of-existence proof for an NXDOMAIN response.

        Implements the closest-encloser proof from RFC 5155 §8.3.

        :param qname: The non-existent queried name.
        :type qname: str
        :param zone: Authoritative zone name.
        :type zone: str
        :param authority: The authority section of the NXDOMAIN response.
        :type authority: list
        :param zone_dnskeys: Trusted keys for *zone*.
        :type zone_dnskeys: dns.rrset.RRset
        :returns: ``True`` if the proof is valid.
        :rtype: bool
        """
        nsec3_map: dict = {}
        nsec3_rrsigs: dict = {}

        for rr in authority:
            if rr.rdtype == dns.rdatatype.NSEC3:
                h = nsec3_owner_hash(rr, zone)
                nsec3_map[h] = (rr, list(rr)[0])
            elif rr.rdtype == dns.rdatatype.RRSIG:
                for sig in rr:
                    if sig.type_covered == dns.rdatatype.NSEC3:
                        h = nsec3_owner_hash(rr, zone)
                        nsec3_rrsigs[h] = rr

        if not nsec3_map:
            return True

        first_rd = next(iter(nsec3_map.values()))[1]
        iterations = first_rd.iterations
        salt_hex = first_rd.salt.hex() if first_rd.salt else "-"
        logger.debug("  NSEC3 parameters: iterations=%d, salt=%s", iterations, salt_hex)

        def validate_nsec3_rrset(owner_hash: str, label: str) -> bool:
            """Validate the RRSIG over the NSEC3 RRset identified by *owner_hash*.

            :param owner_hash: Base32hex hash identifying the NSEC3 record.
            :type owner_hash: str
            :param label: Description for error messages.
            :type label: str
            :returns: ``True`` on success.
            :rtype: bool
            """
            if owner_hash not in nsec3_map:
                return False  # pragma: no cover
            rrset = nsec3_map[owner_hash][0]
            rrsig = nsec3_rrsigs.get(owner_hash)
            if not rrsig:
                self._fail(f"No RRSIG over NSEC3 record covering {label}")
                return False
            ok, key_tag = validate_rrsig_over_rrset(rrset, rrsig, zone_dnskeys, zone)
            if ok:
                logger.info(
                    "  %s %s and DNSKEY=%s verifies NSEC3 RRset (%s)",
                    GREEN,
                    fmt_rrsig(rrsig[0]),
                    key_tag,
                    label,
                )
            else:
                self._fail(
                    f"RRSIG over NSEC3 record for {label} could not be validated"
                )
            return ok

        def find_covering(target_hash: str) -> Optional[str]:
            """Return the owner hash of the NSEC3 that covers *target_hash*.

            :param target_hash: Base32hex hash to search for.
            :type target_hash: str
            :returns: The matching owner hash, or ``None``.
            :rtype: str or None
            """
            for owner_hash, (_, rd) in nsec3_map.items():
                next_hash = base64.b32encode(rd.next).decode().upper().rstrip("=")
                next_hash = next_hash.translate(_TO_B32HEX)
                if nsec3_covers(owner_hash, next_hash, target_hash):
                    return owner_hash
            return None

        qname_stripped = qname.rstrip(".")
        labels = qname_stripped.split(".")
        closest_encloser: Optional[str] = None

        for i in range(len(labels)):
            candidate = ".".join(labels[i:]) + "."
            h = nsec3_hash(candidate, salt_hex, iterations)
            if h in nsec3_map:
                closest_encloser = candidate
                logger.info(
                    "  %s Closest encloser: %s (hash %s...)", GREEN, candidate, h[:16]
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
            nc_hash = nsec3_hash(next_closer, salt_hex, iterations)
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
        wc_hash = nsec3_hash(wildcard, salt_hex, iterations)
        wc_covering = find_covering(wc_hash)
        if wc_hash in nsec3_map:
            self._fail(f"Wildcard {wildcard} exists but NXDOMAIN was returned")
            return False
        if wc_covering:
            logger.info(
                "  %s Wildcard %s (hash %s...) covered by NSEC3 -- no wildcard expansion",
                GREEN,
                wildcard,
                wc_hash[:16],
            )
            if not validate_nsec3_rrset(wc_covering, f"wildcard {wildcard}"):
                return False

        return True

    # ── Nameserver helpers ────────────────────────────────────────────────────

    def _get_ns_ip_for_zone(self, zone: str, validated_keys: dict) -> Optional[str]:
        """Return an authoritative IPv4 address for *zone* from the NS map.

        :param zone: Zone name to look up.
        :type zone: str
        :param validated_keys: Unused; retained for uniform helper signature.
        :returns: An IPv4 address string, or ``None``.
        :rtype: str or None
        """
        if zone in self._zone_ns_map and self._zone_ns_map[zone]:
            return self._zone_ns_map[zone][0][1]
        if zone == ".":
            _, ip = pick_root_server()
            return ip
        return None

    def _resolve_ns_for_child(
        self, child_zone: str, parent_ns_ip: str
    ) -> list[tuple[str, str]]:
        """Ask the parent NS for the NS delegation of *child_zone* and resolve IPs.

        :param child_zone: The child zone whose nameservers are needed.
        :type child_zone: str
        :param parent_ns_ip: IPv4 address of the parent zone's nameserver.
        :type parent_ns_ip: str
        :returns: ``[(ns_name, ip), …]``; empty on failure.
        :rtype: list[tuple[str, str]]
        """
        try:
            resp = udp_query(
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

        :param zone: Zone name to look up.
        :type zone: str
        :param zone_dnskeys: Unused; retained for uniform helper signature.
        :returns: ``[(ns_name, ip), …]``.
        :rtype: list[tuple[str, str]]
        """
        if zone in self._zone_ns_map and self._zone_ns_map[zone]:
            return self._zone_ns_map[zone]
        if zone == ".":
            return [pick_root_server()]
        return []

    # ── Error / warning recording ─────────────────────────────────────────────

    def _fail(self, msg: str) -> None:
        """Record a hard validation error.

        :param msg: Human-readable description of the failure.
        :type msg: str
        """
        self.errors.append(msg)
        self.report.errors.append(msg)
        logger.error("  %s ERROR: %s", RED, msg)

    def _warn(self, msg: str) -> None:
        """Record an advisory warning.

        :param msg: Human-readable description of the insecure condition.
        :type msg: str
        """
        self.warnings.append(msg)
        self.report.warnings.append(msg)
        logger.warning("  %s  WARNING: %s", YELLOW, msg)

    # ── Report finalisation ───────────────────────────────────────────────────

    def _finalise(self) -> None:
        """Set the overall :attr:`~DNSSECReport.status` on the report."""
        if self.errors:
            self.report.status = Status.BOGUS
        elif self.warnings:
            self.report.status = Status.INSECURE
        else:
            self.report.status = Status.SECURE
