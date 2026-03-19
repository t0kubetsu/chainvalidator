"""Data models for chainvalidator results.

All result objects are plain dataclasses — no Rich or DNS library imports.
They are constructed by :mod:`chainvalidator.checker` and consumed by
:mod:`chainvalidator.reporter`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------


class Status(str, enum.Enum):
    """DNSSEC chain-of-trust validation status.

    :cvar SECURE: Full chain of trust validated from root trust anchor.
    :cvar INSECURE: At least one delegation in the chain has no DS record;
        the chain is not anchored end-to-end.
    :cvar BOGUS: Cryptographic validation failed at some point in the chain.
    :cvar ERROR: An unrecoverable operational error occurred (network failure,
        unparseable response, etc.).
    """

    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"
    ERROR = "error"

    @property
    def is_ok(self) -> bool:
        """``True`` for :attr:`SECURE` only.

        :rtype: bool
        """
        return self is Status.SECURE

    @property
    def icon(self) -> str:
        """Unicode status icon for terminal display.

        :rtype: str
        """
        return {
            Status.SECURE: "✔",
            Status.INSECURE: "⚠",
            Status.BOGUS: "✘",
            Status.ERROR: "✘",
        }[self]


# ---------------------------------------------------------------------------
# Per-zone chain link
# ---------------------------------------------------------------------------


@dataclass
class ChainLink:
    """Result for a single delegation step in the chain of trust.

    :param zone: Zone name (e.g. ``"example.com."``).
    :param parent_zone: Parent zone name (e.g. ``"com."``), or ``""`` for root.
    :param status: Validation status for this link.
    :param ds_records: Human-readable labels of DS records found
        (e.g. ``["DS=12345/SHA-256"]``).
    :param dnskeys: Human-readable labels of DNSKEY records found
        (e.g. ``["DNSKEY=12345/SEP"]``).
    :param ds_matched: Human-readable DS→DNSKEY matches that were confirmed.
    :param rrsig_used: Key tag of the RRSIG that validated the DNSKEY RRset.
    :param errors: Hard errors recorded for this link.
    :param warnings: Advisory warnings recorded for this link.
    :param notes: Informational notes (e.g. ``"zone is unsigned"``).
    """

    zone: str
    parent_zone: str = ""
    status: Status = Status.SECURE
    ds_records: list[str] = field(default_factory=list)
    dnskeys: list[str] = field(default_factory=list)
    ds_matched: list[str] = field(default_factory=list)
    rrsig_used: Optional[int] = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Leaf record result
# ---------------------------------------------------------------------------


@dataclass
class LeafResult:
    """Validation result for the final (leaf) DNS record.

    :param qname: Queried name (may differ from the domain if a CNAME was
        followed).
    :param record_type: RR type string (e.g. ``"A"``).
    :param records: Wire-format text representations of matching records.
    :param rrsig_used: Key tag of the RRSIG that validated the RRset.
    :param rrsig_expires: ISO-8601 expiry timestamp of the RRSIG.
    :param cname_chain: Names traversed when following CNAME redirects.
    :param status: Validation status for the leaf.
    :param errors: Hard errors.
    :param warnings: Advisory warnings.
    :param notes: Informational notes (e.g. NODATA / NXDOMAIN proofs).
    """

    qname: str
    record_type: str
    records: list[str] = field(default_factory=list)
    rrsig_used: Optional[int] = None
    rrsig_expires: str = ""
    cname_chain: list[str] = field(default_factory=list)
    status: Status = Status.SECURE
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


@dataclass
class DNSSECReport:
    """Complete DNSSEC chain-of-trust validation report.

    This is the top-level object returned by :func:`chainvalidator.assessor.assess`
    and consumed by :func:`chainvalidator.reporter.print_full_report`.

    :param domain: Domain name that was validated (trailing dot stripped).
    :param record_type: RR type validated at the leaf (e.g. ``"A"``).
    :param status: Overall status — worst of all chain links and the leaf.
    :param trust_anchor_keys: Key tags of active IANA trust anchor DS records.
    :param chain: Ordered list of :class:`ChainLink` objects from root to
        the innermost zone, inclusive.
    :param leaf: Leaf record validation result, or ``None`` when the chain
        failed before reaching the target zone.
    :param errors: Top-level errors (e.g. trust anchor fetch failure).
    :param warnings: Top-level warnings.
    """

    domain: str
    record_type: str = "A"
    status: Status = Status.SECURE
    trust_anchor_keys: list[str] = field(default_factory=list)
    chain: list[ChainLink] = field(default_factory=list)
    leaf: Optional[LeafResult] = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_secure(self) -> bool:
        """``True`` when the full chain including the leaf is :attr:`~Status.SECURE`.

        :rtype: bool
        """
        return self.status is Status.SECURE

    @property
    def is_insecure(self) -> bool:
        """``True`` when the chain has an insecure delegation.

        :rtype: bool
        """
        return self.status is Status.INSECURE

    @property
    def is_bogus(self) -> bool:
        """``True`` when cryptographic validation failed.

        :rtype: bool
        """
        return self.status is Status.BOGUS

    @property
    def zone_path(self) -> list[str]:
        """Ordered zone names traversed, e.g. ``['.', 'com.', 'example.com.']``.

        :rtype: list[str]
        """
        if not self.chain:
            return ["."]
        zones = ["."]
        for link in self.chain:
            if link.zone != ".":
                zones.append(link.zone)
        return zones
