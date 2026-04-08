"""Verdict panel: extract and display prioritised DNSSEC security actions.

Analyses a :class:`~chainvalidator.models.DNSSECReport` and produces a ranked
list of :class:`VerdictAction` items highlighting the most important issues
the operator should address.  Severity is context-aware:

- ``BOGUS`` / ``ERROR`` status → CRITICAL (cryptographic failure)
- ``INSECURE`` delegation → HIGH (chain not anchored)
- Advisory warnings on otherwise-SECURE links → MEDIUM
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from chainvalidator.models import DNSSECReport, Status


class VerdictSeverity(str, Enum):
    """Severity level for a verdict action item.

    Ordered from most to least urgent:
    ``CRITICAL`` → ``HIGH`` → ``MEDIUM``.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


@dataclass
class VerdictAction:
    """A single prioritised action derived from a validation result.

    :param text: Human-readable action description shown in the verdict panel.
    :param severity: Importance level of this action.
    :param check_name: Identifier of the source that produced this action
        (e.g. ``"chain:com."`` or ``"leaf"``).
    """

    text: str
    severity: VerdictSeverity
    check_name: str


_SEV_ORDER: dict[VerdictSeverity, int] = {
    VerdictSeverity.CRITICAL: 0,
    VerdictSeverity.HIGH: 1,
    VerdictSeverity.MEDIUM: 2,
}


def extract_verdict_actions(report: DNSSECReport) -> list[VerdictAction]:
    """Derive a sorted, deduplicated list of :class:`VerdictAction` from *report*.

    Returns an empty list when the report is fully SECURE with no warnings.
    Otherwise returns actions ordered ``CRITICAL`` → ``HIGH`` → ``MEDIUM``.

    :param report: The fully populated validation report.
    :type report: ~chainvalidator.models.DNSSECReport
    :returns: Sorted, deduplicated list of verdict actions.
    :rtype: list[VerdictAction]
    """
    raw: list[VerdictAction] = []

    # ------------------------------------------------------------------
    # Report-level errors → CRITICAL
    # ------------------------------------------------------------------
    for err in report.errors:
        raw.append(
            VerdictAction(
                text=f"Fix: {err}",
                severity=VerdictSeverity.CRITICAL,
                check_name="validation-error",
            )
        )

    # ------------------------------------------------------------------
    # Overall INSECURE status with no chain detail → generic HIGH
    # ------------------------------------------------------------------
    if report.status is Status.INSECURE and not report.chain:
        raw.append(
            VerdictAction(
                text="Chain of trust is not anchored end-to-end; add DS records.",
                severity=VerdictSeverity.HIGH,
                check_name="chain",
            )
        )

    # ------------------------------------------------------------------
    # Report-level warnings
    # ------------------------------------------------------------------
    warning_sev = (
        VerdictSeverity.HIGH
        if report.status is Status.INSECURE
        else VerdictSeverity.MEDIUM
    )
    for w in report.warnings:
        raw.append(
            VerdictAction(text=f"Review: {w}", severity=warning_sev, check_name="chain")
        )

    # ------------------------------------------------------------------
    # Chain link issues
    # ------------------------------------------------------------------
    for link in report.chain:
        if link.status is Status.BOGUS:
            for err in link.errors:
                raw.append(
                    VerdictAction(
                        text=f"Fix {link.zone}: {err}",
                        severity=VerdictSeverity.CRITICAL,
                        check_name=f"chain:{link.zone}",
                    )
                )
            if not link.errors:
                raw.append(
                    VerdictAction(
                        text=f"Fix {link.zone}: DNSSEC validation failed",
                        severity=VerdictSeverity.CRITICAL,
                        check_name=f"chain:{link.zone}",
                    )
                )
        elif link.status is Status.INSECURE:
            raw.append(
                VerdictAction(
                    text=f"Add DS record to establish secure delegation at {link.zone}",
                    severity=VerdictSeverity.HIGH,
                    check_name=f"chain:{link.zone}",
                )
            )
            for w in link.warnings:
                raw.append(
                    VerdictAction(
                        text=f"Review {link.zone}: {w}",
                        severity=VerdictSeverity.HIGH,
                        check_name=f"chain:{link.zone}",
                    )
                )
        else:
            # SECURE link — advisory warnings only
            for w in link.warnings:
                raw.append(
                    VerdictAction(
                        text=f"Review {link.zone}: {w}",
                        severity=VerdictSeverity.MEDIUM,
                        check_name=f"chain:{link.zone}",
                    )
                )

    # ------------------------------------------------------------------
    # Leaf result issues
    # ------------------------------------------------------------------
    if report.leaf is not None:
        leaf = report.leaf
        if leaf.status is Status.BOGUS:
            for err in leaf.errors:
                raw.append(
                    VerdictAction(
                        text=f"Fix leaf record: {err}",
                        severity=VerdictSeverity.CRITICAL,
                        check_name="leaf",
                    )
                )
            if not leaf.errors:
                raw.append(
                    VerdictAction(
                        text="Fix leaf record: RRSIG validation failed",
                        severity=VerdictSeverity.CRITICAL,
                        check_name="leaf",
                    )
                )
        elif leaf.status is Status.INSECURE:
            for w in leaf.warnings:
                raw.append(
                    VerdictAction(
                        text=f"Review leaf: {w}",
                        severity=VerdictSeverity.HIGH,
                        check_name="leaf",
                    )
                )
        else:
            # SECURE leaf — advisory warnings only
            for w in leaf.warnings:
                raw.append(
                    VerdictAction(
                        text=f"Review leaf: {w}",
                        severity=VerdictSeverity.MEDIUM,
                        check_name="leaf",
                    )
                )

    # ------------------------------------------------------------------
    # Deduplicate by text, then sort by severity
    # ------------------------------------------------------------------
    seen: set[str] = set()
    unique: list[VerdictAction] = []
    for action in raw:
        if action.text not in seen:
            seen.add(action.text)
            unique.append(action)

    return sorted(unique, key=lambda a: _SEV_ORDER[a.severity])
