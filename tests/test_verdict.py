"""Tests for chainvalidator.verdict — extract_verdict_actions."""

from __future__ import annotations

import pytest

from chainvalidator.models import ChainLink, DNSSECReport, LeafResult, Status
from chainvalidator.verdict import VerdictAction, VerdictSeverity, extract_verdict_actions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severities(actions: list[VerdictAction]) -> list[VerdictSeverity]:
    return [a.severity for a in actions]


def _has(actions: list[VerdictAction], severity: VerdictSeverity) -> bool:
    return any(a.severity == severity for a in actions)


# ---------------------------------------------------------------------------
# Basic status → actions mapping
# ---------------------------------------------------------------------------


class TestExtractVerdictActionsStatus:
    def test_secure_no_issues_returns_empty(self):
        report = DNSSECReport(domain="example.com", status=Status.SECURE)
        assert extract_verdict_actions(report) == []

    def test_bogus_status_returns_critical(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.BOGUS,
            errors=["sig mismatch at com."],
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.CRITICAL)

    def test_error_status_returns_critical(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.ERROR,
            errors=["network error"],
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.CRITICAL)

    def test_insecure_status_returns_high(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.INSECURE,
            warnings=["no DS found at com."],
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.HIGH)

    def test_insecure_without_warnings_still_has_high(self):
        """Insecure delegation always warrants a HIGH action even with no warnings."""
        report = DNSSECReport(domain="example.com", status=Status.INSECURE)
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.HIGH)


# ---------------------------------------------------------------------------
# Report-level errors and warnings
# ---------------------------------------------------------------------------


class TestReportLevelMessages:
    def test_report_errors_produce_critical_actions(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.BOGUS,
            errors=["validation failed"],
        )
        actions = extract_verdict_actions(report)
        texts = [a.text for a in actions if a.severity == VerdictSeverity.CRITICAL]
        assert any("validation failed" in t for t in texts)

    def test_report_warnings_with_insecure_produce_high(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.INSECURE,
            warnings=["no DS at com."],
        )
        actions = extract_verdict_actions(report)
        texts = [a.text for a in actions if a.severity == VerdictSeverity.HIGH]
        assert any("no DS at com." in t for t in texts)

    def test_report_warnings_with_secure_produce_medium(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.SECURE,
            warnings=["weak algorithm advisory"],
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.MEDIUM)
        assert not _has(actions, VerdictSeverity.CRITICAL)


# ---------------------------------------------------------------------------
# Chain link issues
# ---------------------------------------------------------------------------


class TestChainLinkActions:
    def test_bogus_link_errors_produce_critical(self):
        report = DNSSECReport(domain="example.com", status=Status.BOGUS)
        report.chain.append(
            ChainLink(zone="com.", status=Status.BOGUS, errors=["sig mismatch"])
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.CRITICAL)

    def test_bogus_link_no_errors_uses_generic_critical(self):
        """BOGUS chain link with no error list → generic fallback CRITICAL action."""
        report = DNSSECReport(domain="example.com", status=Status.BOGUS)
        report.chain.append(ChainLink(zone="com.", status=Status.BOGUS, errors=[]))
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.CRITICAL)
        assert any("validation failed" in a.text for a in actions)

    def test_insecure_link_produces_high(self):
        report = DNSSECReport(domain="example.com", status=Status.INSECURE)
        report.chain.append(
            ChainLink(
                zone="com.",
                status=Status.INSECURE,
                warnings=["no DS record at com."],
            )
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.HIGH)

    def test_secure_link_warnings_produce_medium(self):
        report = DNSSECReport(domain="example.com", status=Status.SECURE)
        report.chain.append(
            ChainLink(
                zone="com.",
                status=Status.SECURE,
                warnings=["advisory: algo 5 is deprecated"],
            )
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.MEDIUM)

    def test_secure_link_no_warnings_produces_nothing(self):
        report = DNSSECReport(domain="example.com", status=Status.SECURE)
        report.chain.append(ChainLink(zone="com.", status=Status.SECURE))
        assert extract_verdict_actions(report) == []


# ---------------------------------------------------------------------------
# Leaf result issues
# ---------------------------------------------------------------------------


class TestLeafActions:
    def test_bogus_leaf_errors_produce_critical(self):
        report = DNSSECReport(domain="example.com", status=Status.BOGUS)
        report.leaf = LeafResult(
            qname="example.com",
            record_type="A",
            status=Status.BOGUS,
            errors=["rrsig invalid"],
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.CRITICAL)

    def test_bogus_leaf_no_errors_uses_generic_critical(self):
        """BOGUS leaf with no error list → generic fallback CRITICAL action."""
        report = DNSSECReport(domain="example.com", status=Status.BOGUS)
        report.leaf = LeafResult(
            qname="example.com", record_type="A", status=Status.BOGUS, errors=[]
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.CRITICAL)
        assert any("RRSIG" in a.text for a in actions)

    def test_insecure_leaf_warnings_produce_high(self):
        report = DNSSECReport(domain="example.com", status=Status.INSECURE)
        report.leaf = LeafResult(
            qname="example.com",
            record_type="A",
            status=Status.INSECURE,
            warnings=["leaf rrsig missing"],
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.HIGH)

    def test_secure_leaf_warnings_produce_medium(self):
        report = DNSSECReport(domain="example.com", status=Status.SECURE)
        report.leaf = LeafResult(
            qname="example.com",
            record_type="A",
            status=Status.SECURE,
            warnings=["rrsig expiring soon"],
        )
        actions = extract_verdict_actions(report)
        assert _has(actions, VerdictSeverity.MEDIUM)

    def test_secure_leaf_no_issues_produces_nothing(self):
        report = DNSSECReport(domain="example.com", status=Status.SECURE)
        report.leaf = LeafResult(qname="example.com", record_type="A", status=Status.SECURE)
        assert extract_verdict_actions(report) == []


# ---------------------------------------------------------------------------
# Ordering and deduplication
# ---------------------------------------------------------------------------


class TestOrderingAndDeduplication:
    def test_actions_sorted_critical_before_high_before_medium(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.BOGUS,
            errors=["critical failure"],
            warnings=["medium advisory"],
        )
        report.chain.append(
            ChainLink(zone="com.", status=Status.INSECURE, warnings=["no DS"])
        )
        actions = extract_verdict_actions(report)
        _SEV_ORDER = {
            VerdictSeverity.CRITICAL: 0,
            VerdictSeverity.HIGH: 1,
            VerdictSeverity.MEDIUM: 2,
        }
        orders = [_SEV_ORDER[a.severity] for a in actions]
        assert orders == sorted(orders), "Actions must be sorted CRITICAL → HIGH → MEDIUM"

    def test_duplicate_texts_deduplicated(self):
        """Same error message appearing twice should produce only one action."""
        report = DNSSECReport(
            domain="example.com",
            status=Status.BOGUS,
            errors=["sig mismatch"],
        )
        report.chain.append(
            ChainLink(zone="com.", status=Status.BOGUS, errors=["sig mismatch"])
        )
        actions = extract_verdict_actions(report)
        texts = [a.text for a in actions]
        assert len(texts) == len(set(texts)), "Duplicate action texts must be deduplicated"

    def test_action_has_check_name(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.BOGUS,
            errors=["bad sig"],
        )
        actions = extract_verdict_actions(report)
        assert all(a.check_name for a in actions), "Every action must have a check_name"
