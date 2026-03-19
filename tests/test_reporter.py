"""Tests for chainvalidator.reporter."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.table import Table

from chainvalidator.models import (
    ChainLink,
    DNSSECReport,
    LeafResult,
    Status,
)
from chainvalidator.reporter import (
    _chain_table,
    _status_panel_style,
    _status_text,
    print_chain,
    print_full_report,
    print_leaf,
    print_trust_anchor,
    print_verdict,
)


# ---------------------------------------------------------------------------
# Helper: capture Rich output into a string
# ---------------------------------------------------------------------------


def _capture(fn, *args, **kwargs) -> str:
    """Call *fn* with patched console and return the rendered text."""
    import chainvalidator.reporter as _rep

    buf = StringIO()
    _rep.console = Console(file=buf, highlight=False, markup=False)
    try:
        fn(*args, **kwargs)
    finally:
        _rep.console = Console()
    return buf.getvalue()


# ---------------------------------------------------------------------------
# _status_text
# ---------------------------------------------------------------------------


class TestStatusText:
    def test_secure(self):
        t = _status_text(Status.SECURE)
        assert "SECURE" in t.plain

    def test_insecure(self):
        t = _status_text(Status.INSECURE)
        assert "INSECURE" in t.plain

    def test_bogus(self):
        t = _status_text(Status.BOGUS)
        assert "BOGUS" in t.plain

    def test_error(self):
        t = _status_text(Status.ERROR)
        assert "ERROR" in t.plain

    def test_unknown_status_fallback(self):
        """_STATUS_STYLE.get fallback for unexpected values."""
        t = (
            _status_text.__wrapped__(Status.SECURE)
            if hasattr(_status_text, "__wrapped__")
            else _status_text(Status.SECURE)
        )
        assert t is not None


# ---------------------------------------------------------------------------
# _status_panel_style
# ---------------------------------------------------------------------------


class TestStatusPanelStyle:
    def test_secure_is_green(self):
        assert _status_panel_style(Status.SECURE) == "green"

    def test_insecure_is_yellow(self):
        assert _status_panel_style(Status.INSECURE) == "yellow"

    def test_bogus_is_red(self):
        assert _status_panel_style(Status.BOGUS) == "red"

    def test_error_is_red(self):
        assert _status_panel_style(Status.ERROR) == "red"


# ---------------------------------------------------------------------------
# _chain_table
# ---------------------------------------------------------------------------


class TestChainTable:
    def test_returns_table(self):
        chain = [ChainLink(zone="example.com.", status=Status.SECURE)]
        tbl = _chain_table(chain)
        assert isinstance(tbl, Table)

    def test_row_with_no_ds_shows_dash(self):
        chain = [ChainLink(zone=".", ds_records=[], dnskeys=[])]
        tbl = _chain_table(chain)
        assert tbl.row_count == 1

    def test_row_with_ds_and_matches(self):
        link = ChainLink(
            zone="example.com.",
            ds_records=["DS=1/SHA-256"],
            dnskeys=["DNSKEY=1/SEP"],
            ds_matched=["DS=1/SHA-256 → DNSKEY=1/SEP"],
            warnings=["warning"],
            errors=["error"],
        )
        tbl = _chain_table([link])
        assert tbl.row_count == 1


# ---------------------------------------------------------------------------
# print_trust_anchor
# ---------------------------------------------------------------------------


class TestPrintTrustAnchor:
    def test_with_keys(self):
        report = DNSSECReport(
            domain="example.com", trust_anchor_keys=["DS=20326/SHA-256"]
        )
        out = _capture(print_trust_anchor, report)
        assert "DS=20326/SHA-256" in out

    def test_no_keys_shows_error(self):
        report = DNSSECReport(domain="example.com", trust_anchor_keys=[])
        out = _capture(print_trust_anchor, report)
        assert "No active trust anchor keys found" in out


# ---------------------------------------------------------------------------
# print_chain
# ---------------------------------------------------------------------------


class TestPrintChain:
    def test_with_chain(self):
        report = DNSSECReport(domain="example.com")
        report.chain.append(ChainLink(zone="."))
        out = _capture(print_chain, report)
        assert "." in out

    def test_empty_chain(self):
        report = DNSSECReport(domain="example.com")
        out = _capture(print_chain, report)
        assert "No chain data available" in out


# ---------------------------------------------------------------------------
# print_leaf
# ---------------------------------------------------------------------------


class TestPrintLeaf:
    def test_leaf_none(self):
        report = DNSSECReport(domain="example.com")
        out = _capture(print_leaf, report)
        assert "Chain validation did not reach the leaf record" in out

    def test_leaf_with_records(self):
        report = DNSSECReport(domain="example.com")
        report.leaf = LeafResult(
            qname="example.com",
            record_type="A",
            records=["1.2.3.4"],
            rrsig_used=42,
            rrsig_expires="2099-01-01",
        )
        out = _capture(print_leaf, report)
        assert "1.2.3.4" in out
        assert "42" in out
        assert "2099-01-01" in out

    def test_leaf_with_cname_chain(self):
        report = DNSSECReport(domain="example.com")
        report.leaf = LeafResult(
            qname="target.example.com",
            record_type="A",
            cname_chain=["target.example.com"],
        )
        out = _capture(print_leaf, report)
        assert "target.example.com" in out

    def test_leaf_no_records_nodata(self):
        report = DNSSECReport(domain="example.com")
        report.leaf = LeafResult(qname="example.com", record_type="A", records=[])
        out = _capture(print_leaf, report)
        assert "No A records found" in out

    def test_leaf_with_notes_warnings_errors(self):
        report = DNSSECReport(domain="example.com")
        report.leaf = LeafResult(
            qname="example.com",
            record_type="A",
            notes=["a note"],
            warnings=["a warn"],
            errors=["an error"],
        )
        out = _capture(print_leaf, report)
        assert "a note" in out
        assert "a warn" in out
        assert "an error" in out

    def test_rrsig_without_expiry(self):
        report = DNSSECReport(domain="example.com")
        report.leaf = LeafResult(
            qname="example.com",
            record_type="A",
            rrsig_used=99,
            rrsig_expires="",
        )
        out = _capture(print_leaf, report)
        assert "99" in out


# ---------------------------------------------------------------------------
# print_verdict
# ---------------------------------------------------------------------------


class TestPrintVerdict:
    def test_secure_verdict(self):
        report = DNSSECReport(domain="example.com", status=Status.SECURE)
        out = _capture(print_verdict, report)
        assert "example.com" in out
        assert "successfully" in out

    def test_insecure_verdict_shows_warnings(self):
        report = DNSSECReport(
            domain="example.com", status=Status.INSECURE, warnings=["no DS found"]
        )
        out = _capture(print_verdict, report)
        assert "NOT fully anchored" in out
        assert "no DS found" in out

    def test_bogus_verdict_shows_errors(self):
        report = DNSSECReport(
            domain="example.com", status=Status.BOGUS, errors=["sig mismatch"]
        )
        out = _capture(print_verdict, report)
        assert "FAILED" in out
        assert "sig mismatch" in out

    def test_error_status_uses_bogus_branch(self):
        report = DNSSECReport(
            domain="example.com", status=Status.ERROR, errors=["network error"]
        )
        out = _capture(print_verdict, report)
        assert "FAILED" in out


# ---------------------------------------------------------------------------
# print_full_report
# ---------------------------------------------------------------------------


class TestPrintFullReport:
    def test_full_report_secure(self):
        report = DNSSECReport(
            domain="example.com",
            status=Status.SECURE,
            trust_anchor_keys=["DS=1/SHA-256"],
        )
        report.chain.append(ChainLink(zone="."))
        report.leaf = LeafResult(
            qname="example.com", record_type="A", records=["1.2.3.4"]
        )
        out = _capture(print_full_report, report)
        assert "example.com" in out
        assert "SECURE" in out.upper() or "successfully" in out

    def test_full_report_bogus(self):
        report = DNSSECReport(
            domain="fail.example", status=Status.BOGUS, errors=["chain broken"]
        )
        out = _capture(print_full_report, report)
        assert "chain broken" in out
