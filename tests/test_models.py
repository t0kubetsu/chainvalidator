"""Tests for chainvalidator.models."""

from __future__ import annotations

from chainvalidator.models import ChainLink, DNSSECReport, LeafResult, Status


class TestStatus:
    def test_values(self):
        assert Status.SECURE.value == "secure"
        assert Status.INSECURE.value == "insecure"
        assert Status.BOGUS.value == "bogus"
        assert Status.ERROR.value == "error"

    def test_is_ok_only_for_secure(self):
        assert Status.SECURE.is_ok is True
        assert Status.INSECURE.is_ok is False
        assert Status.BOGUS.is_ok is False
        assert Status.ERROR.is_ok is False

    def test_icon_secure(self):
        assert Status.SECURE.icon == "✔"

    def test_icon_insecure(self):
        assert Status.INSECURE.icon == "⚠"

    def test_icon_bogus(self):
        assert Status.BOGUS.icon == "✘"

    def test_icon_error(self):
        assert Status.ERROR.icon == "✘"

    def test_str_value(self):
        # As a str enum, the value IS the string
        assert Status.SECURE.value == "secure"
        assert Status.SECURE == "secure"  # equality via str inheritance


class TestChainLink:
    def test_defaults(self):
        link = ChainLink(zone="example.com.")
        assert link.parent_zone == ""
        assert link.status == Status.SECURE
        assert link.ds_records == []
        assert link.dnskeys == []
        assert link.ds_matched == []
        assert link.rrsig_used is None
        assert link.errors == []
        assert link.warnings == []
        assert link.notes == []

    def test_field_mutation(self):
        link = ChainLink(zone="example.com.")
        link.errors.append("boom")
        link.status = Status.BOGUS
        assert link.errors == ["boom"]
        assert link.status == Status.BOGUS

    def test_mutable_defaults_are_independent(self):
        a = ChainLink(zone="a.")
        b = ChainLink(zone="b.")
        a.errors.append("x")
        assert b.errors == []


class TestLeafResult:
    def test_defaults(self):
        leaf = LeafResult(qname="example.com", record_type="A")
        assert leaf.records == []
        assert leaf.rrsig_used is None
        assert leaf.rrsig_expires == ""
        assert leaf.cname_chain == []
        assert leaf.nxdomain is False
        assert leaf.nodata is False
        assert leaf.status == Status.SECURE
        assert leaf.errors == []
        assert leaf.warnings == []
        assert leaf.notes == []

    def test_nxdomain_default_is_false(self):
        leaf = LeafResult(qname="example.com", record_type="A")
        assert leaf.nxdomain is False

    def test_nxdomain_can_be_set_true(self):
        leaf = LeafResult(qname="example.com", record_type="A", nxdomain=True)
        assert leaf.nxdomain is True

    def test_nxdomain_mutable_defaults_are_independent(self):
        a = LeafResult(qname="a.example.com", record_type="A")
        b = LeafResult(qname="b.example.com", record_type="A")
        a.nxdomain = True
        assert b.nxdomain is False

    def test_nodata_default_is_false(self):
        leaf = LeafResult(qname="example.com", record_type="A")
        assert leaf.nodata is False

    def test_nodata_can_be_set_true(self):
        leaf = LeafResult(qname="example.com", record_type="A", nodata=True)
        assert leaf.nodata is True

    def test_nodata_mutable_defaults_are_independent(self):
        a = LeafResult(qname="a.example.com", record_type="A")
        b = LeafResult(qname="b.example.com", record_type="A")
        a.nodata = True
        assert b.nodata is False

    def test_set_fields(self):
        leaf = LeafResult(
            qname="example.com",
            record_type="A",
            records=["1.2.3.4"],
            rrsig_used=42,
            rrsig_expires="2099-01-01",
        )
        assert leaf.records == ["1.2.3.4"]
        assert leaf.rrsig_used == 42
        assert leaf.rrsig_expires == "2099-01-01"

    def test_secure_nxdomain_leaf(self):
        """A proven NXDOMAIN should be SECURE with nxdomain=True and a note."""
        leaf = LeafResult(
            qname="www.example.com",
            record_type="A",
            nxdomain=True,
            status=Status.SECURE,
            notes=[
                "Secure NXDOMAIN: www.example.com does not exist (denial proof validated)"
            ],
        )
        assert leaf.nxdomain is True
        assert leaf.status == Status.SECURE
        assert any("Secure NXDOMAIN" in n for n in leaf.notes)
        assert leaf.warnings == []
        assert leaf.errors == []

    def test_secure_nodata_leaf(self):
        """A proven NODATA (NSEC3) should be SECURE with nodata=True and a note."""
        leaf = LeafResult(
            qname="www.example.com",
            record_type="A",
            nodata=True,
            status=Status.SECURE,
            notes=[
                "Secure NODATA: www.example.com exists but has no A records (NSEC3 proof validated)"
            ],
        )
        assert leaf.nodata is True
        assert leaf.status == Status.SECURE
        assert any("NODATA" in n for n in leaf.notes)
        assert leaf.warnings == []
        assert leaf.errors == []

    def test_insecure_nxdomain_leaf(self):
        """An unproven NXDOMAIN should be INSECURE with nxdomain=True and a warning."""
        leaf = LeafResult(
            qname="www.example.com",
            record_type="A",
            nxdomain=True,
            status=Status.INSECURE,
            warnings=["NXDOMAIN: www.example.com does not exist in zone example.com."],
        )
        assert leaf.nxdomain is True
        assert leaf.status == Status.INSECURE
        assert any("NXDOMAIN" in w for w in leaf.warnings)
        assert leaf.errors == []


class TestDNSSECReport:
    def test_defaults(self):
        r = DNSSECReport(domain="example.com")
        assert r.record_type == "A"
        assert r.status == Status.SECURE
        assert r.trust_anchor_keys == []
        assert r.chain == []
        assert r.leaf is None
        assert r.errors == []
        assert r.warnings == []

    def test_is_secure(self):
        r = DNSSECReport(domain="d", status=Status.SECURE)
        assert r.is_secure is True
        assert r.is_insecure is False
        assert r.is_bogus is False

    def test_is_insecure(self):
        r = DNSSECReport(domain="d", status=Status.INSECURE)
        assert r.is_secure is False
        assert r.is_insecure is True
        assert r.is_bogus is False

    def test_is_bogus(self):
        r = DNSSECReport(domain="d", status=Status.BOGUS)
        assert r.is_secure is False
        assert r.is_insecure is False
        assert r.is_bogus is True

    def test_zone_path_empty_chain(self):
        r = DNSSECReport(domain="example.com")
        assert r.zone_path == ["."]

    def test_zone_path_with_chain(self):
        r = DNSSECReport(domain="example.com")
        r.chain.append(ChainLink(zone="."))
        r.chain.append(ChainLink(zone="com."))
        r.chain.append(ChainLink(zone="example.com."))
        assert r.zone_path == [".", "com.", "example.com."]

    def test_zone_path_root_only_in_chain(self):
        r = DNSSECReport(domain="example.com")
        r.chain.append(ChainLink(zone="."))
        # root "." is filtered out of the appended list
        assert r.zone_path == ["."]

    def test_secure_nxdomain_does_not_degrade_report(self):
        """A proven NXDOMAIN leaf must not cause the report status to degrade."""
        r = DNSSECReport(domain="www.example.com", status=Status.SECURE)
        r.leaf = LeafResult(
            qname="www.example.com",
            record_type="A",
            nxdomain=True,
            status=Status.SECURE,
            notes=[
                "Secure NXDOMAIN: www.example.com does not exist (denial proof validated)"
            ],
        )
        # No errors or warnings on the report itself
        assert r.errors == []
        assert r.warnings == []
        assert r.is_secure is True
