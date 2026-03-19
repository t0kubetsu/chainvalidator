"""Tests for chainvalidator.checker.DNSSECChecker.

All DNS I/O is mocked.  Tests exercise every branch by controlling the
return values of udp_query, get_dnskey, get_ds_from_parent, requests.get,
and dns.resolver.resolve.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from chainvalidator.checker import DNSSECChecker
from chainvalidator.models import Status
from tests.conftest import (
    make_a_rrset,
    make_cname_rrset,
    make_dnskey_rdata,
    make_dnskey_rrset,
    make_ds_rrset,
    make_ns_rrset,
    make_nsec_rrset,
    make_response,
    make_response_with_answer,
    make_rrsig_rrset,
    make_soa_rrset,
)

# ---------------------------------------------------------------------------
# Helpers shared across many tests
# ---------------------------------------------------------------------------

TRUST_ANCHOR_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="AD42165F-3B1A-4778-8F42-D34A1D41FD93" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Klajeyz" validFrom="2010-07-15T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Flags>257</Flags>
<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
</KeyDigest>
</TrustAnchor>
"""

EXPIRED_TA_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor>
<Zone>.</Zone>
<KeyDigest validFrom="2000-01-01T00:00:00+00:00" validUntil="2001-01-01T00:00:00+00:00">
<KeyTag>99</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Flags>257</Flags>
<Digest>AABBCC</Digest>
</KeyDigest>
</TrustAnchor>
"""

FUTURE_TA_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor>
<Zone>.</Zone>
<KeyDigest validFrom="2099-01-01T00:00:00+00:00">
<KeyTag>88</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Flags>257</Flags>
<Digest>AABBCC</Digest>
</KeyDigest>
</TrustAnchor>
"""

NO_SEP_TA_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor>
<Zone>.</Zone>
<KeyDigest validFrom="2010-01-01T00:00:00+00:00">
<KeyTag>77</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Flags>256</Flags>
<Digest>AABBCC</Digest>
</KeyDigest>
</TrustAnchor>
"""

NO_FLAGS_TA_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor>
<Zone>.</Zone>
<KeyDigest validFrom="2010-01-01T00:00:00+00:00">
<KeyTag>55</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
</KeyDigest>
</TrustAnchor>
"""


def _ns_response(
    zone: str, ns_name: str = "ns1.example.com.", ns_ip: str = "1.2.3.4"
) -> dns.message.Message:
    """Build a referral NS response with glue A record."""
    resp = make_response(zone, dns.rdatatype.NS)
    ns_rr = make_ns_rrset(zone, [ns_name])
    resp.authority.append(ns_rr)
    # glue
    a_rr = make_a_rrset(ns_name, addresses=[ns_ip])
    resp.additional.append(a_rr)
    return resp


def _soa_response(zone: str) -> dns.message.Message:
    """Build a SOA-in-authority response (name lives inside parent zone)."""
    resp = make_response(zone, dns.rdatatype.NS)
    resp.authority.append(make_soa_rrset(zone))
    return resp


def _make_checker(domain: str = "example.com", record_type: str = "A") -> DNSSECChecker:
    return DNSSECChecker(domain, record_type=record_type)


# ---------------------------------------------------------------------------
# __init__ validation
# ---------------------------------------------------------------------------


class TestCheckerInit:
    def test_valid_domain(self):
        c = _make_checker("example.com")
        assert c.domain == "example.com."

    def test_trailing_dot_preserved(self):
        c = _make_checker("example.com.")
        assert c.domain == "example.com."

    def test_single_label_raises(self):
        with pytest.raises(ValueError, match="fully-qualified"):
            DNSSECChecker("localhost")

    def test_invalid_domain_raises(self):
        with pytest.raises(ValueError):
            DNSSECChecker("!!!invalid!!!")

    def test_invalid_record_type_raises(self):
        with pytest.raises(ValueError, match="Unknown record type"):
            DNSSECChecker("example.com", record_type="NOTATYPE")

    def test_report_initialized(self):
        c = _make_checker()
        assert c.report.domain == "example.com"
        assert c.report.record_type == "A"

    def test_record_type_uppercased(self):
        c = DNSSECChecker("example.com", record_type="a")
        assert c.report.record_type == "A"


# ---------------------------------------------------------------------------
# _build_zone_list
# ---------------------------------------------------------------------------


class TestBuildZoneList:
    def test_com_zone_detected(self):
        """example.com → ['.', 'com.', 'example.com.']"""
        c = _make_checker("example.com")

        def udp_side_effect(qname, rdtype, ns_ip, *args, **kwargs):
            qname_str = str(qname) if hasattr(qname, "to_text") else qname
            if "com." in str(qname_str) and "example" not in str(qname_str):
                return _ns_response("com.", "ns1.com.", "2.2.2.2")
            return _ns_response("example.com.", "ns1.example.com.", "3.3.3.3")

        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch("chainvalidator.checker.udp_query", side_effect=udp_side_effect):
                zones = c._build_zone_list("example.com.")
        assert "." in zones
        assert "com." in zones
        assert "example.com." in zones

    def test_udp_failure_returns_empty_ns(self):
        """If udp_query raises, the candidate is treated as non-apex."""
        c = _make_checker("example.com")
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch(
                "chainvalidator.checker.udp_query", side_effect=RuntimeError("timeout")
            ):
                zones = c._build_zone_list("example.com.")
        assert zones == ["."]  # nothing resolved → only root

    def test_soa_in_authority_returns_empty(self):
        """SOA in authority means candidate is not a zone apex."""
        c = _make_checker("example.com")
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch(
                "chainvalidator.checker.udp_query",
                return_value=_soa_response("example.com."),
            ):
                zones = c._build_zone_list("example.com.")
        assert "example.com." not in zones

    def test_ns_in_answer_section(self):
        """NS in ANSWER (not authority) also confirms zone apex."""
        c = _make_checker("example.com")
        resp = make_response("example.com.", dns.rdatatype.NS)
        ns_rr = make_ns_rrset("example.com.", ["ns1.example.com."])
        resp.answer.append(ns_rr)
        a_rr = make_a_rrset("ns1.example.com.", addresses=["1.2.3.4"])
        resp.additional.append(a_rr)
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch("chainvalidator.checker.udp_query", return_value=resp):
                zones = c._build_zone_list("example.com.")
        assert "example.com." in zones

    def test_ns_without_glue_resolved(self):
        """NS without glue falls back to dns.resolver.resolve."""
        c = _make_checker("example.com")
        resp = make_response("example.com.", dns.rdatatype.NS)
        ns_rr = make_ns_rrset("example.com.", ["ns1.example.com."])
        resp.authority.append(ns_rr)
        # No glue in additional

        mock_answer = MagicMock()
        mock_answer[0].address = "9.9.9.9"

        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch("chainvalidator.checker.udp_query", return_value=resp):
                with patch(
                    "chainvalidator.checker.dns.resolver.resolve",
                    return_value=mock_answer,
                ):
                    zones = c._build_zone_list("example.com.")
        assert "example.com." in zones

    def test_ns_resolve_failure_ignored(self):
        """If resolver.resolve fails, NS is skipped but no exception raised."""
        c = _make_checker("example.com")
        resp = make_response("example.com.", dns.rdatatype.NS)
        ns_rr = make_ns_rrset("example.com.", ["ns1.example.com."])
        resp.authority.append(ns_rr)

        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch("chainvalidator.checker.udp_query", return_value=resp):
                with patch(
                    "chainvalidator.checker.dns.resolver.resolve",
                    side_effect=Exception("no resolve"),
                ):
                    _ = c._build_zone_list("example.com.")
        # ns1.example.com resolved with no IP → zone list entry may or may not
        # be present (no NS IP → empty result list → zone skipped)

    def test_no_ns_names_found_returns_empty(self):
        """Response with no NS and no SOA returns empty list."""
        c = _make_checker("example.com")
        resp = make_response("example.com.", dns.rdatatype.NS)
        # No NS, no SOA in authority
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch("chainvalidator.checker.udp_query", return_value=resp):
                zones = c._build_zone_list("example.com.")
        assert "example.com." not in zones


# ---------------------------------------------------------------------------
# _load_trust_anchor
# ---------------------------------------------------------------------------


class TestLoadTrustAnchor:
    def test_success_returns_ds_list(self):
        c = _make_checker()
        mock_resp = MagicMock()
        mock_resp.content = TRUST_ANCHOR_XML
        with patch("requests.get", return_value=mock_resp):
            ds_list = c._load_trust_anchor()
        assert len(ds_list) == 1

    def test_network_failure_records_error_and_returns_empty(self):
        c = _make_checker()
        with patch("requests.get", side_effect=Exception("network error")):
            ds_list = c._load_trust_anchor()
        assert ds_list == []
        assert len(c.errors) == 1

    def test_expired_key_digest_skipped(self):
        c = _make_checker()
        mock_resp = MagicMock()
        mock_resp.content = EXPIRED_TA_XML
        with patch("requests.get", return_value=mock_resp):
            ds_list = c._load_trust_anchor()
        assert ds_list == []
        assert any("No active" in e for e in c.errors)

    def test_future_key_digest_skipped(self):
        c = _make_checker()
        mock_resp = MagicMock()
        mock_resp.content = FUTURE_TA_XML
        with patch("requests.get", return_value=mock_resp):
            ds_list = c._load_trust_anchor()
        assert ds_list == []

    def test_non_sep_flags_skipped(self):
        c = _make_checker()
        mock_resp = MagicMock()
        mock_resp.content = NO_SEP_TA_XML
        with patch("requests.get", return_value=mock_resp):
            ds_list = c._load_trust_anchor()
        assert ds_list == []

    def test_missing_flags_element_skipped(self):
        c = _make_checker()
        mock_resp = MagicMock()
        mock_resp.content = NO_FLAGS_TA_XML
        with patch("requests.get", return_value=mock_resp):
            ds_list = c._load_trust_anchor()
        assert ds_list == []


# ---------------------------------------------------------------------------
# _check_root
# ---------------------------------------------------------------------------


class TestCheckRoot:
    def _dnskey_rrset_and_valid_ta(self):
        """Return (dnskey_rrset, rrsig_rrset, ta_ds_list) where DS matches DNSKEY."""
        dnskey = make_dnskey_rdata(flags=257, algorithm=13)
        dnskey_rrset = make_dnskey_rrset(name=".")
        # Clear and add our specific key
        dnskey_rrset.clear()
        dnskey_rrset.add(dnskey)

        computed_ds = dns.dnssec.make_ds(".", dnskey, 2)
        rrsig_rrset = make_rrsig_rrset(
            name=".",
            type_covered=dns.rdatatype.DNSKEY,
            key_tag=dns.dnssec.key_id(dnskey),
        )
        return dnskey_rrset, rrsig_rrset, [computed_ds]

    def test_get_dnskey_runtime_error(self):
        c = _make_checker()
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch(
                "chainvalidator.checker.get_dnskey",
                side_effect=RuntimeError("no connect"),
            ):
                result = c._check_root([MagicMock()], {})
        assert result is False
        assert len(c.errors) == 1

    def test_no_dnskey_records(self):
        c = _make_checker()
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch("chainvalidator.checker.get_dnskey", return_value=(None, None)):
                result = c._check_root([MagicMock()], {})
        assert result is False

    def test_no_ta_match(self):
        c = _make_checker()
        dnskey_rrset = make_dnskey_rrset(name=".")
        rrsig_rrset = make_rrsig_rrset(name=".", type_covered=dns.rdatatype.DNSKEY)
        ta_ds = [MagicMock()]  # DS that won't match

        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch(
                "chainvalidator.checker.get_dnskey",
                return_value=(dnskey_rrset, rrsig_rrset),
            ):
                with patch(
                    "chainvalidator.checker.ds_matches_dnskey", return_value=False
                ):
                    result = c._check_root(ta_ds, {})
        assert result is False

    def test_no_rrsig(self):
        c = _make_checker()
        dnskey_rrset = make_dnskey_rrset(name=".")
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch(
                "chainvalidator.checker.get_dnskey", return_value=(dnskey_rrset, None)
            ):
                with patch(
                    "chainvalidator.checker.ds_matches_dnskey", return_value=True
                ):
                    result = c._check_root([MagicMock()], {})
        assert result is False

    def test_rrsig_validation_fails(self):
        c = _make_checker()
        dnskey_rrset = make_dnskey_rrset(name=".")
        rrsig_rrset = make_rrsig_rrset(name=".", type_covered=dns.rdatatype.DNSKEY)
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch(
                "chainvalidator.checker.get_dnskey",
                return_value=(dnskey_rrset, rrsig_rrset),
            ):
                with patch(
                    "chainvalidator.checker.ds_matches_dnskey", return_value=True
                ):
                    with patch(
                        "chainvalidator.checker.validate_rrsig_over_rrset",
                        return_value=(False, None),
                    ):
                        result = c._check_root([MagicMock()], {})
        assert result is False

    def test_success(self):
        c = _make_checker()
        dnskey_rrset = make_dnskey_rrset(name=".")
        rrsig_rrset = make_rrsig_rrset(name=".", type_covered=dns.rdatatype.DNSKEY)
        validated = {}
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root-servers.net", "198.41.0.4"),
        ):
            with patch(
                "chainvalidator.checker.get_dnskey",
                return_value=(dnskey_rrset, rrsig_rrset),
            ):
                with patch(
                    "chainvalidator.checker.ds_matches_dnskey", return_value=True
                ):
                    with patch(
                        "chainvalidator.checker.validate_rrsig_over_rrset",
                        return_value=(True, 12345),
                    ):
                        result = c._check_root([MagicMock()], validated)
        assert result is True
        assert "." in validated
        assert len(c.report.chain) == 1
        assert c.report.chain[0].zone == "."


# ---------------------------------------------------------------------------
# _check_zone
# ---------------------------------------------------------------------------


class TestCheckZone:
    def _setup(self):
        c = _make_checker("example.com")
        c._zone_ns_map = {
            ".": [("a.root", "1.1.1.1")],
            "com.": [("ns1.com.", "2.2.2.2")],
        }
        parent_dnskeys = make_dnskey_rrset(name="com.")
        validated = {"com.": parent_dnskeys}
        return c, validated, parent_dnskeys

    def test_no_parent_ns_ip(self):
        c, validated, _ = self._setup()
        # Remove com. from map so parent NS lookup fails
        c._zone_ns_map = {}
        result = c._check_zone("com.", "example.com.", MagicMock(), validated)
        assert result is False

    def test_get_ds_runtime_error(self):
        c, validated, pk = self._setup()
        with patch(
            "chainvalidator.checker.get_ds_from_parent",
            side_effect=RuntimeError("DS fetch failed"),
        ):
            result = c._check_zone("com.", "example.com.", pk, validated)
        assert result is False

    def test_no_ds_triggers_insecure_delegation(self):
        c, validated, pk = self._setup()
        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(None, None)
        ):
            with patch.object(
                c, "_handle_insecure_delegation", return_value=True
            ) as mock_insecure:
                result = c._check_zone("com.", "example.com.", pk, validated)
        assert result is True
        mock_insecure.assert_called_once()

    def test_ds_found_but_no_rrsig(self):
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, None)
        ):
            result = c._check_zone("com.", "example.com.", pk, validated)
        assert result is False

    def test_ds_rrsig_validation_fails(self):
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DS)
        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, rrsig_r)
        ):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(False, None),
            ):
                result = c._check_zone("com.", "example.com.", pk, validated)
        assert result is False

    def test_no_child_ns_resolved(self):
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DS)
        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, rrsig_r)
        ):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                with patch.object(c, "_resolve_ns_for_child", return_value=[]):
                    result = c._check_zone("com.", "example.com.", pk, validated)
        assert result is False

    def test_no_child_dnskey(self):
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DS)
        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, rrsig_r)
        ):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                with patch.object(
                    c,
                    "_resolve_ns_for_child",
                    return_value=[("ns1.example.com.", "3.3.3.3")],
                ):
                    with patch(
                        "chainvalidator.checker.get_dnskey", return_value=(None, None)
                    ):
                        result = c._check_zone("com.", "example.com.", pk, validated)
        assert result is False

    def test_get_dnskey_raises_continues(self):
        """get_dnskey raising on first NS but succeeding on second."""
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DS)
        child_dnskeys = make_dnskey_rrset("example.com.")
        child_rrsig = make_rrsig_rrset(
            "example.com.", type_covered=dns.rdatatype.DNSKEY
        )
        call_count = [0]

        def dnskey_side(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("first NS failed")
            return child_dnskeys, child_rrsig

        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, rrsig_r)
        ):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                with patch.object(
                    c,
                    "_resolve_ns_for_child",
                    return_value=[("ns1.", "1.1.1.1"), ("ns2.", "2.2.2.2")],
                ):
                    with patch(
                        "chainvalidator.checker.get_dnskey", side_effect=dnskey_side
                    ):
                        with patch(
                            "chainvalidator.checker.ds_matches_dnskey",
                            return_value=True,
                        ):
                            result = c._check_zone(
                                "com.", "example.com.", pk, validated
                            )
        # Should succeed after second NS
        assert result is True

    def test_no_ds_dnskey_match(self):
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DS)
        child_dnskeys = make_dnskey_rrset("example.com.")
        child_rrsig = make_rrsig_rrset(
            "example.com.", type_covered=dns.rdatatype.DNSKEY
        )
        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, rrsig_r)
        ):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                with patch.object(
                    c, "_resolve_ns_for_child", return_value=[("ns1.", "1.1.1.1")]
                ):
                    with patch(
                        "chainvalidator.checker.get_dnskey",
                        return_value=(child_dnskeys, child_rrsig),
                    ):
                        with patch(
                            "chainvalidator.checker.ds_matches_dnskey",
                            return_value=False,
                        ):
                            result = c._check_zone(
                                "com.", "example.com.", pk, validated
                            )
        assert result is False

    def test_no_child_dnskey_rrsig(self):
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DS)
        child_dnskeys = make_dnskey_rrset("example.com.")
        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, rrsig_r)
        ):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                with patch.object(
                    c, "_resolve_ns_for_child", return_value=[("ns1.", "1.1.1.1")]
                ):
                    with patch(
                        "chainvalidator.checker.get_dnskey",
                        return_value=(child_dnskeys, None),
                    ):
                        with patch(
                            "chainvalidator.checker.ds_matches_dnskey",
                            return_value=True,
                        ):
                            result = c._check_zone(
                                "com.", "example.com.", pk, validated
                            )
        assert result is False

    def test_child_dnskey_rrsig_validation_fails(self):
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DS)
        child_dnskeys = make_dnskey_rrset("example.com.")
        child_rrsig = make_rrsig_rrset(
            "example.com.", type_covered=dns.rdatatype.DNSKEY
        )
        side_effects = [(True, 42), (False, None)]  # DS RRSIG ok, DNSKEY RRSIG fails
        idx = [0]

        def validate_side(*args, **kwargs):
            r = side_effects[idx[0]]
            idx[0] = min(idx[0] + 1, len(side_effects) - 1)
            return r

        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, rrsig_r)
        ):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                side_effect=validate_side,
            ):
                with patch.object(
                    c, "_resolve_ns_for_child", return_value=[("ns1.", "1.1.1.1")]
                ):
                    with patch(
                        "chainvalidator.checker.get_dnskey",
                        return_value=(child_dnskeys, child_rrsig),
                    ):
                        with patch(
                            "chainvalidator.checker.ds_matches_dnskey",
                            return_value=True,
                        ):
                            result = c._check_zone(
                                "com.", "example.com.", pk, validated
                            )
        assert result is False

    def test_full_success(self):
        c, validated, pk = self._setup()
        ds_rr = make_ds_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DS)
        child_dnskeys = make_dnskey_rrset("example.com.")
        child_rrsig = make_rrsig_rrset(
            "example.com.", type_covered=dns.rdatatype.DNSKEY
        )
        with patch(
            "chainvalidator.checker.get_ds_from_parent", return_value=(ds_rr, rrsig_r)
        ):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                with patch.object(
                    c, "_resolve_ns_for_child", return_value=[("ns1.", "1.1.1.1")]
                ):
                    with patch(
                        "chainvalidator.checker.get_dnskey",
                        return_value=(child_dnskeys, child_rrsig),
                    ):
                        with patch(
                            "chainvalidator.checker.ds_matches_dnskey",
                            return_value=True,
                        ):
                            result = c._check_zone(
                                "com.", "example.com.", pk, validated
                            )
        assert result is True
        assert "example.com." in validated


# ---------------------------------------------------------------------------
# _handle_insecure_delegation
# ---------------------------------------------------------------------------


class TestHandleInsecureDelegation:
    def _checker_with_ns(self):
        c = _make_checker("example.com")
        c._zone_ns_map = {"com.": [("ns1.com.", "2.2.2.2")]}
        return c

    def _make_link(self):
        from chainvalidator.models import ChainLink

        return ChainLink(
            zone="example.com.", parent_zone="com.", status=Status.INSECURE
        )

    def test_no_child_ns_returns_false(self):
        c = self._checker_with_ns()
        link = self._make_link()
        with patch.object(c, "_resolve_ns_for_child", return_value=[]):
            result = c._handle_insecure_delegation("example.com.", "2.2.2.2", {}, link)
        assert result is False

    def test_no_dnskey_zone_unsigned(self):
        c = self._checker_with_ns()
        link = self._make_link()
        validated = {}
        with patch.object(
            c, "_resolve_ns_for_child", return_value=[("ns1.", "1.1.1.1")]
        ):
            with patch("chainvalidator.checker.get_dnskey", return_value=(None, None)):
                result = c._handle_insecure_delegation(
                    "example.com.", "2.2.2.2", validated, link
                )
        assert result is True
        assert validated["example.com."] is None

    def test_dnskey_get_raises_continues(self):
        c = self._checker_with_ns()
        link = self._make_link()
        validated = {}
        call_n = [0]

        def dnskey_side(*args, **kwargs):
            call_n[0] += 1
            if call_n[0] == 1:
                raise RuntimeError("fail")
            return None, None

        with patch.object(
            c,
            "_resolve_ns_for_child",
            return_value=[("ns1.", "1.1.1.1"), ("ns2.", "2.2.2.2")],
        ):
            with patch("chainvalidator.checker.get_dnskey", side_effect=dnskey_side):
                result = c._handle_insecure_delegation(
                    "example.com.", "2.2.2.2", validated, link
                )
        assert result is True

    def test_with_dnskey_and_valid_rrsig(self):
        c = self._checker_with_ns()
        link = self._make_link()
        validated = {}
        dk_rr = make_dnskey_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DNSKEY)
        with patch.object(
            c, "_resolve_ns_for_child", return_value=[("ns1.", "1.1.1.1")]
        ):
            with patch(
                "chainvalidator.checker.get_dnskey", return_value=(dk_rr, rrsig_r)
            ):
                with patch(
                    "chainvalidator.checker.validate_rrsig_over_rrset",
                    return_value=(True, 42),
                ):
                    result = c._handle_insecure_delegation(
                        "example.com.", "2.2.2.2", validated, link
                    )
        assert result is True
        assert link.rrsig_used == 42

    def test_with_dnskey_and_invalid_rrsig(self):
        c = self._checker_with_ns()
        link = self._make_link()
        validated = {}
        dk_rr = make_dnskey_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.DNSKEY)
        with patch.object(
            c, "_resolve_ns_for_child", return_value=[("ns1.", "1.1.1.1")]
        ):
            with patch(
                "chainvalidator.checker.get_dnskey", return_value=(dk_rr, rrsig_r)
            ):
                with patch(
                    "chainvalidator.checker.validate_rrsig_over_rrset",
                    return_value=(False, None),
                ):
                    result = c._handle_insecure_delegation(
                        "example.com.", "2.2.2.2", validated, link
                    )
        assert result is True  # still returns True (insecure, not bogus)
        assert len(link.notes) >= 1

    def test_with_dnskey_no_rrsig(self):
        c = self._checker_with_ns()
        link = self._make_link()
        validated = {}
        dk_rr = make_dnskey_rrset("example.com.")
        with patch.object(
            c, "_resolve_ns_for_child", return_value=[("ns1.", "1.1.1.1")]
        ):
            with patch("chainvalidator.checker.get_dnskey", return_value=(dk_rr, None)):
                result = c._handle_insecure_delegation(
                    "example.com.", "2.2.2.2", validated, link
                )
        assert result is True


# ---------------------------------------------------------------------------
# _check_final_rrset
# ---------------------------------------------------------------------------


class TestCheckFinalRrset:
    def _checker_with_ns_map(self):
        c = _make_checker("example.com")
        c._zone_ns_map = {"example.com.": [("ns1.example.com.", "1.2.3.4")]}
        return c

    def test_cname_depth_exceeded(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        result = c._check_final_rrset("example.com.", dnskeys, depth=9)
        assert result is False
        assert any("CNAME chain too deep" in e for e in c.errors)

    def test_no_ns_found(self):
        c = _make_checker("example.com")
        c._zone_ns_map = {}
        dnskeys = make_dnskey_rrset("example.com.")
        result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False

    def test_no_response_from_any_ns(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        with patch(
            "chainvalidator.checker.udp_query", side_effect=RuntimeError("timeout")
        ):
            result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False

    def test_direct_answer_no_rrsig(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        a_rr = make_a_rrset()
        resp = make_response_with_answer([a_rr])
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False
        assert any("No RRSIG" in e for e in c.errors)

    def test_direct_answer_rrsig_invalid(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        a_rr = make_a_rrset()
        rrsig_r = make_rrsig_rrset()
        resp = make_response_with_answer([a_rr, rrsig_r])
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(False, None),
            ):
                result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False

    def test_direct_answer_rrsig_expired(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        a_rr = make_a_rrset()
        rrsig_r = make_rrsig_rrset(expiration_offset=-3600)  # 1 hour in past
        resp = make_response_with_answer([a_rr, rrsig_r])
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False
        assert any("EXPIRED" in e for e in c.errors)

    def test_direct_answer_success(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        a_rr = make_a_rrset()
        rrsig_r = make_rrsig_rrset(expiration_offset=86400)
        resp = make_response_with_answer([a_rr, rrsig_r])
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                result = c._check_final_rrset("example.com.", dnskeys)
        assert result is True
        assert c.report.leaf is not None
        assert c.report.leaf.rrsig_used == 42

    def test_cname_no_rrsig(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        cname_rr = make_cname_rrset("www.example.com.", "example.com.")
        resp = make_response_with_answer([cname_rr])
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False
        assert any("No RRSIG" in e for e in c.errors)

    def test_cname_rrsig_invalid(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        cname_rr = make_cname_rrset("www.example.com.", "target.example.com.")
        cname_rrsig = make_rrsig_rrset(
            "www.example.com.", type_covered=dns.rdatatype.CNAME
        )
        resp = make_response_with_answer([cname_rr, cname_rrsig])
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(False, None),
            ):
                result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False

    def test_nxdomain_response(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        resp = make_response("example.com.", dns.rdatatype.A, rcode=dns.rcode.NXDOMAIN)
        resp.authority.append(make_soa_rrset("example.com."))
        rrsig_soa = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.SOA)
        resp.authority.append(rrsig_soa)
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(True, 42),
            ):
                result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False
        assert any("NXDOMAIN" in w for w in c.warnings)

    def test_no_record_and_no_nsec_no_nxdomain(self):
        """Empty answer, no NSEC, NOERROR → bogus."""
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        resp = make_response("example.com.", dns.rdatatype.A)  # NOERROR, empty
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False

    def test_nsec_nodata_proof_no_rrsig(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        nsec_rr = make_nsec_rrset("example.com.")
        resp = make_response("example.com.", dns.rdatatype.A)
        resp.authority.append(nsec_rr)
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False

    def test_nsec_nodata_rrsig_invalid(self):
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        nsec_rr = make_nsec_rrset("example.com.")
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.NSEC)
        resp = make_response("example.com.", dns.rdatatype.A)
        resp.authority.append(nsec_rr)
        resp.authority.append(rrsig_r)
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(False, None),
            ):
                result = c._check_final_rrset("example.com.", dnskeys)
        assert result is False


# ---------------------------------------------------------------------------
# _resolve_ns_for_child
# ---------------------------------------------------------------------------


class TestResolveNsForChild:
    def test_udp_query_raises_returns_empty(self):
        c = _make_checker()
        with patch(
            "chainvalidator.checker.udp_query", side_effect=RuntimeError("no connect")
        ):
            result = c._resolve_ns_for_child("example.com.", "1.2.3.4")
        assert result == []

    def test_ns_from_answer_section(self):
        c = _make_checker()
        resp = make_response("example.com.", dns.rdatatype.NS)
        ns_rr = make_ns_rrset("example.com.", ["ns1.example.com."])
        resp.answer.append(ns_rr)
        a_rr = make_a_rrset("ns1.example.com.", addresses=["5.6.7.8"])
        resp.additional.append(a_rr)
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            result = c._resolve_ns_for_child("example.com.", "1.2.3.4")
        assert ("ns1.example.com.", "5.6.7.8") in result

    def test_ns_without_glue_uses_resolver(self):
        c = _make_checker()
        resp = make_response("example.com.", dns.rdatatype.NS)
        ns_rr = make_ns_rrset("example.com.", ["ns1.example.com."])
        resp.authority.append(ns_rr)
        mock_ans = MagicMock()
        mock_ans[0].address = "9.9.9.9"
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.dns.resolver.resolve", return_value=mock_ans
            ):
                result = c._resolve_ns_for_child("example.com.", "1.2.3.4")
        assert ("ns1.example.com.", "9.9.9.9") in result

    def test_resolver_failure_skips_ns(self):
        c = _make_checker()
        resp = make_response("example.com.", dns.rdatatype.NS)
        ns_rr = make_ns_rrset("example.com.", ["ns1.example.com."])
        resp.authority.append(ns_rr)
        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.dns.resolver.resolve",
                side_effect=Exception("no resolve"),
            ):
                result = c._resolve_ns_for_child("example.com.", "1.2.3.4")
        assert result == []


# ---------------------------------------------------------------------------
# _get_ns_ip_for_zone / _get_authoritative_ns
# ---------------------------------------------------------------------------


class TestNsHelpers:
    def test_get_ns_ip_from_map(self):
        c = _make_checker()
        c._zone_ns_map = {"example.com.": [("ns1.", "5.5.5.5")]}
        ip = c._get_ns_ip_for_zone("example.com.", {})
        assert ip == "5.5.5.5"

    def test_get_ns_ip_root_fallback(self):
        c = _make_checker()
        c._zone_ns_map = {}
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root", "1.1.1.1"),
        ):
            ip = c._get_ns_ip_for_zone(".", {})
        assert ip == "1.1.1.1"

    def test_get_ns_ip_unknown_zone_returns_none(self):
        c = _make_checker()
        c._zone_ns_map = {}
        ip = c._get_ns_ip_for_zone("unknown.zone.", {})
        assert ip is None

    def test_get_authoritative_ns_from_map(self):
        c = _make_checker()
        c._zone_ns_map = {"example.com.": [("ns1.", "1.2.3.4")]}
        ns = c._get_authoritative_ns("example.com.", MagicMock())
        assert ns == [("ns1.", "1.2.3.4")]

    def test_get_authoritative_ns_root_fallback(self):
        c = _make_checker()
        c._zone_ns_map = {}
        with patch(
            "chainvalidator.checker.pick_root_server",
            return_value=("a.root", "1.1.1.1"),
        ):
            ns = c._get_authoritative_ns(".", MagicMock())
        assert ns == [("a.root", "1.1.1.1")]

    def test_get_authoritative_ns_unknown_returns_empty(self):
        c = _make_checker()
        c._zone_ns_map = {}
        ns = c._get_authoritative_ns("unknown.", MagicMock())
        assert ns == []


# ---------------------------------------------------------------------------
# _finalise
# ---------------------------------------------------------------------------


class TestFinalise:
    def test_errors_set_bogus(self):
        c = _make_checker()
        c.errors.append("oops")
        c._finalise()
        assert c.report.status == Status.BOGUS

    def test_warnings_set_insecure(self):
        c = _make_checker()
        c.warnings.append("warn")
        c._finalise()
        assert c.report.status == Status.INSECURE

    def test_clean_set_secure(self):
        c = _make_checker()
        c._finalise()
        assert c.report.status == Status.SECURE


# ---------------------------------------------------------------------------
# check() — top-level integration
# ---------------------------------------------------------------------------


class TestCheckerCheck:
    def _minimal_secure_setup(self, c: DNSSECChecker):
        """Patch everything so check() succeeds end-to-end."""
        dnskey_rr = make_dnskey_rrset(".")

        def mock_build_zones(fqdn):
            c._zone_ns_map = {".": [("a.root", "1.1.1.1")]}
            return ["."]

        def mock_load_ta():
            return [MagicMock()]

        def mock_check_root(ta, validated):
            validated["."] = dnskey_rr
            c.report.chain.append(MagicMock())
            return True

        def mock_check_final(zone, keys, **kwargs):
            return True

        return (
            patch.object(c, "_build_zone_list", side_effect=mock_build_zones),
            patch.object(c, "_load_trust_anchor", side_effect=mock_load_ta),
            patch.object(c, "_check_root", side_effect=mock_check_root),
            patch.object(c, "_check_final_rrset", side_effect=mock_check_final),
        )

    def test_trust_anchor_failure_returns_false(self):
        c = _make_checker()

        def mock_build(fqdn):
            c._zone_ns_map = {".": [("a.root", "1.1.1.1")]}
            return ["."]

        with patch.object(c, "_build_zone_list", side_effect=mock_build):
            with patch.object(c, "_load_trust_anchor", return_value=[]):
                result = c.check()
        assert result is False
        assert c.report.status == Status.BOGUS

    def test_root_check_failure_returns_false(self):
        c = _make_checker()

        def mock_build(fqdn):
            c._zone_ns_map = {".": [("a.root", "1.1.1.1")]}
            return ["."]

        with patch.object(c, "_build_zone_list", side_effect=mock_build):
            with patch.object(c, "_load_trust_anchor", return_value=[MagicMock()]):
                with patch.object(c, "_check_root", return_value=False):
                    result = c.check()
        assert result is False

    def test_zone_check_failure_returns_false(self):
        c = _make_checker()
        dnskeys = make_dnskey_rrset(".")

        def mock_build(fqdn):
            c._zone_ns_map = {
                ".": [("a.root", "1.1.1.1")],
                "com.": [("ns.com.", "2.2.2.2")],
            }
            return [".", "com."]

        def mock_root(ta, validated):
            validated["."] = dnskeys
            return True

        with patch.object(c, "_build_zone_list", side_effect=mock_build):
            with patch.object(c, "_load_trust_anchor", return_value=[MagicMock()]):
                with patch.object(c, "_check_root", side_effect=mock_root):
                    with patch.object(c, "_check_zone", return_value=False):
                        result = c.check()
        assert result is False

    def test_all_secure_returns_true(self):
        c = _make_checker()
        patches = self._minimal_secure_setup(c)
        with patches[0], patches[1], patches[2], patches[3]:
            result = c.check()
        assert result is True
        assert c.report.status == Status.SECURE

    def test_with_warnings_returns_none(self):
        c = _make_checker()
        patches = self._minimal_secure_setup(c)
        with patches[0], patches[1], patches[2], patches[3]:
            c.warnings.append("insecure delegation")
            result = c.check()
        assert result is None

    def test_with_errors_returns_false(self):
        c = _make_checker()
        patches = self._minimal_secure_setup(c)
        with patches[0], patches[1], patches[2], patches[3]:
            c.errors.append("bogus chain")
            result = c.check()
        assert result is False


# ---------------------------------------------------------------------------
# NXDOMAIN with signed SOA validation failure
# ---------------------------------------------------------------------------


class TestNxdomainSoaValidation:
    def test_soa_rrsig_fails_returns_false(self):
        c = _make_checker("example.com")
        c._zone_ns_map = {"example.com.": [("ns1.example.com.", "1.2.3.4")]}
        dnskeys = make_dnskey_rrset("example.com.")

        soa_rr = make_soa_rrset("example.com.")
        rrsig_soa = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.SOA)
        resp = make_response("example.com.", dns.rdatatype.A, rcode=dns.rcode.NXDOMAIN)
        resp.authority.append(soa_rr)
        resp.authority.append(rrsig_soa)

        from chainvalidator.models import LeafResult

        leaf = LeafResult(qname="example.com", record_type="A")

        with patch("chainvalidator.checker.udp_query", return_value=resp):
            with patch(
                "chainvalidator.checker.validate_rrsig_over_rrset",
                return_value=(False, None),
            ):
                result = c._validate_nxdomain(
                    resp, "example.com.", dnskeys, "example.com.", leaf
                )
        assert result is False


# ---------------------------------------------------------------------------
# NSEC bitmap type_in_bitmap check
# ---------------------------------------------------------------------------


class TestNsecBitmapIncludes:
    def test_nsec_bitmap_includes_requested_type(self):
        """NSEC bitmap says A exists, but no answer → bogus."""
        c = _make_checker("example.com")
        c._zone_ns_map = {"example.com.": [("ns1.example.com.", "1.2.3.4")]}
        dnskeys = make_dnskey_rrset("example.com.")

        # Build NSEC with A (type 1) in the bitmap
        nsec_rr = dns.rrset.RRset(
            dns.name.from_text("example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC
        )
        nsec_rr.update_ttl(300)
        nsec_rr.add(
            dns.rdata.from_text(
                dns.rdataclass.IN, dns.rdatatype.NSEC, "z.example.com. A SOA"
            )
        )
        rrsig_r = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.NSEC)

        from chainvalidator.models import LeafResult

        leaf = LeafResult(qname="example.com", record_type="A")

        # Build NOERROR response with NSEC in authority
        resp = make_response("example.com.", dns.rdatatype.A)
        resp.authority.append(nsec_rr)
        resp.authority.append(rrsig_r)

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            result = c._validate_nodata_nsec(
                nsec_rr,
                rrsig_r,
                dnskeys,
                "example.com.",
                "example.com.",
                "A",
                resp,
                leaf,
            )
        assert result is False
        assert any("NSEC bitmap includes" in e for e in c.errors)


# ===========================================================================
# Additional tests to reach 100% coverage
# ===========================================================================

# ---------------------------------------------------------------------------
# __init__: DNSException from dns.name.from_text (lines 114-115)
# ---------------------------------------------------------------------------


class TestCheckerInitDnsException:
    def test_dns_exception_in_from_text_raises_value_error(self):
        """dns.name.from_text can raise DNSException on malformed labels."""
        # A name with an empty label (double dot) triggers DNSException
        with pytest.raises(ValueError, match="Invalid domain name"):
            DNSSECChecker("example..com")

    def test_too_long_label_raises_value_error(self):
        """A label > 63 chars triggers DNSException → ValueError."""
        bad = "a" * 64 + ".com"
        with pytest.raises(ValueError):
            DNSSECChecker(bad)


# ---------------------------------------------------------------------------
# _follow_cname: already-validated zone skipped (line 965)
# and full CNAME success path (lines 976-996)
# ---------------------------------------------------------------------------


class TestFollowCnameComplete:
    def _checker_with_ns_map(self):
        c = _make_checker("www.example.com")
        c._zone_ns_map = {
            ".": [("a.root", "198.41.0.4")],
            "com.": [("ns1.com.", "2.2.2.2")],
            "example.com.": [("ns1.example.com.", "3.3.3.3")],
        }
        return c

    def test_cname_skips_already_validated_zone(self):
        """When the target zone is already in shared_keys, _check_zone is skipped."""
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")

        # Pre-populate shared_keys so the zone walk finds example.com. already done
        shared_keys = {
            ".": make_dnskey_rrset("."),
            "com.": make_dnskey_rrset("com."),
            "example.com.": dnskeys,
        }

        cname_rr = make_cname_rrset("www.example.com.", "example.com.")
        cname_rrsig = make_rrsig_rrset(
            "www.example.com.", type_covered=dns.rdatatype.CNAME
        )

        from chainvalidator.models import LeafResult

        leaf = LeafResult(qname="www.example.com", record_type="A")

        check_zone_calls = []

        def mock_build_zones(fqdn):
            # Set NS map for the target
            return [".", "com.", "example.com."]

        def mock_final_rrset(
            zone, zone_dnskeys, qname=None, depth=0, validated_keys=None
        ):
            return True

        with patch.object(c, "_build_zone_list", side_effect=mock_build_zones):
            with patch.object(c, "_check_zone", side_effect=check_zone_calls.append):
                with patch(
                    "chainvalidator.checker.validate_rrsig_over_rrset",
                    return_value=(True, 42),
                ):
                    with patch.object(
                        c, "_check_final_rrset", side_effect=mock_final_rrset
                    ):
                        result = c._follow_cname(
                            cname_rr,
                            cname_rrsig,
                            dnskeys,
                            "example.com.",
                            "www.example.com.",
                            0,
                            shared_keys,
                            leaf,
                        )

        assert result is True
        # _check_zone should NOT have been called (all zones already validated)
        assert len(check_zone_calls) == 0

    def test_cname_zone_check_fails(self):
        """If _check_zone fails during CNAME follow, _follow_cname returns False."""
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        shared_keys = {".": make_dnskey_rrset(".")}

        cname_rr = make_cname_rrset("www.example.com.", "target.other.com.")
        cname_rrsig = make_rrsig_rrset(
            "www.example.com.", type_covered=dns.rdatatype.CNAME
        )

        from chainvalidator.models import LeafResult

        leaf = LeafResult(qname="www.example.com", record_type="A")

        def mock_build_zones(fqdn):
            return [".", "other.com.", "target.other.com."]

        with patch.object(c, "_build_zone_list", side_effect=mock_build_zones):
            with patch.object(c, "_check_zone", return_value=False):
                with patch(
                    "chainvalidator.checker.validate_rrsig_over_rrset",
                    return_value=(True, 42),
                ):
                    result = c._follow_cname(
                        cname_rr,
                        cname_rrsig,
                        dnskeys,
                        "example.com.",
                        "www.example.com.",
                        0,
                        shared_keys,
                        leaf,
                    )
        assert result is False

    def test_cname_valid_rrsig_and_full_walk(self):
        """Full CNAME success: valid RRSIG, zone walk completes, leaf validated."""
        c = self._checker_with_ns_map()
        dnskeys = make_dnskey_rrset("example.com.")
        target_dnskeys = make_dnskey_rrset("target.example.com.")

        cname_rr = make_cname_rrset("www.example.com.", "target.example.com.")
        cname_rrsig = make_rrsig_rrset(
            "www.example.com.", type_covered=dns.rdatatype.CNAME
        )

        from chainvalidator.models import LeafResult

        leaf = LeafResult(qname="www.example.com", record_type="A")

        shared_keys = {}

        def mock_build_zones(fqdn):
            shared_keys["."] = make_dnskey_rrset(".")
            shared_keys["example.com."] = dnskeys
            shared_keys["target.example.com."] = target_dnskeys
            return [".", "example.com.", "target.example.com."]

        def mock_check_zone(
            parent_zone, child_zone, parent_validated_keys, validated_keys
        ):
            return True

        def mock_final(zone, zone_dnskeys, qname=None, depth=0, validated_keys=None):
            return True

        with patch.object(c, "_build_zone_list", side_effect=mock_build_zones):
            with patch.object(c, "_check_zone", side_effect=mock_check_zone):
                with patch(
                    "chainvalidator.checker.validate_rrsig_over_rrset",
                    return_value=(True, 99),
                ):
                    with patch.object(c, "_check_final_rrset", side_effect=mock_final):
                        result = c._follow_cname(
                            cname_rr,
                            cname_rrsig,
                            dnskeys,
                            "example.com.",
                            "www.example.com.",
                            0,
                            shared_keys,
                            leaf,
                        )
        assert result is True


# ---------------------------------------------------------------------------
# _validate_nodata_nsec: SOA RRSIG validates successfully (lines 1118-1147)
# ---------------------------------------------------------------------------


class TestNodataNsecSoaBranch:
    def test_nodata_nsec_with_valid_soa(self):
        """NSEC proof + signed SOA → returns True."""
        c = _make_checker("example.com")
        c._zone_ns_map = {"example.com.": [("ns1.", "1.2.3.4")]}
        dnskeys = make_dnskey_rrset("example.com.")

        # NSEC proving no A record (bitmap has only SOA)
        nsec_rr = make_nsec_rrset("example.com.")
        rrsig_nsec = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.NSEC)
        soa_rr = make_soa_rrset("example.com.")
        rrsig_soa = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.SOA)

        resp = make_response("example.com.", dns.rdatatype.A)
        resp.authority.append(nsec_rr)
        resp.authority.append(rrsig_nsec)
        resp.authority.append(soa_rr)
        resp.authority.append(rrsig_soa)

        from chainvalidator.models import LeafResult

        leaf = LeafResult(qname="example.com", record_type="A")

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            result = c._validate_nodata_nsec(
                nsec_rr,
                rrsig_nsec,
                dnskeys,
                "example.com.",
                "example.com.",
                "A",
                resp,
                leaf,
            )
        assert result is True
        assert any("NSEC proves" in n for n in leaf.notes)

    def test_nodata_nsec_soa_rrsig_fails(self):
        """NSEC proof passes but SOA RRSIG invalid → returns False."""
        c = _make_checker("example.com")
        c._zone_ns_map = {"example.com.": [("ns1.", "1.2.3.4")]}
        dnskeys = make_dnskey_rrset("example.com.")

        nsec_rr = make_nsec_rrset("example.com.")
        rrsig_nsec = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.NSEC)
        soa_rr = make_soa_rrset("example.com.")
        rrsig_soa = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.SOA)

        resp = make_response("example.com.", dns.rdatatype.A)
        resp.authority.append(nsec_rr)
        resp.authority.append(rrsig_nsec)
        resp.authority.append(soa_rr)
        resp.authority.append(rrsig_soa)

        from chainvalidator.models import LeafResult

        leaf = LeafResult(qname="example.com", record_type="A")

        # First call (NSEC) → success; second call (SOA) → failure
        side_effects = [(True, 42), (False, None)]
        idx = [0]

        def validate_side(*args, **kwargs):
            r = side_effects[idx[0]]
            idx[0] = min(idx[0] + 1, len(side_effects) - 1)
            return r

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset",
            side_effect=validate_side,
        ):
            result = c._validate_nodata_nsec(
                nsec_rr,
                rrsig_nsec,
                dnskeys,
                "example.com.",
                "example.com.",
                "A",
                resp,
                leaf,
            )
        assert result is False


# ---------------------------------------------------------------------------
# _validate_nxdomain: NSEC3 failing path (lines 1196-1201)
# ---------------------------------------------------------------------------


class TestNxdomainNsec3FailPath:
    def test_nxdomain_nsec3_validation_fails(self):
        """NSEC3 in authority but validation fails → returns False + BOGUS."""
        c = _make_checker("example.com")
        c._zone_ns_map = {"example.com.": [("ns1.", "1.2.3.4")]}
        dnskeys = make_dnskey_rrset("example.com.")

        soa_rr = make_soa_rrset("example.com.")
        rrsig_soa = make_rrsig_rrset("example.com.", type_covered=dns.rdatatype.SOA)

        resp = make_response("example.com.", dns.rdatatype.A, rcode=dns.rcode.NXDOMAIN)
        resp.authority.append(soa_rr)
        resp.authority.append(rrsig_soa)

        # Use a mock NSEC3 RRset (avoids wire format issues)
        nsec3_rr = MagicMock()
        nsec3_rr.rdtype = dns.rdatatype.NSEC3
        resp.authority.append(nsec3_rr)

        from chainvalidator.models import LeafResult

        leaf = LeafResult(qname="nonexistent.example.com", record_type="A")

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            with patch.object(c, "_validate_nsec3_nxdomain", return_value=False):
                result = c._validate_nxdomain(
                    resp, "example.com.", dnskeys, "nonexistent.example.com.", leaf
                )
        assert result is False
        assert leaf.status == Status.BOGUS


# ---------------------------------------------------------------------------
# _validate_nsec3_nxdomain: all branches (lines 1231-1349)
# ---------------------------------------------------------------------------


class TestValidateNsec3Nxdomain:
    """Exercise every branch of _validate_nsec3_nxdomain using real NSEC3 hashes."""

    _zone = "example.com."
    _qname = "nonexistent.example.com."

    def _make_nsec3_rr(
        self, owner_hash_b32hex: str, next_raw: bytes, zone: str = "example.com."
    ) -> dns.rrset.RRset:
        """Build an NSEC3 RRset with the given owner hash and next pointer."""
        import struct

        owner_name = dns.name.from_text(f"{owner_hash_b32hex}.{zone}")
        rr = dns.rrset.RRset(owner_name, dns.rdataclass.IN, dns.rdatatype.NSEC3)
        rr.update_ttl(300)

        nsec3_wire = struct.pack(
            "!BBHB", 1, 0, 0, 0
        )  # alg=1, flags=0, iter=0, saltlen=0
        nsec3_wire += struct.pack("!B", 20) + next_raw  # hashlen=20, next_hash
        nsec3_wire += struct.pack("!BB", 0, 1) + bytes([0x02])  # window 0: SOA present
        rdata = dns.rdata.from_wire(
            dns.rdataclass.IN, dns.rdatatype.NSEC3, nsec3_wire, 0, len(nsec3_wire)
        )
        rr.add(rdata)
        return rr

    def _make_nsec3_rrsig(
        self, owner_hash_b32hex: str, zone: str = "example.com."
    ) -> dns.rrset.RRset:
        owner_name = f"{owner_hash_b32hex}.{zone}"
        return make_rrsig_rrset(owner_name, type_covered=dns.rdatatype.NSEC3)

    def _compute_hashes(self):
        """Return pre-computed hashes for our test names."""
        import hashlib

        _B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        _B32_HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
        to_hex = str.maketrans(_B32_STD, _B32_HEX)

        def h(name):
            wire = dns.name.from_text(name).canonicalize().to_wire()
            digest = hashlib.sha1(wire).digest()
            return base64.b32encode(digest).decode().upper().rstrip("=").translate(
                to_hex
            ), digest

        return {
            "ce": h("example.com."),  # closest encloser
            "nc": h("nonexistent.example.com."),  # next closer
            "wc": h("*.example.com."),  # wildcard
        }

    def _checker(self):
        c = _make_checker("nonexistent.example.com")
        c._zone_ns_map = {"example.com.": [("ns1.", "1.2.3.4")]}
        return c

    def test_empty_nsec3_map_returns_true(self):
        """No NSEC3 records in authority → returns True immediately."""
        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")
        result = c._validate_nsec3_nxdomain(
            "nonexistent.example.com.", "example.com.", [], dnskeys
        )
        assert result is True

    def test_nsec3_no_rrsig_fails(self):
        """NSEC3 present but no matching RRSIG → _fail."""
        hashes = self._compute_hashes()
        ce_b32hex, ce_raw = hashes["ce"]
        nc_b32hex, nc_raw = hashes["nc"]

        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")

        # CE NSEC3 exists, no RRSIG for it
        ce_rr = self._make_nsec3_rr(ce_b32hex, nc_raw)
        authority = [ce_rr]  # no RRSIG

        result = c._validate_nsec3_nxdomain(
            "nonexistent.example.com.", "example.com.", authority, dnskeys
        )
        assert result is False
        assert any("No RRSIG" in e for e in c.errors)

    def test_nsec3_rrsig_invalid_fails(self):
        """NSEC3 + RRSIG present but RRSIG validation fails."""
        hashes = self._compute_hashes()
        ce_b32hex, ce_raw = hashes["ce"]
        nc_b32hex, nc_raw = hashes["nc"]

        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")

        ce_rr = self._make_nsec3_rr(ce_b32hex, nc_raw)
        ce_rrsig = self._make_nsec3_rrsig(ce_b32hex)
        authority = [ce_rr, ce_rrsig]

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset",
            return_value=(False, None),
        ):
            result = c._validate_nsec3_nxdomain(
                "nonexistent.example.com.", "example.com.", authority, dnskeys
            )
        assert result is False

    def test_no_next_closer_coverage_fails(self):
        """CE found but no NSEC3 covers the next-closer → _fail."""
        hashes = self._compute_hashes()
        ce_b32hex, ce_raw = hashes["ce"]
        nc_b32hex, nc_raw = hashes["nc"]

        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")

        # CE NSEC3: next points to itself (covers nothing useful for nc)
        ce_rr = self._make_nsec3_rr(ce_b32hex, ce_raw)  # next = same as owner
        ce_rrsig = self._make_nsec3_rrsig(ce_b32hex)
        authority = [ce_rr, ce_rrsig]

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            with patch("chainvalidator.checker.nsec3_covers", return_value=False):
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        # No covering record for next-closer → False
        assert result is False

    def test_wildcard_exists_fails(self):
        """If wildcard hash is found in nsec3_map → wildcard exists → bogus."""
        hashes = self._compute_hashes()
        ce_b32hex, ce_raw = hashes["ce"]
        nc_b32hex, nc_raw = hashes["nc"]
        wc_b32hex, wc_raw = hashes["wc"]

        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")

        # CE NSEC3 (covers nc, so nc proof passes)
        # NC NSEC3 covers nc_hash
        # WC NSEC3 at wildcard hash position (proves wildcard EXISTS)
        ce_rr = self._make_nsec3_rr(ce_b32hex, wc_raw)
        ce_rrsig = self._make_nsec3_rrsig(ce_b32hex)
        # A record covering the next-closer hash
        # We need nc_b32hex to be covered by some interval.
        # Use the CE record's interval by making its next point past nc_hash.
        # Simpler: patch nsec3_covers to return True for nc check.
        wc_rr = self._make_nsec3_rr(wc_b32hex, nc_raw)  # WC exists in map
        wc_rrsig = self._make_nsec3_rrsig(wc_b32hex)
        authority = [ce_rr, ce_rrsig, wc_rr, wc_rrsig]

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            with patch("chainvalidator.checker.nsec3_covers", return_value=True):
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        assert result is False
        assert any("Wildcard" in e and "exists" in e for e in c.errors)

    def test_wildcard_covered_validates_it(self):
        """Wildcard covered by NSEC3 → proof validated → returns True."""
        hashes = self._compute_hashes()
        ce_b32hex, ce_raw = hashes["ce"]
        nc_b32hex, nc_raw = hashes["nc"]
        wc_b32hex, wc_raw = hashes["wc"]

        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")

        # CE: exists (hash match in map)
        # NC covering: covered by CE interval
        # WC: covered by NC interval (wildcard NOT in map, but covered)
        ce_rr = self._make_nsec3_rr(ce_b32hex, nc_raw)
        ce_rrsig = self._make_nsec3_rrsig(ce_b32hex)
        nc_rr = self._make_nsec3_rr(nc_b32hex, wc_raw)
        nc_rrsig = self._make_nsec3_rrsig(nc_b32hex)
        authority = [ce_rr, ce_rrsig, nc_rr, nc_rrsig]

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            with patch("chainvalidator.checker.nsec3_covers") as mock_covers:
                # nc_hash covered by ce interval → True
                # wc_hash covered by nc interval → True
                mock_covers.return_value = True
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        # Should return True (complete valid proof)
        assert result is True

    def test_no_closest_encloser_fallback_to_zone(self):
        """No CE hash match → falls back to zone apex as CE."""
        hashes = self._compute_hashes()
        nc_b32hex, nc_raw = hashes["nc"]

        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")

        # Only provide an NC covering record, no CE hash in map
        nc_rr = self._make_nsec3_rr(nc_b32hex, b"\x00" * 20)
        nc_rrsig = self._make_nsec3_rrsig(nc_b32hex)
        authority = [nc_rr, nc_rrsig]

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            with patch("chainvalidator.checker.nsec3_covers", return_value=True):
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        # No CE hash match → zone apex used as CE → ce_depth == 2 (example.com.)
        # q_labels has 3 parts → next_closer checked
        assert result is True

    def test_next_closer_rrsig_invalid(self):
        """NC RRSIG validation fails → returns False."""
        hashes = self._compute_hashes()
        ce_b32hex, ce_raw = hashes["ce"]
        nc_b32hex, nc_raw = hashes["nc"]

        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")

        ce_rr = self._make_nsec3_rr(ce_b32hex, nc_raw)
        ce_rrsig = self._make_nsec3_rrsig(ce_b32hex)
        nc_rr = self._make_nsec3_rr(nc_b32hex, b"\xff" * 20)
        nc_rrsig = self._make_nsec3_rrsig(nc_b32hex)
        authority = [ce_rr, ce_rrsig, nc_rr, nc_rrsig]

        # CE validates, NC validates with (False) on second call
        call_idx = [0]
        results = [(True, 42), (False, None)]

        def side_effect(*args, **kwargs):
            r = results[min(call_idx[0], len(results) - 1)]
            call_idx[0] += 1
            return r

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", side_effect=side_effect
        ):
            with patch("chainvalidator.checker.nsec3_covers", return_value=True):
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        assert result is False

    def test_wildcard_rrsig_invalid(self):
        """Wildcard coverage RRSIG validation fails → returns False.

        Setup: only ce_rr is in nsec3_map (nc_rr is absent so nc_hash is NOT
        found directly; find_covering returns ce_b32hex for both the next-closer
        and wildcard intervals).  The 3rd validate_rrsig call (wildcard) returns
        (False, None) which triggers _fail and returns False.
        """
        hashes = self._compute_hashes()
        ce_b32hex, ce_raw = hashes["ce"]
        nc_b32hex, nc_raw = hashes["nc"]

        c = self._checker()
        dnskeys = make_dnskey_rrset("example.com.")

        # Only CE in the authority; nc_hash is absent from nsec3_map so
        # find_covering is used for both next-closer and wildcard.
        ce_rr = self._make_nsec3_rr(ce_b32hex, nc_raw)
        ce_rrsig = self._make_nsec3_rrsig(ce_b32hex)
        authority = [ce_rr, ce_rrsig]

        # call_0 = CE RRSIG OK, call_1 = next-closer RRSIG OK,
        # call_2 = wildcard RRSIG FAIL → _fail → return False.
        call_idx = [0]
        results = [(True, 42), (True, 42), (False, None)]

        def side_effect(*args, **kwargs):
            r = results[min(call_idx[0], len(results) - 1)]
            call_idx[0] += 1
            return r

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", side_effect=side_effect
        ):
            with patch("chainvalidator.checker.nsec3_covers", return_value=True):
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        assert result is False

    def test_no_nsec3_covering_next_closer(self):
        """find_covering returns None for next-closer → _fail → False (L1311-1312).

        Setup: CE is found (example.com.), but nsec3_covers always False so
        find_covering(nc_hash) iterates the map and never matches → returns None.
        This triggers the ``else`` branch: _fail + return False.
        """
        hashes = self._compute_hashes()
        ce_b32, ce_raw = hashes["ce"]
        nc_b32, nc_raw = hashes["nc"]

        c = self._checker()  # qname = nonexistent.example.com
        dnskeys = make_dnskey_rrset("example.com.")

        # Only ce_rr in authority → ce_b32 is in nsec3_map.
        # NC hash is NOT in nsec3_map.
        ce_rr = self._make_nsec3_rr(ce_b32, nc_raw)
        ce_rrsig = self._make_nsec3_rrsig(ce_b32)
        authority = [ce_rr, ce_rrsig]

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            # nsec3_covers=False → find_covering iterates map, never matches → None
            with patch("chainvalidator.checker.nsec3_covers", return_value=False):
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        assert result is False
        assert any("No NSEC3 record covers next closer" in e for e in c.errors)

    def test_find_covering_returns_none_for_wildcard_opt_out(self):
        """find_covering returns None for wildcard → opt-out logged at DEBUG → True (L1330).

        Setup: qname has the SAME depth as the closest encloser so the
        next-closer block is skipped entirely.  Then for the wildcard,
        nsec3_covers is always False so find_covering returns None and
        the function returns True (RFC 5155 opt-out is assumed).
        """
        import base64
        import hashlib

        _B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        _B32_HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
        to_hex = str.maketrans(_B32_STD, _B32_HEX)

        def compute(name: str):
            wire = dns.name.from_text(name).canonicalize().to_wire()
            d = hashlib.sha1(wire).digest()
            return base64.b32encode(d).decode().upper().rstrip("=").translate(to_hex), d

        # We validate "child.example.com." against zone "example.com."
        # CE candidates (from qname "child.example.com"):
        #   i=0: "child.example.com." → hash not in map (skip)
        #   i=1: "example.com."       → ce_b32 IN map → CE found, ce_depth=2
        # q_labels = ["child","example","com"] → q_depth=3 > ce_depth=2
        # next_closer = "child.example.com." → nc_hash
        # nc_hash NOT in map; nsec3_covers=True → find_covering returns ce_b32 → NC OK (call_1)
        # wc = "*.example.com." → wc_hash not in map
        # nsec3_covers=False → find_covering(wc_hash) → None → opt-out log → True

        ce_b32, ce_raw = compute("example.com.")
        nc_b32, nc_raw = compute("child.example.com.")

        c = DNSSECChecker("child.example.com", record_type="A")
        c._zone_ns_map = {"example.com.": [("ns1.", "1.2.3.4")]}
        dnskeys = make_dnskey_rrset("example.com.")

        # Only ce_rr in authority (nc not in map).
        ce_rr = self._make_nsec3_rr(ce_b32, nc_raw)
        ce_rrsig = self._make_nsec3_rrsig(ce_b32)
        authority = [ce_rr, ce_rrsig]

        call_n = [0]

        def validate_side(*args, **kwargs):
            call_n[0] += 1
            return (True, 42)

        # nsec3_covers True for first call (CE validate check),
        # True for NC find_covering, False for WC find_covering.
        cover_calls = [0]

        def covers_side(owner, nxt, tgt):
            # find_covering is called for nc and wc.
            # For nc: return True (covers) → find_covering returns ce_b32.
            # For wc: return False → find_covering returns None.
            cover_calls[0] += 1
            # CE RRSIG call goes through validate_rrsig_over_rrset, not nsec3_covers.
            # nsec3_covers is only called inside find_covering.
            # First find_covering call is for nc_hash → return True.
            # Second find_covering call is for wc_hash → return False.
            if cover_calls[0] <= 1:
                return True  # nc: covered
            return False  # wc: not covered → opt-out

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset",
            side_effect=validate_side,
        ):
            with patch("chainvalidator.checker.nsec3_covers", side_effect=covers_side):
                result = c._validate_nsec3_nxdomain(
                    "child.example.com.", "example.com.", authority, dnskeys
                )
        assert result is True  # opt-out: wc not covered, no error
        assert c.errors == []

    def test_closest_encloser_fallback_to_zone_apex(self):
        """L1311-1312: no label of qname hashes to any nsec3_map entry → fallback to zone.

        When the CE loop completes without finding a match, closest_encloser is
        set to the zone apex and execution continues.  The wildcard step then
        exercises find_covering and validate_nsec3_rrset using the fallback CE.
        """
        import base64
        import hashlib

        _B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        _B32_HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
        to_hex = str.maketrans(_B32_STD, _B32_HEX)

        def compute(name: str):
            wire = dns.name.from_text(name).canonicalize().to_wire()
            d = hashlib.sha1(wire).digest()
            return base64.b32encode(d).decode().upper().rstrip("=").translate(to_hex), d

        # nsec3_map holds a hash for "unrelated.zone." — none of the qname labels
        # ("nonexistent", "example", "com") will match.
        unrel_b32, unrel_raw = compute("unrelated.zone.")

        c = self._checker()  # qname = nonexistent.example.com
        dnskeys = make_dnskey_rrset("example.com.")

        unrel_rr = self._make_nsec3_rr(unrel_b32, unrel_raw)
        unrel_rrsig = self._make_nsec3_rrsig(unrel_b32)
        authority = [unrel_rr, unrel_rrsig]

        # nsec3_covers=True → find_covering always returns unrel_b32 for both NC and WC.
        # validate_rrsig_over_rrset returns True for all → overall True.
        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset", return_value=(True, 42)
        ):
            with patch("chainvalidator.checker.nsec3_covers", return_value=True):
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        # No errors — the fallback CE path ran and everything validated OK.
        assert result is True
        assert c.errors == []

    def test_nc_covering_found_but_rrsig_invalid(self):
        """L1330: find_covering finds NC covering but RRSIG validation fails → False.

        CE is found and validates OK (call 0).  The next-closer is NOT directly
        in nsec3_map, but find_covering returns the CE record as its covering
        interval (nsec3_covers=True).  validate_nsec3_rrset then tries to
        validate the RRSIG for that covering record and gets (False, None),
        causing L1330 `return False` to execute.
        """
        hashes = self._compute_hashes()
        ce_b32, ce_raw = hashes["ce"]
        nc_b32, nc_raw = hashes["nc"]

        c = self._checker()  # qname = nonexistent.example.com
        dnskeys = make_dnskey_rrset("example.com.")

        # Only ce_rr in nsec3_map; nc_b32 is absent.
        ce_rr = self._make_nsec3_rr(ce_b32, nc_raw)
        ce_rrsig = self._make_nsec3_rrsig(ce_b32)
        authority = [ce_rr, ce_rrsig]

        call_idx = [0]
        results = [(True, 42), (False, None)]  # CE OK; NC covering RRSIG invalid

        def validate_side(*args, **kwargs):
            r = results[min(call_idx[0], len(results) - 1)]
            call_idx[0] += 1
            return r

        with patch(
            "chainvalidator.checker.validate_rrsig_over_rrset",
            side_effect=validate_side,
        ):
            # nsec3_covers=True → find_covering(nc_hash) returns ce_b32 (the only key).
            with patch("chainvalidator.checker.nsec3_covers", return_value=True):
                result = c._validate_nsec3_nxdomain(
                    "nonexistent.example.com.", "example.com.", authority, dnskeys
                )
        assert result is False
        assert any("could not be validated" in e for e in c.errors)
