"""Tests for chainvalidator.dns_utils."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import dns.flags
import dns.message
import dns.rdatatype
import pytest

from chainvalidator.constants import DNS_PORT, DNS_TIMEOUT
from chainvalidator.dns_utils import (
    extract_rrsets,
    get_dnskey,
    get_ds_from_parent,
    udp_query,
)
from tests.conftest import (
    make_a_rrset,
    make_dnskey_rrset,
    make_ds_rrset,
    make_response,
    make_response_with_answer,
    make_rrsig_rrset,
)

# ---------------------------------------------------------------------------
# udp_query
# ---------------------------------------------------------------------------


class TestUdpQuery:
    def _make_ok_response(self, tc: bool = False) -> dns.message.Message:
        resp = make_response("example.com.", dns.rdatatype.A)
        if tc:
            resp.flags |= dns.flags.TC
        return resp

    def test_success_returns_message(self):
        resp = self._make_ok_response()
        with patch("dns.query.udp", return_value=resp):
            result = udp_query("example.com.", dns.rdatatype.A, "1.2.3.4")
        assert result is resp

    def test_udp_failure_raises_runtime_error(self):
        with patch("dns.query.udp", side_effect=OSError("timeout")):
            with pytest.raises(RuntimeError, match="UDP query"):
                udp_query("example.com.", dns.rdatatype.A, "1.2.3.4")

    def test_truncated_falls_back_to_tcp(self):
        tc_resp = self._make_ok_response(tc=True)
        tcp_resp = self._make_ok_response()
        with patch("dns.query.udp", return_value=tc_resp):
            with patch("dns.query.tcp", return_value=tcp_resp) as mock_tcp:
                result = udp_query("example.com.", dns.rdatatype.A, "1.2.3.4")
        mock_tcp.assert_called_once()
        assert result is tcp_resp

    def test_tcp_fallback_failure_raises_runtime_error(self):
        tc_resp = self._make_ok_response(tc=True)
        with patch("dns.query.udp", return_value=tc_resp):
            with patch("dns.query.tcp", side_effect=OSError("tcp fail")):
                with pytest.raises(RuntimeError, match="TCP fallback"):
                    udp_query("example.com.", dns.rdatatype.A, "1.2.3.4")

    def test_custom_port_and_timeout_passed_through(self):
        resp = self._make_ok_response()
        with patch("dns.query.udp", return_value=resp) as mock_udp:
            udp_query(
                "example.com.", dns.rdatatype.A, "1.2.3.4", port=5353, timeout=2.0
            )
        _, kwargs = mock_udp.call_args
        assert kwargs.get("port") == 5353
        assert kwargs.get("timeout") == 2.0


# ---------------------------------------------------------------------------
# extract_rrsets
# ---------------------------------------------------------------------------


class TestExtractRrsets:
    def test_finds_rrset_and_rrsig_in_answer(self):
        a_rr = make_a_rrset()
        rrsig = make_rrsig_rrset(type_covered=dns.rdatatype.A)
        resp = make_response_with_answer([a_rr, rrsig])
        rrset, rrsig_out = extract_rrsets(resp, dns.rdatatype.A)
        assert rrset is a_rr
        assert rrsig_out is not None

    def test_returns_none_none_when_empty(self):
        resp = make_response()
        rrset, rrsig_out = extract_rrsets(resp, dns.rdatatype.A)
        assert rrset is None
        assert rrsig_out is None

    def test_finds_rrset_in_authority(self):
        ds_rr = make_ds_rrset()
        resp = make_response()
        resp.authority.append(ds_rr)
        rrset, _ = extract_rrsets(resp, dns.rdatatype.DS)
        assert rrset is ds_rr

    def test_finds_rrset_in_additional(self):
        a_rr = make_a_rrset()
        resp = make_response()
        resp.additional.append(a_rr)
        rrset, _ = extract_rrsets(resp, dns.rdatatype.A)
        assert rrset is a_rr

    def test_rrsig_must_cover_requested_type(self):
        """An RRSIG covering a different type should not be returned."""
        rrsig_dnskey = make_rrsig_rrset(type_covered=dns.rdatatype.DNSKEY)
        resp = make_response_with_answer([rrsig_dnskey])
        _, rrsig_out = extract_rrsets(resp, dns.rdatatype.A)
        assert rrsig_out is None


# ---------------------------------------------------------------------------
# get_ds_from_parent / get_dnskey
# ---------------------------------------------------------------------------


class TestGetDsFromParent:
    def test_delegates_to_udp_query_and_extract(self):
        ds_rr = make_ds_rrset()
        resp = make_response()
        resp.authority.append(ds_rr)
        with patch("chainvalidator.dns_utils.udp_query", return_value=resp) as mock_q:
            rrset, rrsig = get_ds_from_parent("example.com.", "1.2.3.4", timeout=3.0)
        mock_q.assert_called_once_with(
            "example.com.", dns.rdatatype.DS, "1.2.3.4", timeout=3.0
        )
        assert rrset is ds_rr

    def test_propagates_runtime_error(self):
        with patch(
            "chainvalidator.dns_utils.udp_query",
            side_effect=RuntimeError("network error"),
        ):
            with pytest.raises(RuntimeError, match="network error"):
                get_ds_from_parent("example.com.", "1.2.3.4")


class TestGetDnskey:
    def test_delegates_to_udp_query_and_extract(self):
        dk_rr = make_dnskey_rrset()
        resp = make_response_with_answer([dk_rr])
        with patch("chainvalidator.dns_utils.udp_query", return_value=resp) as mock_q:
            rrset, rrsig = get_dnskey("example.com.", "1.2.3.4", timeout=2.5)
        mock_q.assert_called_once_with(
            "example.com.", dns.rdatatype.DNSKEY, "1.2.3.4", timeout=2.5
        )
        assert rrset is dk_rr
