"""Tests for chainvalidator.dnssec_utils."""

from __future__ import annotations

import hashlib
import base64
from unittest.mock import MagicMock, patch

import dns.dnssec
import dns.name
import dns.rdatatype
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

from tests.conftest import (
    make_dnskey_rdata,
    make_dnskey_rrset,
    make_ds_rrset,
    make_a_rrset,
    make_rrsig_rrset,
)


# ---------------------------------------------------------------------------
# ds_matches_dnskey
# ---------------------------------------------------------------------------


class TestDsMatchesDnskey:
    def test_returns_false_on_exception(self):
        """Any exception during make_ds → False."""
        bad_ds = MagicMock()
        bad_ds.digest_type = 999
        dnskey = make_dnskey_rdata()
        # dns.dnssec.make_ds will fail with an unknown digest type
        result = ds_matches_dnskey(bad_ds, dnskey, "example.com.")
        assert result is False

    def test_mismatched_digests(self):
        """Real DS with wrong digest bytes → False."""
        ds_rrset = make_ds_rrset("example.com.", digest_type=2)
        ds = list(ds_rrset)[0]
        dnskey = make_dnskey_rdata(flags=257, algorithm=13)
        # The dummy DS digest won't match the computed one
        result = ds_matches_dnskey(ds, dnskey, "example.com.")
        assert result is False

    def test_matching_ds_and_dnskey(self):
        """Compute DS from real DNSKEY; they must match."""
        dnskey = make_dnskey_rdata(flags=257, algorithm=13)
        computed_ds = dns.dnssec.make_ds("example.com.", dnskey, 2)
        result = ds_matches_dnskey(computed_ds, dnskey, "example.com.")
        assert result is True


# ---------------------------------------------------------------------------
# validate_rrsig_over_rrset
# ---------------------------------------------------------------------------


class TestValidateRrsigOverRrset:
    def test_returns_false_none_when_all_keys_fail(self):
        rrset = make_a_rrset()
        rrsig = make_rrsig_rrset()
        dnskeys = make_dnskey_rrset()

        with patch("dns.dnssec.validate", side_effect=Exception("bad sig")):
            ok, tag = validate_rrsig_over_rrset(rrset, rrsig, dnskeys, "example.com.")
        assert ok is False
        assert tag is None

    def test_returns_true_and_key_tag_on_success(self):
        rrset = make_a_rrset()
        rrsig = make_rrsig_rrset()
        dnskeys = make_dnskey_rrset()

        with patch("dns.dnssec.validate", return_value=None):
            ok, tag = validate_rrsig_over_rrset(rrset, rrsig, dnskeys, "example.com.")
        assert ok is True
        assert isinstance(tag, int)

    def test_tries_all_keys_before_giving_up(self):
        """All keys fail → returns (False, None)."""
        rrset = make_a_rrset()
        rrsig = make_rrsig_rrset()
        # Two keys in the RRset
        dnskeys = make_dnskey_rrset()
        dnskeys.add(make_dnskey_rdata(flags=256, algorithm=13, key_bytes=b"\x02" * 64))

        call_count = 0

        def always_fail(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise Exception("fail")

        with patch("dns.dnssec.validate", side_effect=always_fail):
            ok, tag = validate_rrsig_over_rrset(rrset, rrsig, dnskeys, "example.com.")
        assert ok is False
        assert call_count == 2  # tried both keys


# ---------------------------------------------------------------------------
# fmt_ds / fmt_dnskey / fmt_rrsig
# ---------------------------------------------------------------------------


class TestFmtDs:
    def test_known_digest_type(self):
        ds_rrset = make_ds_rrset("example.com.", key_tag=12345, digest_type=2)
        ds = list(ds_rrset)[0]
        label = fmt_ds(ds)
        assert label == "DS=12345/SHA-256"

    def test_unknown_digest_type_uses_number(self):
        ds_rrset = make_ds_rrset("example.com.", key_tag=999, digest_type=99)
        ds = list(ds_rrset)[0]
        label = fmt_ds(ds)
        assert label == "DS=999/99"


class TestFmtDnskey:
    def test_sep_flag_set(self):
        dnskey = make_dnskey_rdata(flags=257)  # 257 = 0x0101 → SEP bit set
        label = fmt_dnskey(dnskey)
        assert "/SEP" in label
        assert label.startswith("DNSKEY=")

    def test_no_sep_flag(self):
        dnskey = make_dnskey_rdata(flags=256)  # 256 = 0x0100 → ZSK
        label = fmt_dnskey(dnskey)
        assert "/SEP" not in label
        assert label.startswith("DNSKEY=")


class TestFmtRrsig:
    def test_format(self):
        rrsig_rrset = make_rrsig_rrset(key_tag=42)
        rrsig = list(rrsig_rrset)[0]
        label = fmt_rrsig(rrsig)
        assert label == "RRSIG=42"


# ---------------------------------------------------------------------------
# nsec3_hash
# ---------------------------------------------------------------------------


class TestNsec3Hash:
    def test_no_salt_single_iteration(self):
        """RFC 5155 §5: hash = SHA-1 of wire-name with empty salt, 1 pass."""
        name = "example.com."
        wire = dns.name.from_text(name).canonicalize().to_wire()
        expected_raw = hashlib.sha1(wire).digest()
        # encode as base32, translate to hex alphabet
        b32std = base64.b32encode(expected_raw).decode().upper().rstrip("=")
        expected = b32std.translate(_TO_B32HEX)
        assert nsec3_hash(name, "", 0) == expected

    def test_with_dash_salt_treated_as_empty(self):
        result_dash = nsec3_hash("example.com.", "-", 0)
        result_empty = nsec3_hash("example.com.", "", 0)
        assert result_dash == result_empty

    def test_with_hex_salt(self):
        result = nsec3_hash("example.com.", "aabbccdd", 0)
        assert isinstance(result, str)
        assert len(result) == 32  # SHA-1 → 20 bytes → 32 base32hex chars

    def test_with_iterations(self):
        r0 = nsec3_hash("example.com.", "", 0)
        r1 = nsec3_hash("example.com.", "", 1)
        assert r0 != r1


# ---------------------------------------------------------------------------
# nsec3_covers
# ---------------------------------------------------------------------------


class TestNsec3Covers:
    def test_normal_range_target_inside(self):
        assert nsec3_covers("AAAA", "ZZZZ", "MMMM") is True

    def test_normal_range_target_before(self):
        assert nsec3_covers("MMMM", "ZZZZ", "AAAA") is False

    def test_normal_range_target_after(self):
        assert nsec3_covers("AAAA", "MMMM", "ZZZZ") is False

    def test_wraparound_target_after_owner(self):
        # In wrap-around (owner > next), target > owner means covered.
        # 'ZZZZ1' > 'ZZZZ' → covered is True (it's in the upper arc).
        assert nsec3_covers("ZZZZ", "AAAA", "ZZZZ1") is True

    def test_wraparound_target_before_next(self):
        assert nsec3_covers("ZZZZ", "MMMM", "AAAA") is True

    def test_wraparound_target_after_next(self):
        assert nsec3_covers("ZZZZ", "AAAA", "BBBB") is False

    def test_case_insensitive(self):
        assert nsec3_covers("aaaa", "zzzz", "mmmm") is True

    def test_boundary_owner_not_covered(self):
        assert nsec3_covers("AAAA", "ZZZZ", "AAAA") is False

    def test_boundary_next_not_covered(self):
        assert nsec3_covers("AAAA", "ZZZZ", "ZZZZ") is False


# ---------------------------------------------------------------------------
# nsec3_owner_hash
# ---------------------------------------------------------------------------


class TestNsec3OwnerHash:
    def _make_nsec3_rrset(self, owner: str) -> object:
        """Build a minimal mock RRset-like object with the right .name."""
        rr = MagicMock()
        rr.name = dns.name.from_text(owner)
        return rr

    def test_extracts_hash_label(self):
        owner = "JFFEHCP1SILLDV4FFBNLF8GMEBOCAP8O.example.com."
        rr = self._make_nsec3_rrset(owner)
        result = nsec3_owner_hash(rr, "example.com.")
        assert result == "JFFEHCP1SILLDV4FFBNLF8GMEBOCAP8O"

    def test_fallback_splits_on_dot(self):
        """If zone suffix doesn't match, return first label."""
        owner = "HASH1234.other.zone."
        rr = self._make_nsec3_rrset(owner)
        result = nsec3_owner_hash(rr, "example.com.")
        assert result == "HASH1234"
