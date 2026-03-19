"""DNSSEC cryptographic helpers and NSEC3 proof utilities.

All pure-logic helpers that operate on already-fetched DNS objects —
no network I/O in this module.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Optional

import dns.dnssec
import dns.exception
import dns.name
import dns.rdatatype
import dns.rrset
from dns.rdata import Rdata

from chainvalidator.constants import DIGEST_MAP

# ---------------------------------------------------------------------------
# DS / DNSKEY matching
# ---------------------------------------------------------------------------


def ds_matches_dnskey(ds: Rdata, dnskey: Rdata, zone: str) -> bool:
    """Check whether *ds* is a valid cryptographic hash of *dnskey*.

    Delegates to :func:`dns.dnssec.make_ds` and compares digests.

    :param ds: The DS record to verify.
    :type ds: dns.rdata.Rdata
    :param dnskey: The DNSKEY record to hash.
    :type dnskey: dns.rdata.Rdata
    :param zone: The owner zone name, required to compute the canonical form.
    :type zone: str
    :returns: ``True`` if the digests match.
    :rtype: bool
    """
    try:
        computed = dns.dnssec.make_ds(zone, dnskey, ds.digest_type)
        return computed.digest == ds.digest
    except Exception:
        return False


def validate_rrsig_over_rrset(
    rrset: dns.rrset.RRset,
    rrsig_rrset: dns.rrset.RRset,
    dnskeys: dns.rrset.RRset,
    zone: str,
) -> tuple[bool, Optional[int]]:
    """Attempt to validate *rrsig_rrset* over *rrset* using any key in *dnskeys*.

    Each DNSKEY is tried in turn; validation succeeds as soon as one key
    verifies the signature.

    :param rrset: The signed RRset.
    :type rrset: dns.rrset.RRset
    :param rrsig_rrset: The RRSIG RRset covering *rrset*.
    :type rrsig_rrset: dns.rrset.RRset
    :param dnskeys: The DNSKEY RRset from which to try keys.
    :type dnskeys: dns.rrset.RRset
    :param zone: The zone name (used to look up keys by owner name).
    :type zone: str
    :returns: ``(True, key_tag)`` on success, ``(False, None)`` on failure.
    :rtype: tuple[bool, int or None]
    """
    zone_name = dns.name.from_text(zone)
    for dnskey in dnskeys:
        key_tag = dns.dnssec.key_id(dnskey)
        try:
            key_rrset = dns.rrset.from_rdata(zone_name, dnskeys.ttl, dnskey)
            dns.dnssec.validate(rrset, rrsig_rrset, {zone_name: key_rrset})
            return True, key_tag
        except Exception:
            continue
    return False, None


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def fmt_ds(ds: Rdata) -> str:
    """Return a concise human-readable label for a DS record.

    :param ds: A DS :class:`~dns.rdata.Rdata` object.
    :type ds: dns.rdata.Rdata
    :returns: A string such as ``"DS=12345/SHA-256"``.
    :rtype: str
    """
    digest_name = DIGEST_MAP.get(ds.digest_type, str(ds.digest_type))
    return f"DS={ds.key_tag}/{digest_name}"


def fmt_dnskey(dnskey: Rdata) -> str:
    """Return a concise human-readable label for a DNSKEY record.

    :param dnskey: A DNSKEY :class:`~dns.rdata.Rdata` object.
    :type dnskey: dns.rdata.Rdata
    :returns: A string such as ``"DNSKEY=12345/SEP"`` (SEP suffix only for
        key-signing keys with the Secure Entry Point flag set).
    :rtype: str
    """
    tag = dns.dnssec.key_id(dnskey)
    sep = "/SEP" if dnskey.flags & 0x0001 else ""
    return f"DNSKEY={tag}{sep}"


def fmt_rrsig(rrsig: Rdata) -> str:
    """Return a concise human-readable label for an RRSIG record.

    :param rrsig: An RRSIG :class:`~dns.rdata.Rdata` object.
    :type rrsig: dns.rdata.Rdata
    :returns: A string such as ``"RRSIG=12345"``.
    :rtype: str
    """
    return f"RRSIG={rrsig.key_tag}"


# ---------------------------------------------------------------------------
# NSEC3 helpers  (RFC 5155)
# ---------------------------------------------------------------------------

# base32hex alphabet (RFC 4648 §7) used by NSEC3 owner names
_B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_TO_B32HEX = str.maketrans(_B32_STD, _B32_HEX)


def nsec3_hash(name: str, salt_hex: str, iterations: int) -> str:
    """Compute the NSEC3 hash of a DNS name as specified in RFC 5155 §5.

    The algorithm is iterated SHA-1 over the wire-format name concatenated
    with the salt, repeated ``iterations + 1`` times in total.

    :param name: The DNS name to hash (canonicalised to wire format internally).
    :type name: str
    :param salt_hex: Hex-encoded salt string, or ``"-"`` / ``""`` for no salt.
    :type salt_hex: str
    :param iterations: Number of *additional* hash iterations (0 = one pass).
    :type iterations: int
    :returns: The hash as an uppercase base32hex string with no padding,
        matching the owner-name prefix used in NSEC3 RRs.
    :rtype: str
    """
    wire = dns.name.from_text(name).canonicalize().to_wire()
    salt = bytes.fromhex(salt_hex) if salt_hex and salt_hex != "-" else b""
    digest = wire
    for _ in range(iterations + 1):
        digest = hashlib.sha1(digest + salt).digest()
    b32std = base64.b32encode(digest).decode().upper().rstrip("=")
    return b32std.translate(_TO_B32HEX)


def nsec3_covers(owner_b32: str, next_b32: str, target_b32: str) -> bool:
    """Return ``True`` if *target_b32* falls in the NSEC3 interval ``(owner, next)``.

    Handles the wrap-around case for the last record in the chain, whose
    interval spans ``(owner, end] ∪ [start, next)``.

    :param owner_b32: Base32hex hash of the NSEC3 owner name.
    :type owner_b32: str
    :param next_b32: Base32hex hash of the next name in the chain.
    :type next_b32: str
    :param target_b32: Base32hex hash of the name being tested.
    :type target_b32: str
    :returns: ``True`` if *target_b32* is covered by this NSEC3 record.
    :rtype: bool
    """
    o, n, t = owner_b32.upper(), next_b32.upper(), target_b32.upper()
    if o < n:
        return o < t < n
    else:
        return t > o or t < n


def nsec3_owner_hash(rr: dns.rrset.RRset, zone: str) -> str:
    """Extract the base32hex hash label from an NSEC3 owner name.

    NSEC3 owner names have the form ``<hash>.<zone>``, e.g.
    ``JFFEHCP1SILLDV4FFBNLF8GMEBOCAP8O.example.com.``

    :param rr: An NSEC3 RRset whose owner name contains the hash label.
    :type rr: dns.rrset.RRset
    :param zone: The zone name used to strip the suffix.
    :type zone: str
    :returns: The uppercase hash label, e.g.
        ``"JFFEHCP1SILLDV4FFBNLF8GMEBOCAP8O"``.
    :rtype: str
    """
    owner = rr.name.to_text().upper()
    zone_suffix = "." + zone.upper().rstrip(".") + "."
    if owner.endswith(zone_suffix):
        return owner[: -len(zone_suffix)]
    return owner.split(".")[0]
