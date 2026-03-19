"""Shared test fixtures and DNS-object factories for chainvalidator tests.

All network-I/O functions (udp_query, dns.query.udp/tcp, requests.get,
dns.resolver.resolve) are mocked at the boundary.  No test ever touches
a real nameserver.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

# ---------------------------------------------------------------------------
# Low-level DNS object builders
# ---------------------------------------------------------------------------


def make_a_rrset(
    name: str = "example.com.", ttl: int = 300, addresses: list[str] | None = None
) -> dns.rrset.RRset:
    """Build an A RRset."""
    addresses = addresses or ["1.2.3.4"]
    rr = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.A)
    rr.update_ttl(ttl)
    for addr in addresses:
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, addr)
        rr.add(rdata)
    return rr


def make_ns_rrset(
    name: str = "example.com.", nameservers: list[str] | None = None
) -> dns.rrset.RRset:
    """Build an NS RRset."""
    nameservers = nameservers or ["ns1.example.com."]
    rr = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.NS)
    rr.update_ttl(300)
    for ns in nameservers:
        rr.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns))
    return rr


def make_soa_rrset(name: str = "example.com.") -> dns.rrset.RRset:
    """Build a minimal SOA RRset."""
    rr = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.SOA)
    rr.update_ttl(300)
    rr.add(
        dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            "ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 300",
        )
    )
    return rr


def make_dnskey_rdata(
    flags: int = 257, algorithm: int = 13, key_bytes: bytes | None = None
) -> dns.rdata.Rdata:
    """Build a DNSKEY rdata object (real wire format accepted by dnspython)."""
    if key_bytes is None:
        # 64-byte dummy key (not cryptographically valid, but structurally fine)
        key_bytes = b"\x01" * 64
    protocol = 3
    wire = struct.pack("!HBB", flags, protocol, algorithm) + key_bytes
    return dns.rdata.from_wire(
        dns.rdataclass.IN, dns.rdatatype.DNSKEY, wire, 0, len(wire)
    )


def make_dnskey_rrset(
    name: str = "example.com.", flags: int = 257, algorithm: int = 13
) -> dns.rrset.RRset:
    """Build a DNSKEY RRset containing one key."""
    rr = dns.rrset.RRset(
        dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    rr.update_ttl(300)
    rr.add(make_dnskey_rdata(flags=flags, algorithm=algorithm))
    return rr


def make_ds_rrset(
    name: str = "example.com.",
    key_tag: int = 12345,
    algorithm: int = 13,
    digest_type: int = 2,
) -> dns.rrset.RRset:
    """Build a DS RRset containing one DS record."""
    rr = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.DS)
    rr.update_ttl(300)
    digest = b"\xab" * 32  # 32-byte dummy SHA-256 digest
    rr.add(
        dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DS,
            f"{key_tag} {algorithm} {digest_type} {digest.hex()}",
        )
    )
    return rr


def make_rrsig_rrset(
    name: str = "example.com.",
    type_covered: int = dns.rdatatype.A,
    key_tag: int = 12345,
    algorithm: int = 13,
    expiration_offset: int = 86400,
) -> dns.rrset.RRset:
    """Build an RRSIG RRset with a future expiration by default."""
    rr = dns.rrset.RRset(
        dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.RRSIG
    )
    rr.update_ttl(300)
    now = datetime.now(timezone.utc)
    inception = int((now - timedelta(hours=1)).timestamp())
    expiration = int((now + timedelta(seconds=expiration_offset)).timestamp())

    def ts(t: int) -> str:
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y%m%d%H%M%S")

    rdtype_name = dns.rdatatype.to_text(type_covered)
    sig_text = (
        f"{rdtype_name} {algorithm} 2 300 "
        f"{ts(expiration)} {ts(inception)} {key_tag} "
        f"example.com. AAAA"  # dummy base64 signature
    )
    rr.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG, sig_text))
    return rr


def make_cname_rrset(
    name: str = "www.example.com.", target: str = "example.com."
) -> dns.rrset.RRset:
    """Build a CNAME RRset."""
    rr = dns.rrset.RRset(
        dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.CNAME
    )
    rr.update_ttl(300)
    rr.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, target))
    return rr


def make_nsec_rrset(
    name: str = "example.com.",
    next_name: str = "z.example.com.",
    windows: tuple[tuple[int, bytes], ...] | None = None,
) -> dns.rrset.RRset:
    """Build an NSEC RRset that proves absence of type A (rdtype 1) in window 0."""
    rr = dns.rrset.RRset(
        dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.NSEC
    )
    rr.update_ttl(300)
    # Bitmap window 0: SOA (type 6) present, A (type 1) absent.
    # SOA = type 6 → window 0, byte 0, bit 1 = 0x02
    rr.add(
        dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC,
            f"{next_name} SOA",
        )
    )
    return rr


# ---------------------------------------------------------------------------
# DNS message builders
# ---------------------------------------------------------------------------


def make_response(
    qname: str = "example.com.", rdtype: int = dns.rdatatype.A, rcode: int = 0
) -> dns.message.Message:
    """Build a minimal DNS response with no RRsets."""
    q = dns.message.make_query(qname, rdtype)
    resp = dns.message.make_response(q)
    resp.set_rcode(rcode)
    return resp


def make_response_with_answer(
    rrsets: list[dns.rrset.RRset],
    qname: str = "example.com.",
    rdtype: int = dns.rdatatype.A,
) -> dns.message.Message:
    """Build a DNS NOERROR response with the given RRsets in the answer section."""
    resp = make_response(qname, rdtype)
    for rr in rrsets:
        resp.answer.append(rr)
    return resp


def make_response_with_authority(
    rrsets: list[dns.rrset.RRset],
    qname: str = "example.com.",
    rdtype: int = dns.rdatatype.A,
    rcode: int = 0,
) -> dns.message.Message:
    """Build a DNS response with given RRsets in the authority section."""
    resp = make_response(qname, rdtype, rcode=rcode)
    for rr in rrsets:
        resp.authority.append(rr)
    return resp
