"""Low-level DNS transport helpers for chainvalidator.

All functions perform network I/O and raise :exc:`RuntimeError` on failure
so callers can decide how to handle errors without catching DNS-library
exceptions directly.
"""

from __future__ import annotations

import logging
from typing import Optional

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdatatype
import dns.resolver
import dns.rrset

from chainvalidator.constants import DNS_PORT, DNS_TIMEOUT

logger = logging.getLogger("chainvalidator")


# ---------------------------------------------------------------------------
# Core UDP/TCP query
# ---------------------------------------------------------------------------


def udp_query(
    qname: str | dns.name.Name,
    rdtype: int,
    nameserver: str,
    port: int = DNS_PORT,
    timeout: float = DNS_TIMEOUT,
) -> dns.message.Message:
    """Send a DNSSEC-enabled UDP query, falling back to TCP on truncation.

    Large RRsets such as DNSKEY frequently exceed the 512-byte UDP limit even
    with EDNS0, so the TCP fallback is essential for correct operation.

    :param qname: Query name (string or :class:`dns.name.Name`).
    :type qname: str or dns.name.Name
    :param rdtype: RR type code (e.g. :data:`dns.rdatatype.DNSKEY`).
    :type rdtype: int
    :param nameserver: IPv4 address of the target nameserver.
    :type nameserver: str
    :param port: DNS port.  Defaults to :data:`~chainvalidator.constants.DNS_PORT`.
    :type port: int
    :param timeout: Per-attempt timeout in seconds.
    :type timeout: float
    :returns: The parsed DNS response message.
    :rtype: dns.message.Message
    :raises RuntimeError: On UDP or TCP transport failure.
    """
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    try:
        resp = dns.query.udp(q, nameserver, timeout=timeout, port=port)
    except Exception as exc:
        raise RuntimeError(
            f"UDP query for {qname}/{dns.rdatatype.to_text(rdtype)} "
            f"to {nameserver} failed: {exc}"
        ) from exc

    if resp.flags & dns.flags.TC:
        logger.debug(
            "  Response truncated; retrying %s/%s over TCP",
            qname,
            dns.rdatatype.to_text(rdtype),
        )
        try:
            resp = dns.query.tcp(q, nameserver, timeout=timeout, port=port)
        except Exception as exc:
            raise RuntimeError(
                f"TCP fallback for {qname}/{dns.rdatatype.to_text(rdtype)} "
                f"to {nameserver} failed: {exc}"
            ) from exc

    return resp


# ---------------------------------------------------------------------------
# RRset extraction
# ---------------------------------------------------------------------------


def extract_rrsets(
    response: dns.message.Message,
    rdtype: int,
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Scan all sections of *response* and return the target RRset plus its RRSIG.

    :param response: A parsed DNS response message.
    :type response: dns.message.Message
    :param rdtype: The RR type to search for.
    :type rdtype: int
    :returns: ``(rrset, rrsig_rrset)``; either element may be ``None`` if
        absent from the response.
    :rtype: tuple[dns.rrset.RRset or None, dns.rrset.RRset or None]
    """
    rrset = rrsig = None
    for section in (response.answer, response.authority, response.additional):
        for rr in section:
            if rr.rdtype == rdtype and rrset is None:
                rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG and rrsig is None:
                for sig in rr:
                    if sig.type_covered == rdtype:
                        rrsig = rr
                        break
    return rrset, rrsig


# ---------------------------------------------------------------------------
# DS and DNSKEY fetchers
# ---------------------------------------------------------------------------


def get_ds_from_parent(
    zone: str,
    parent_ns: str,
    timeout: float = DNS_TIMEOUT,
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query *parent_ns* for the DS RRset of *zone* and its covering RRSIG.

    :param zone: Child zone name (e.g. ``"example.com."``).
    :type zone: str
    :param parent_ns: IPv4 address of the parent zone's nameserver.
    :type parent_ns: str
    :param timeout: Per-query timeout in seconds.
    :type timeout: float
    :returns: ``(ds_rrset, rrsig_rrset)``; either may be ``None``.
    :rtype: tuple[dns.rrset.RRset or None, dns.rrset.RRset or None]
    :raises RuntimeError: On transport failure.
    """
    resp = udp_query(zone, dns.rdatatype.DS, parent_ns, timeout=timeout)
    return extract_rrsets(resp, dns.rdatatype.DS)


def get_dnskey(
    zone: str,
    ns: str,
    timeout: float = DNS_TIMEOUT,
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query *ns* for the DNSKEY RRset of *zone* and its covering RRSIG.

    :param zone: Zone name (e.g. ``"example.com."``).
    :type zone: str
    :param ns: IPv4 address of an authoritative nameserver for *zone*.
    :type ns: str
    :param timeout: Per-query timeout in seconds.
    :type timeout: float
    :returns: ``(dnskey_rrset, rrsig_rrset)``; either may be ``None``.
    :rtype: tuple[dns.rrset.RRset or None, dns.rrset.RRset or None]
    :raises RuntimeError: On transport failure.
    """
    resp = udp_query(zone, dns.rdatatype.DNSKEY, ns, timeout=timeout)
    return extract_rrsets(resp, dns.rdatatype.DNSKEY)
