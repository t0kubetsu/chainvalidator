"""Shared constants and lookup tables for chainvalidator.

All values are protocol-defined and do not depend on runtime state.
"""

from __future__ import annotations

import secrets

# ---------------------------------------------------------------------------
# DNSSEC algorithm / digest name maps
# ---------------------------------------------------------------------------

ALGORITHM_MAP: dict[int, str] = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    12: "ECC-GOST",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "Ed25519",
    16: "Ed448",
}
"""Mapping of DNSSEC algorithm numbers (RFC 8624) to human-readable mnemonics."""

DIGEST_MAP: dict[int, str] = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST R 34.11-94",
    4: "SHA-384",
}
"""Mapping of DS digest type numbers (RFC 4034 §5.1) to human-readable names."""

# ---------------------------------------------------------------------------
# Root name servers
# ---------------------------------------------------------------------------

ROOT_SERVERS: dict[str, str] = {
    "a.root-servers.net": "198.41.0.4",
    "b.root-servers.net": "170.247.170.2",
    "c.root-servers.net": "192.33.4.12",
    "d.root-servers.net": "199.7.91.13",
    "e.root-servers.net": "192.203.230.10",
    "f.root-servers.net": "192.5.5.241",
    "g.root-servers.net": "192.112.36.4",
    "h.root-servers.net": "198.97.190.53",
    "i.root-servers.net": "192.36.148.17",
    "j.root-servers.net": "192.58.128.30",
    "k.root-servers.net": "193.0.14.129",
    "l.root-servers.net": "199.7.83.42",
    "m.root-servers.net": "202.12.27.33",
}
"""All 13 IANA root name servers with their IPv4 addresses."""

# ---------------------------------------------------------------------------
# DNS transport defaults
# ---------------------------------------------------------------------------

DNS_TIMEOUT: float = 5.0
"""Default per-query UDP/TCP timeout in seconds."""

DNS_PORT: int = 53
"""Standard DNS port."""

# ---------------------------------------------------------------------------
# Terminal output symbols
# ---------------------------------------------------------------------------

GREEN = "\u2714"  # ✔
YELLOW = "\u26a0"  # ⚠
RED = "\u2718"  # ✘


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def pick_root_server() -> tuple[str, str]:
    """Select a root name server at random using a cryptographically secure RNG.

    :returns: A ``(hostname, ipv4_address)`` tuple chosen from
        :data:`ROOT_SERVERS`, e.g. ``("k.root-servers.net", "193.0.14.129")``.
    :rtype: tuple[str, str]
    """
    names = list(ROOT_SERVERS.keys())
    name = names[secrets.randbelow(len(names))]
    return name, ROOT_SERVERS[name]


def algo_name(alg: int) -> str:
    """Resolve a DNSSEC algorithm number to its mnemonic name.

    :param alg: Algorithm number as defined in RFC 8624.
    :type alg: int
    :returns: The mnemonic string (e.g. ``"ECDSAP256SHA256"``) or
        ``"ALG<n>"`` for unknown values.
    :rtype: str
    """
    return ALGORITHM_MAP.get(alg, f"ALG{alg}")
