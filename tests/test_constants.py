"""Tests for chainvalidator.constants."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from chainvalidator.constants import (
    ALGORITHM_MAP,
    DIGEST_MAP,
    DNS_PORT,
    DNS_TIMEOUT,
    GREEN,
    RED,
    ROOT_SERVERS,
    YELLOW,
    algo_name,
    pick_root_server,
)


class TestMaps:
    def test_algorithm_map_known_entries(self):
        assert ALGORITHM_MAP[8] == "RSASHA256"
        assert ALGORITHM_MAP[13] == "ECDSAP256SHA256"
        assert ALGORITHM_MAP[15] == "Ed25519"

    def test_digest_map_known_entries(self):
        assert DIGEST_MAP[1] == "SHA-1"
        assert DIGEST_MAP[2] == "SHA-256"
        assert DIGEST_MAP[4] == "SHA-384"

    def test_root_servers_count(self):
        assert len(ROOT_SERVERS) == 13

    def test_root_servers_contains_known(self):
        assert "a.root-servers.net" in ROOT_SERVERS
        assert ROOT_SERVERS["a.root-servers.net"] == "198.41.0.4"


class TestDefaults:
    def test_dns_timeout(self):
        assert DNS_TIMEOUT == 5.0

    def test_dns_port(self):
        assert DNS_PORT == 53


class TestSymbols:
    def test_green_is_checkmark(self):
        assert GREEN == "\u2714"

    def test_yellow_is_warning(self):
        assert YELLOW == "\u26a0"

    def test_red_is_cross(self):
        assert RED == "\u2718"


class TestAlgoName:
    def test_known_algorithm(self):
        assert algo_name(13) == "ECDSAP256SHA256"
        assert algo_name(8) == "RSASHA256"

    def test_unknown_algorithm_returns_algN(self):
        assert algo_name(99) == "ALG99"
        assert algo_name(0) == "ALG0"


class TestPickRootServer:
    def test_returns_tuple_of_two_strings(self):
        name, ip = pick_root_server()
        assert isinstance(name, str)
        assert isinstance(ip, str)

    def test_result_is_in_root_servers(self):
        name, ip = pick_root_server()
        assert name in ROOT_SERVERS
        assert ROOT_SERVERS[name] == ip

    def test_uses_secrets_randbelow(self):
        """Ensure cryptographic randomness is used."""
        with patch(
            "chainvalidator.constants.secrets.randbelow", return_value=0
        ) as mock_rb:
            name, ip = pick_root_server()
        mock_rb.assert_called_once_with(13)
        assert name == list(ROOT_SERVERS.keys())[0]
