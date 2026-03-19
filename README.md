# chainvalidator

> Validate the full DNSSEC chain of trust for any domain — from the command
> line or as a Python library.

**chainvalidator** walks the delegation path from the IANA root trust anchor
down through every TLD and delegated zone to the target, verifying each
DS → DNSKEY → RRSIG link and the signed leaf record.

This tool was created to provide a **Python CLI and library equivalent of the
[Verisign DNSSEC Debugger](https://dnssec-debugger.verisignlabs.com/)**, enabling
DNSSEC validation directly from scripts or automation pipelines.

```
$ chainvalidator check example.com
```

![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)
![Tests](https://img.shields.io/badge/tests-226%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![License](https://img.shields.io/badge/license-GPLv3-lightgrey)

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Python API](#python-api)
- [Logging](#logging)
- [Exit Codes](#exit-codes)
- [Project Structure](#project-structure)

---

## Features

- **Full chain validation** — Trust Anchor → `.` → TLD → Delegated Zone → target.
- **Automatic zone-cut detection** — walks the DNS hierarchy iteratively; no
  hard-coded assumptions about delegation depth.
- **DS → DNSKEY → RRSIG** — each delegation step is cryptographically verified.
- **NSEC NODATA proofs** — RFC 4035 §5.4 denial-of-existence validation.
- **NSEC3 closest-encloser proofs** — RFC 5155 §8.3 NXDOMAIN validation.
- **CNAME following** — validates each target zone independently (max 8 hops).
- **RRSIG expiry checking** on leaf records.
- **Rich terminal output** — colour-coded chain table and verdict panel.
- **Structured result models** — `DNSSECReport`, `ChainLink`, `LeafResult`,
  `Status` for programmatic use.
- **Library-friendly logging** — all diagnostic output via the
  `"chainvalidator"` logger; the CLI never touches it.

---

## Requirements

- Python ≥ 3.11
- [`dnspython[dnssec]`](https://www.dnspython.org/) ≥ 2.6
- [`requests`](https://docs.python-requests.org/) ≥ 2.31
- [`rich`](https://github.com/Textualize/rich) ≥ 13.7
- [`typer`](https://typer.tiangolo.com/) ≥ 0.12

---

## Installation

```bash
git clone https://github.com/t0kubetsu/chainvalidator.git
cd chainvalidator
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## CLI Usage

```bash
# Validate a domain (A record by default)
chainvalidator check example.com

# Validate a specific record type
chainvalidator check example.com --type AAAA
chainvalidator check example.com --type MX

# Adjust the per-query timeout (seconds)
chainvalidator check example.com --timeout 10

# Reference tables
chainvalidator info algorithms
chainvalidator info digests
chainvalidator info root-servers

# Version
chainvalidator --version
```

---

## Python API

```python
from chainvalidator.assessor import assess
from chainvalidator.models   import Status

report = assess("example.com", record_type="A", timeout=5.0)

print(report.status)           # Status.SECURE | INSECURE | BOGUS
print(report.is_secure)        # True / False
print(report.zone_path)        # ['.', 'com.', 'example.com.']
print(report.trust_anchor_keys)# ['DS=20326/SHA-256']

for link in report.chain:
    print(link.zone, link.status, link.ds_matched)

if report.leaf:
    print(report.leaf.records)       # ['93.184.216.34']
    print(report.leaf.rrsig_expires) # '2025-06-01'

# Rich terminal output
from chainvalidator.reporter import print_full_report
print_full_report(report)
```

---

## Logging

The CLI produces no logging output — all display goes through Rich.
As a library, you can capture detailed diagnostic output via the
`"chainvalidator"` logger:

```python
import logging

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger("chainvalidator").addHandler(handler)
logging.getLogger("chainvalidator").setLevel(logging.DEBUG)
```

| Level | Content |
|---|---|
| `DEBUG` | Per-query detail: NS selection, keytag listings, RRSIG expiry |
| `INFO` | Chain milestones: zone headers, DS/DNSKEY matches, final verdict |
| `WARNING` | Insecure delegations, unsigned zones, NXDOMAIN |
| `ERROR` | Hard validation failures (bogus chain) |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Chain fully secure |
| `1` | Bogus — cryptographic validation failed |
| `2` | Insecure — delegation chain not anchored end-to-end |

---

## Project Structure

```
chainvalidator/
├── chainvalidator/
│   ├── __init__.py       Package version, NullHandler
│   ├── assessor.py       assess() — public API entry point
│   ├── checker.py        DNSSECChecker — core validation logic
│   ├── cli.py            Typer CLI: check, info sub-commands
│   ├── constants.py      ALGORITHM_MAP, DIGEST_MAP, ROOT_SERVERS, DNS_TIMEOUT
│   ├── dns_utils.py      udp_query, extract_rrsets, get_ds_from_parent, get_dnskey
│   ├── dnssec_utils.py   ds_matches_dnskey, validate_rrsig_over_rrset, NSEC3 helpers
│   ├── models.py         Status, ChainLink, LeafResult, DNSSECReport
│   └── reporter.py       print_full_report and section printers (Rich)
├── LICENSE
└── pyproject.toml
```

---

## License

GPLv3 — see [LICENSE](LICENSE) for details.