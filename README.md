# ChainValidator

**ChainValidator** is a Python tool that validates the **DNSSEC chain of trust** for a domain.

It verifies the DNSSEC delegation hierarchy step-by-step, starting from the **root trust anchor** and validating **DS ↔ DNSKEY relationships and RRSIG signatures** until the target domain.

The tool can be used either as a **Python CLI utility** or as a **Python module**.

---

# Features

* Validate the **complete DNSSEC chain of trust**
* Walk the hierarchy from **root → delegated zone → target domain**
* Verify:

  * DNSKEY records
  * DS records
  * RRSIG signatures
  * Parent/child cryptographic linkage
* Detect **broken DNSSEC delegations**
* Detailed **step-by-step validation output**
* Can be used as:

  * **CLI tool**
  * **Python module**

---

# Why ChainValidator

Tools such as `dig`, `drill`, or `delv` typically rely on a **validating resolver** to perform DNSSEC verification.

ChainValidator instead performs **explicit step-by-step validation**, exposing the internal validation process:

* trust anchor verification
* DS → DNSKEY validation
* DNSKEY → RRSIG verification
* record signature validation

This tool was created to provide a **Python CLI and library equivalent of the [Verisign DNSSEC Debugger](https://dnssec-debugger.verisignlabs.com/)**, enabling DNSSEC validation directly from scripts or automation pipelines.

It is useful for:

* learning how DNSSEC validation works
* debugging broken DNSSEC delegations
* auditing DNSSEC deployments
* building security tooling around DNSSEC

---

# DNSSEC Chain of Trust

DNSSEC establishes trust using a **hierarchical chain of cryptographic signatures**.

```
Trust Anchor (IANA)
        │
        ▼
Root Zone (.)
        │
        ▼
Top-Level Domain (TLD)
        │
        ▼
Delegated Zone
        │
        ▼
Target Domain
```

Each parent zone publishes a **DS record** that references the child zone’s **DNSKEY**.

If all DS ↔ DNSKEY relationships and signatures verify successfully, the domain is considered **securely signed**.

---

# Quick Start

```bash
git clone https://github.com/t0kubetsu/chainvalidator.git
cd chainvalidator

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python chainvalidator.py example.com
```

---

# Example Output

Successful validation:

```
======================================================================
  DNSSEC Validation for: example.com
======================================================================
----------------------------------------------------------------------
  Trust Anchor (IANA root-anchors.xml)
----------------------------------------------------------------------
  ✅ Trust anchor DS=20326/SHA-256 (algorithm RSASHA256) -- active
  ✅ Trust anchor DS=38696/SHA-256 (algorithm RSASHA256) -- active
----------------------------------------------------------------------
  Zone: . (root)
----------------------------------------------------------------------
  ✅ Found 3 DNSKEY record(s) for .
  ✅ DS=20326/SHA-256 verifies DNSKEY=20326/SEP
  ✅ DS=38696/SHA-256 verifies DNSKEY=38696/SEP
  ✅ RRSIG=20326 and DNSKEY=20326/SEP verifies the DNSKEY RRset
----------------------------------------------------------------------
  Zone: com.  (parent: .)
----------------------------------------------------------------------
  [DS check: . -> com.]
  ✅ Found 1 DS record(s) for com.
      DS=19718/SHA-256  algorithm=ECDSAP256SHA256
  ✅ RRSIG=21831 and DNSKEY=21831 verifies the DS RRset
  [DNSKEY check: com.]
  ✅ Found 2 DNSKEY record(s) for com.
  ✅ DS=19718/SHA-256 verifies DNSKEY=19718/SEP
  ✅ RRSIG=19718 and DNSKEY=19718/SEP verifies the DNSKEY RRset
----------------------------------------------------------------------
  Zone: example.com.  (parent: com.)
----------------------------------------------------------------------
  [DS check: com. -> example.com.]
  ✅ Found 1 DS record(s) for example.com.
      DS=2371/SHA-256  algorithm=ECDSAP256SHA256
  ✅ RRSIG=35511 and DNSKEY=35511 verifies the DS RRset
  [DNSKEY check: example.com.]
  ✅ Found 4 DNSKEY record(s) for example.com.
  ✅ DS=2371/SHA-256 verifies DNSKEY=2371/SEP
  ✅ RRSIG=2371 and DNSKEY=2371/SEP verifies the DNSKEY RRset
----------------------------------------------------------------------
  Record validation: example.com. A
----------------------------------------------------------------------
  ✅ Found 2 A record(s):
      example.com. 300 IN A 104.18.27.120
      example.com. 300 IN A 104.18.26.120
  ✅ RRSIG=34505 and DNSKEY=34505 verifies the A RRset
======================================================================
✅  Full chain-of-trust validated successfully!
======================================================================
```

Example of **unsigned domain**:

```
======================================================================
  DNSSEC Validation for: google.com
======================================================================
----------------------------------------------------------------------
  Trust Anchor (IANA root-anchors.xml)
----------------------------------------------------------------------
  ✅ Trust anchor DS=20326/SHA-256 (algorithm RSASHA256) -- active
  ✅ Trust anchor DS=38696/SHA-256 (algorithm RSASHA256) -- active
----------------------------------------------------------------------
  Zone: . (root)
----------------------------------------------------------------------
  ✅ Found 3 DNSKEY record(s) for .
  ✅ DS=20326/SHA-256 verifies DNSKEY=20326/SEP
  ✅ DS=38696/SHA-256 verifies DNSKEY=38696/SEP
  ✅ RRSIG=20326 and DNSKEY=20326/SEP verifies the DNSKEY RRset
----------------------------------------------------------------------
  Zone: com.  (parent: .)
----------------------------------------------------------------------
  [DS check: . -> com.]
  ✅ Found 1 DS record(s) for com.
      DS=19718/SHA-256  algorithm=ECDSAP256SHA256
  ✅ RRSIG=21831 and DNSKEY=21831 verifies the DS RRset
  [DNSKEY check: com.]
  ✅ Found 2 DNSKEY record(s) for com.
  ✅ DS=19718/SHA-256 verifies DNSKEY=19718/SEP
  ✅ RRSIG=19718 and DNSKEY=19718/SEP verifies the DNSKEY RRset
----------------------------------------------------------------------
  Zone: google.com.  (parent: com.)
----------------------------------------------------------------------
  [DS check: com. -> google.com.]
  ⚠️  WARNING: No DS records for google.com. in parent zone -- delegation is INSECURE (island of security).
  [DNSKEY check (insecure): google.com.]
  ⚠️  WARNING: No DNSKEY records found for google.com. -- zone is unsigned
----------------------------------------------------------------------
  Record validation: google.com. A
----------------------------------------------------------------------
  ✅ Found 1 A record(s):
      google.com. 300 IN A 216.58.206.78
  ❌ ERROR: No RRSIG found over google.com. A RRset
======================================================================
❌  Validation FAILED -- 1 error(s)
     * No RRSIG found over google.com. A RRset
⚠️   2 warning(s):
     * No DS records for google.com. in parent zone -- delegation is INSECURE (island of security).
     * No DNSKEY records found for google.com. -- zone is unsigned
======================================================================
```
