# Frappe Tamper-Proof Audit Trail Ledger (MCA & CARO 2020)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Frappe Certified](https://img.shields.io/badge/Frappe-Enterprise%20Audit-red.svg)](https://frappe.io)

An enterprise cryptographic audit-logging engine designed to satisfy Indian Ministry of Corporate Affairs (MCA) audit trail mandates and CARO 2020 governance rules within Frappe & ERPNext.

## Core Capabilities
- **SHA-256 Hash Chaining:** Every DocType version mutation is cryptographically linked to the preceding block.
- **Payload Immutability:** Any direct DB modification (`UPDATE tabDocType...`) triggers an instant chain failure upon audit verification.
- **Deterministic Serialization:** Canonical JSON sorting guarantees consistent hashing across environments.
- **Fast Integrity Audits:** Verifies millions of historical ledger records in sub-second sweeps.

## Installation & Tests
```bash
python3 -m unittest discover tests
```
