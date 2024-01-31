# Vouch Architecture Documentation (`arc/`)

This directory contains the in-depth architectural and cryptographic specifications for **Vouch**, a verified-by-default distribution system for machine learning models and datasets.

---

## Architecture Index

| Document | Description |
|---|---|
| [01_TECHNICAL_ARCHITECTURE.md](01_TECHNICAL_ARCHITECTURE.md) | Technical architecture, content-addressed storage (CAS), DSSE envelope layout, carrier/mirror decoupling, and wire protocols. |
| [02_SECURITY_AND_THREAT_MODEL.md](02_SECURITY_AND_THREAT_MODEL.md) | Security guarantees, trust anchors, threat model boundaries (T1–T6), key lifecycle, and failure modes. |
| [03_THREAT_COVERAGE_MATRIX.md](03_THREAT_COVERAGE_MATRIX.md) | Threat-to-test verification matrix mapping every adversarial attack to proof test suites. |

---

## Visual Architecture Assets

- [Architecture Diagram](../docs/img/architecture.svg)
- [Verification Pipeline](../docs/img/verification-pipeline.svg)
- [Threat Model](../docs/img/threat-model.svg)
- [Threat Coverage](../docs/img/threat-coverage.svg)
