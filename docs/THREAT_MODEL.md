# Vouch Security Threat Model

This document outlines the security assumptions, attack vectors, and defensive guarantees provided by Vouch.

## 1. Adversary Capabilities

| Threat Actor | Capabilities | Vouch Defensive Mechanism |
| :--- | :--- | :--- |
| **Malicious Mirror (CDN)** | Tamper with chunks, serve stale metadata | BLAKE3 chunk verification, signed DSSE manifests, anti-rollback checks |
| **Compromised Target Signer** | Sign poisoned model weights | Publisher root key revocation, status reconciliation, quorum policies |
| **Man-in-the-Middle (Network)** | Inject payloads or downgrade protocols | Mandatory TLS, cryptographic envelopes, peer cross-validation |
| **Stale Mirror Replay** | Replay obsolete metadata versions | Monotonically increasing version numbers in Root and Snapshot metadata |

## 2. Invariants
1. **Never Trust, Always Verify**: No artifact is ever placed in target location before verifying against root-anchored manifest.
2. **Deterministic Canonicalization**: All cryptographic signatures strictly adhere to RFC 8785.
3. **No Bypass Switches**: No CLI flags or environment variables exist to disable signature or digest checks.
