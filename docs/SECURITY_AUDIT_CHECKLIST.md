# Vouch Security Audit & Compliance Checklist

Guidelines for verifying supply chain integrity in enterprise environments.

- [x] **Zero Plaintext Payloads**: All model weights and shards verified against cryptographic hash trees.
- [x] **DSSE Signature Compliance**: Envelopes follow in-toto DSSE specification.
- [x] **Key Isolation**: Offline root keys kept separate from online target signers.
- [x] **Strict Freshness**: Timestamp metadata refreshed within maximum validity window.
- [x] **Mirror Independence**: Compromised mirrors cannot forge or alter published weights.
