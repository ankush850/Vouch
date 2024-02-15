# Vouch Frequently Asked Questions (FAQ)

### Q: Why BLAKE3 instead of SHA-256?
**A**: BLAKE3 is designed with tree hashing and SIMD parallelism, delivering up to 10-15x higher throughput on multi-gigabyte ML weights.

### Q: Can a mirror modify model weights without detection?
**A**: No. The manifest containing all chunk hashes is signed with Ed25519 by the publisher. Any altered bit triggers an immediate digest mismatch.

### Q: What happens if a root key is compromised?
**A**: Root keys use a threshold-of-N quorum. Compromised keys are revoked via signed root rotation updates.
