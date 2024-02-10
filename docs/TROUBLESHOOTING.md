# Vouch Troubleshooting Guide

Common issues, failure codes, and step-by-step resolution steps.

---

### 1. Hash Mismatch During Fetch (`E_DIGEST_MISMATCH`)
- **Cause**: Downloaded chunk does not match BLAKE3 digest in verified manifest.
- **Resolution**:
  - The chunk is quarantined automatically.
  - Vouch will attempt download from peer fallback mirrors.
  - Run `vouch doctor` to verify local CAS integrity.

### 2. Expired Root / Timestamp Metadata (`E_TIMESTAMP_EXPIRED`)
- **Cause**: Local root metadata snapshot is past its `expires_at` window.
- **Resolution**:
  - Ensure client clock is synchronized with NTP.
  - Run `vouch trust refresh --name <PUBLISHER>` to fetch the latest signed timestamp.

### 3. Key Revocation Detected (`E_SIGNER_REVOKED`)
- **Cause**: The artifact signer key was revoked in a newer root version.
- **Resolution**:
  - Check `vouch status` to see revoked publisher artifacts.
  - Upgrade to the latest published artifact version signed by active keys.

### 4. Mirror Unavailable (`E_MIRROR_UNREACHABLE`)
- **Cause**: Primary mirror returned 5xx or timed out.
- **Resolution**:
  - Add secondary mirrors via `vouch trust update --mirror <URL>`.
