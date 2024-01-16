"""Snapshot document, per 02_TECHNICAL_ARCHITECTURE.md section 4.2 (Decision D6).

The snapshot is deliberately digest-bound to the timestamp rather than
separately signed -- one fewer online key. That means, unlike every other
document in this codebase, there is NO DSSE envelope and no base64 field
insulating the trust-relevant bytes from re-serialization: the digest is
computed over the exact bytes on the wire. Every caller MUST treat snapshot
bytes the way `cas.py` treats chunk bytes -- store and serve the literal
bytes `build_and_digest_snapshot` produced, never re-derive them by
`json.dumps`-ing the parsed dict again (a different encoder, or even the
same encoder with different settings, produces different bytes and
therefore a different digest for semantically-identical content).

V5 (03_SECURITY_AND_ACCESS.md section 6) has exactly one failure mode --
"bytes hash to that digest" -- so every failure path here, including
malformed or non-canonical bytes that still happen to match the requested
digest, raises DigestMismatchError(40).
"""

from __future__ import annotations

import json

from .canonical import canonicalize
from .errors import DigestMismatchError
from .hashing import b3_hex

SNAPSHOT_TYPE = "snapshot/v1"


def build_and_digest_snapshot(*, publisher: str, artifacts: dict) -> tuple[dict, bytes, str]:
    """Returns (doc, canonical_bytes, digest). Callers must persist and serve
    `canonical_bytes` verbatim -- never `doc` re-serialized.
    """
    doc = {"vouch": SNAPSHOT_TYPE, "publisher": publisher, "artifacts": artifacts}
    canonical = canonicalize(doc)
    return doc, canonical, b3_hex(canonical)


def verify_snapshot(data: bytes, *, expected_digest: str) -> dict:
    """V5. Returns the parsed snapshot dict. Fail: DigestMismatchError(40)."""
    actual_digest = b3_hex(data)
    if actual_digest != expected_digest:
        raise DigestMismatchError(
            f"snapshot digest mismatch: expected {expected_digest}, got {actual_digest}",
            expected=expected_digest,
            actual=actual_digest,
        )

    try:
        parsed = json.loads(data)
        if canonicalize(parsed) != data:
            raise ValueError("snapshot bytes are not the canonical encoding of their own content")
        if not isinstance(parsed, dict):
            raise ValueError(f"snapshot document is not a JSON object: {type(parsed).__name__}")
        if parsed.get("vouch") != SNAPSHOT_TYPE:
            raise ValueError(f"unexpected snapshot document type: {parsed.get('vouch')!r}")
    except (ValueError, UnicodeDecodeError) as e:
        raise DigestMismatchError(
            f"snapshot bytes at digest {expected_digest} are malformed",
            expected=expected_digest,
            actual=actual_digest,
        ) from e

    return parsed
