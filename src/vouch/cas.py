"""Content-addressed object store.

Every object Vouch ever writes under `objects/` (a chunk, a manifest, a
root document) is bounded in size by protocol: chunks are exactly
CHUNK_SIZE (4 MiB) or shorter, and metadata documents are kilobytes. This is
what keeps `write_verified` at O(chunk size) memory as required by
01_PRD.md's performance criterion -- nothing in this codebase ever calls it
with a whole multi-gigabyte artifact's bytes at once; file assembly (V9)
concatenates already-verified chunk objects on disk instead.

`write_verified` is the single choke point through which bytes cross from
"received, unverified" to "on disk, trusted": it hashes first and only
writes to the final content-addressed path on a match. A digest mismatch
never touches the final path at all -- the bytes go to quarantine instead.
This function is both the V8 check (03_SECURITY_AND_ACCESS.md section 6) and
the target of the PBT-CHUNK-MUTATE property test.
"""

from __future__ import annotations

import os
from pathlib import Path

from .errors import DigestMismatchError
from .hashing import b3_hex
from .quarantine import quarantine
from .store import atomic_write_bytes, objects_dir


def object_path(home: Path, digest: str) -> Path:
    hex_part = digest.split(":", 1)[1] if ":" in digest else digest
    filename = digest.replace(":", "_") if os.name == "nt" else digest
    return objects_dir(home) / hex_part[:2] / filename


def has_object(home: Path, digest: str) -> bool:
    return object_path(home, digest).exists()


def open_object(home: Path, digest: str) -> bytes:
    return object_path(home, digest).read_bytes()


def write_verified(home: Path, expected_digest: str, data: bytes, *, peer: str | None = None) -> Path:
    """Hash `data`; on a match with `expected_digest`, write it to the CAS and
    return its path. On mismatch, quarantine the bytes and raise
    DigestMismatchError -- the bytes never touch the final object path.
    """
    actual_digest = b3_hex(data)
    if actual_digest != expected_digest:
        qdir = quarantine(
            home,
            code=40,
            data=data,
            expected=expected_digest,
            actual=actual_digest,
            peer=peer,
            reason="chunk digest mismatch",
        )
        raise DigestMismatchError(
            f"digest mismatch: expected {expected_digest}, got {actual_digest}",
            evidence=qdir,
            expected=expected_digest,
            actual=actual_digest,
            peer=peer,
        )

    path = object_path(home, expected_digest)
    if not path.exists():
        atomic_write_bytes(path, data)
    return path
