"""The manifest: the signed statement "this artifact is exactly these bytes",
per 02_TECHNICAL_ARCHITECTURE.md section 3.3.

This is the core M1 deliverable. `verify_manifest_envelope` implements
check V6 from 03_SECURITY_AND_ACCESS.md section 6: signature under an
authorized key, canonical-form payload, digest match, embedded
publisher/name/version match against what was requested (so a compromised
resolution step can never remap a reference to a different, legitimately
signed manifest), a per-artifact rollback high-water mark (M2), and key
revocation (M3, D13: a revoked key's signature is rejected everywhere,
including on manifests that would otherwise verify).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import cas, dsse
from . import records as records_mod
from .canonical import canonicalize, is_canonical
from .chunking import CHUNK_SIZE, iter_chunks, compute_file_digest
from .errors import DigestMismatchError, InternalError, RollbackError, SignatureError
from .hashing import b3_hex
from .timeutil import utc_now_iso

MANIFEST_TYPE = "manifest/v1"


def _validate_relative_path(rel_posix: str) -> None:
    if not rel_posix or rel_posix.startswith("/"):
        raise InternalError(f"unsafe path in artifact: {rel_posix!r}")
    parts = rel_posix.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise InternalError(f"unsafe path in artifact: {rel_posix!r}")


def _iter_relative_files(source_dir: Path) -> list[str]:
    paths: list[str] = []
    for root, dirs, files in os.walk(source_dir):
        dirs.sort()
        for filename in sorted(files):
            abs_path = Path(root) / filename
            rel_posix = abs_path.relative_to(source_dir).as_posix()
            _validate_relative_path(rel_posix)
            paths.append(rel_posix)
    paths.sort()
    return paths


def build_manifest(
    source_dir: Path,
    home: Path,
    *,
    publisher: str,
    name: str,
    version: str,
    seq: int,
    artifact_type: str,
    created: str | None = None,
    records: str = records_mod.GRANULARITY_NONE,
) -> dict:
    """Chunk and hash every file under `source_dir`, writing each chunk into
    the CAS at `home`, and assemble the signed-manifest shape (unsigned).

    `records` (dataset-only, per D15/D11) builds a per-file record digest
    index at the given granularity for every `.jsonl` file; other file
    extensions are opaque and never contribute to `record_index`, even
    when `records` is non-'none'.
    """
    file_entries = []
    total_size = 0
    record_index: dict[str, list[str]] | None = None
    for rel_path in _iter_relative_files(source_dir):
        abs_path = source_dir / rel_path
        chunk_digests: list[str] = []
        size = 0
        for chunk in iter_chunks(abs_path):
            cas.write_verified(home, chunk.digest, chunk.data)
            chunk_digests.append(chunk.digest)
            size += len(chunk.data)
        file_digest = compute_file_digest(chunk_digests)
        file_entries.append(
            {
                "path": rel_path,
                "size": size,
                "chunk_size": CHUNK_SIZE,
                "chunks": chunk_digests,
                "digest": file_digest,
            }
        )
        total_size += size

        if artifact_type == "dataset" and records != records_mod.GRANULARITY_NONE and abs_path.suffix == ".jsonl":
            if record_index is None:
                record_index = {}
            record_index[rel_path] = records_mod.build_record_index(abs_path, records)

    return {
        "vouch": MANIFEST_TYPE,
        "publisher": publisher,
        "name": name,
        "version": version,
        "seq": seq,
        "type": artifact_type,
        "created": created or utc_now_iso(),
        "files": file_entries,
        "total_size": total_size,
        "record_index": record_index,
        "provenance": None,
    }


def manifest_digest(manifest: dict) -> str:
    return b3_hex(canonicalize(manifest))


def content_digest(manifest: dict) -> str:
    """The manifest's digest with `provenance` forced to null -- the stable
    identity a provenance attestation's `subject.digest` binds to.
    Independent of which (if any) attestation the manifest's own
    `provenance` field happens to point at, since that field's value would
    otherwise be circular with the manifest's own digest (the field can't
    name a digest computed over a payload that includes the field itself).
    """
    return b3_hex(canonicalize({**manifest, "provenance": None}))


def sign_manifest(manifest: dict, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    """Return a DSSE envelope over the manifest's canonical bytes."""
    return dsse.sign(canonicalize(manifest), private_key, key_id)


def verify_manifest_envelope(
    envelope: dict,
    *,
    authorized_keys: dict[str, bytes],
    expected_digest: str,
    publisher: str,
    name: str,
    version: str,
    min_seq: int = 0,
    revoked_keys: frozenset[str] = frozenset(),
) -> dict:
    """Implements V6, including (from M2) the per-artifact rollback
    sub-check: a manifest whose `seq` is below `min_seq`, the consumer's
    persisted high-water mark for this artifact, is rejected, and (from
    M3) revocation: a signature from a key in `revoked_keys` is rejected
    even if otherwise cryptographically valid (D13, fail closed). Returns
    the verified manifest dict on success.
    """
    payload = dsse.verify(envelope, authorized_keys, revoked_keys=revoked_keys)

    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as e:
        raise SignatureError("manifest payload is not valid JSON") from e
    if not isinstance(parsed, dict):
        raise SignatureError("manifest payload is not a JSON object")

    if not is_canonical(parsed, payload):
        # The signature is valid over these exact bytes, but the bytes are
        # not the canonical encoding of their own parsed content -- reject
        # rather than let a non-canonical signed payload compute a different
        # digest than every other verifier would derive for the same data.
        raise SignatureError("manifest payload is not canonical JSON")

    digest = b3_hex(payload)
    if digest != expected_digest:
        raise DigestMismatchError(
            f"manifest digest mismatch: expected {expected_digest}, got {digest}",
            expected=expected_digest,
            actual=digest,
        )

    if (
        parsed.get("publisher") != publisher
        or parsed.get("name") != name
        or parsed.get("version") != version
    ):
        raise SignatureError(
            "manifest publisher/name/version does not match the requested reference"
        )

    seq = parsed.get("seq", 0)
    if seq < min_seq:
        raise RollbackError(
            f"{name} seq {seq} is older than the previously seen seq {min_seq}",
            seen=min_seq,
            offered=seq,
        )

    return parsed
