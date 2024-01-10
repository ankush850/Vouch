"""On-disk layout for an origin's published state, layered on top of the
shared CAS (`store.py`/`cas.py`).

Chunks are content-addressed and therefore publisher-agnostic, living in the
shared `objects/` tree. Manifest envelopes are served by
`GET /v1/manifest/{digest}` with no publisher segment in the route
(02_TECHNICAL_ARCHITECTURE.md section 6.1), so they are stored flat, keyed
only by the manifest digest -- any publisher's manifest is reachable by its
digest alone, matching the route exactly. Root documents, the timestamp,
and the snapshot ARE namespaced by publisher (the root key fingerprint,
since there is no naming authority per section 2) because their routes
carry a `{publisher}` segment.

`current_pointer_path`/`write_current_pointer`/`read_current_pointer` are
the on-disk bookkeeping `publish` writes for every release (per-artifact
"what does this version's manifest digest look like"). In M1 these were
also served directly over HTTP as a trust-free resolution bridge; from M2
that HTTP route is gone (superseded by the signed snapshot) and this data
is purely internal input for `origin reissue-timestamp` to enumerate when
building a snapshot -- see `list_artifacts`/`list_versions`.

Snapshot bytes are written and read RAW (`atomic_write_bytes`/
`.read_bytes()`), never through `atomic_write_json`/`read_json`, per the
byte-exactness requirement in `snapshot.py`'s docstring: re-serializing
through `json.dumps` would silently change the bytes a digest was computed
over.

The transparency log (M3) is stored as a single atomic JSON array
(`log/leaves.json`) plus the latest checkpoint (`log/checkpoint.json`) and
a per-tree-size checkpoint history (`log/checkpoint/<size>.json`) --
`append_log_leaf` is lock-protected exactly like `next_seq`/
`next_timestamp_seq`, since allocating the next leaf index and re-signing
the checkpoint must be atomic against a concurrent publish/rotate/revoke.
This is a deliberate simplification from the architecture doc's framing of
log leaves as individually content-addressed objects that mirrors
replicate automatically like any other content (DECISIONS.md, log storage
decision): a single JSON array is simpler and matches D9's "inspectable
JSON over cleverness" philosophy, at the cost of `mirror sync` needing an
explicit added step to pull the log rather than getting it "for free" the
way it walks chunks.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from . import log as log_mod
from .errors import InternalError
from .hashing import is_valid_digest
from .store import (
    _long_path,
    _long_path_obj,
    atomic_write_bytes,
    atomic_write_json,
    locked,
    read_json,
)


def validate_path_component(value: str, field: str) -> None:
    if not value or "/" in value or "\\" in value or value in (".", ".."):
        raise InternalError(f"unsafe {field}: {value!r}")


def manifests_dir(store: Path) -> Path:
    return store / "manifests"


def manifest_envelope_path(store: Path, digest: str) -> Path:
    if not is_valid_digest(digest):
        raise InternalError(f"not a valid digest: {digest!r}")
    fname = digest.replace(":", "_") if os.name == "nt" else digest
    return manifests_dir(store) / f"{fname}.json"


def publisher_dir(store: Path, fingerprint: str) -> Path:
    validate_path_component(fingerprint, "publisher fingerprint")
    safe_fp = fingerprint.replace(":", "_") if os.name == "nt" else fingerprint
    return store / "publisher" / safe_fp


def root_doc_path(store: Path, fingerprint: str, version: int) -> Path:
    return publisher_dir(store, fingerprint) / "root" / f"{int(version)}.json"


def current_pointer_path(store: Path, fingerprint: str, artifact: str, version: str) -> Path:
    validate_path_component(artifact, "artifact name")
    validate_path_component(version, "version")
    return publisher_dir(store, fingerprint) / "current" / artifact / f"{version}.json"


def seq_counter_path(store: Path, fingerprint: str, artifact: str) -> Path:
    validate_path_component(artifact, "artifact name")
    return publisher_dir(store, fingerprint) / "seq" / f"{artifact}.json"


def timestamp_path(store: Path, fingerprint: str) -> Path:
    return publisher_dir(store, fingerprint) / "timestamp.json"


def timestamp_seq_path(store: Path, fingerprint: str) -> Path:
    return publisher_dir(store, fingerprint) / "timestamp-seq.json"


def snapshot_path(store: Path, fingerprint: str, digest: str) -> Path:
    if not is_valid_digest(digest):
        raise InternalError(f"not a valid digest: {digest!r}")
    fname = digest.replace(":", "_") if os.name == "nt" else digest
    return publisher_dir(store, fingerprint) / "snapshot" / f"{fname}.json"


def current_dir(store: Path, fingerprint: str) -> Path:
    return publisher_dir(store, fingerprint) / "current"


def log_leaves_path(store: Path, fingerprint: str) -> Path:
    return publisher_dir(store, fingerprint) / "log" / "leaves.json"


def checkpoint_path(store: Path, fingerprint: str) -> Path:
    return publisher_dir(store, fingerprint) / "log" / "checkpoint.json"


def checkpoint_history_path(store: Path, fingerprint: str, tree_size: int) -> Path:
    return publisher_dir(store, fingerprint) / "log" / "checkpoint" / f"{int(tree_size)}.json"


def write_root_doc(store: Path, fingerprint: str, version: int, envelope: dict) -> None:
    atomic_write_json(root_doc_path(store, fingerprint, version), envelope)


def read_root_doc(store: Path, fingerprint: str, version: int) -> dict | None:
    path = _long_path_obj(root_doc_path(store, fingerprint, version))
    return read_json(path) if path.exists() else None


def write_manifest_envelope(store: Path, digest: str, envelope: dict) -> None:
    atomic_write_json(manifest_envelope_path(store, digest), envelope)


def read_manifest_envelope(store: Path, digest: str) -> dict | None:
    path = _long_path_obj(manifest_envelope_path(store, digest))
    return read_json(path) if path.exists() else None


def write_current_pointer(
    store: Path, fingerprint: str, artifact: str, version: str, digest: str, *, log_index: int | None = None
) -> None:
    atomic_write_json(
        current_pointer_path(store, fingerprint, artifact, version), {"digest": digest, "log_index": log_index}
    )


def read_current_pointer(store: Path, fingerprint: str, artifact: str, version: str) -> dict | None:
    path = _long_path_obj(current_pointer_path(store, fingerprint, artifact, version))
    return read_json(path) if path.exists() else None


def next_seq(store: Path, fingerprint: str, artifact: str) -> int:
    """Allocate and persist the next per-artifact monotonic seq number.
    Lock-protected: two concurrent `publish` invocations must never
    allocate the same seq twice.
    """
    path = _long_path_obj(seq_counter_path(store, fingerprint, artifact))
    with locked(path):
        current = read_json(path)["seq"] if path.exists() else 0
        new_seq = current + 1
        atomic_write_json(path, {"seq": new_seq})
        return new_seq


def write_timestamp(store: Path, fingerprint: str, envelope: dict) -> None:
    """DSSE-enveloped -- safe to round-trip through JSON like the root doc."""
    atomic_write_json(timestamp_path(store, fingerprint), envelope)


def read_timestamp(store: Path, fingerprint: str) -> dict | None:
    path = _long_path_obj(timestamp_path(store, fingerprint))
    return read_json(path) if path.exists() else None


def next_timestamp_seq(store: Path, fingerprint: str) -> int:
    """Allocate and persist the next publisher-wide monotonic timestamp seq.
    Lock-protected, same reasoning as `next_seq`.
    """
    path = _long_path_obj(timestamp_seq_path(store, fingerprint))
    with locked(path):
        current = read_json(path)["seq"] if path.exists() else 0
        new_seq = current + 1
        atomic_write_json(path, {"seq": new_seq})
        return new_seq


def write_snapshot(store: Path, fingerprint: str, digest: str, canonical_bytes: bytes) -> None:
    """Raw bytes, NOT JSON -- see module and snapshot.py docstrings."""
    atomic_write_bytes(snapshot_path(store, fingerprint, digest), canonical_bytes)


def read_snapshot_bytes(store: Path, fingerprint: str, digest: str) -> bytes | None:
    path = _long_path_obj(snapshot_path(store, fingerprint, digest))
    return path.read_bytes() if path.exists() else None


def list_artifacts(store: Path, fingerprint: str) -> list[str]:
    """Every artifact name this publisher has ever published under, from the
    `current/` bookkeeping `publish` writes. Used by `origin
    reissue-timestamp` to enumerate what belongs in a fresh snapshot.
    """
    base = _long_path_obj(current_dir(store, fingerprint))
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir())


def list_versions(store: Path, fingerprint: str, artifact: str) -> list[str]:
    validate_path_component(artifact, "artifact name")
    base = _long_path_obj(current_dir(store, fingerprint) / artifact)
    if not base.is_dir():
        return []
    return sorted(p.stem for p in base.iterdir() if p.is_file() and p.suffix == ".json")


def read_log_leaves(store: Path, fingerprint: str) -> list[dict]:
    path = _long_path_obj(log_leaves_path(store, fingerprint))
    return read_json(path) if path.exists() else []


def read_checkpoint(store: Path, fingerprint: str) -> dict | None:
    path = _long_path_obj(checkpoint_path(store, fingerprint))
    return read_json(path) if path.exists() else None


def read_checkpoint_at(store: Path, fingerprint: str, tree_size: int) -> dict | None:
    path = _long_path_obj(checkpoint_history_path(store, fingerprint, tree_size))
    return read_json(path) if path.exists() else None


def append_log_leaf(
    store: Path,
    fingerprint: str,
    *,
    event: str,
    digest: str,
    release_private_key,
    release_key_id: str,
) -> tuple[int, dict]:
    """Append a new leaf (the next tree index is assigned automatically) and
    re-sign a fresh checkpoint over the resulting tree. Lock-protected: the
    read-current-size + append + re-sign sequence must be atomic against a
    concurrent publish/rotate/revoke on the same store, same reasoning as
    `next_seq`. Returns (new_leaf_index, checkpoint_envelope).
    """
    leaves_path = log_leaves_path(store, fingerprint)
    with locked(leaves_path):
        existing = read_json(leaves_path) if leaves_path.exists() else []
        new_index = len(existing)
        leaf = log_mod.build_leaf(seq=new_index, event=event, digest=digest, publisher=fingerprint)
        existing.append(leaf)
        atomic_write_json(leaves_path, existing)

        hashes = [log_mod.leaf_hash(entry) for entry in existing]
        root_hash = log_mod.merkle_root(hashes)
        tree_size = len(existing)
        checkpoint = log_mod.build_checkpoint(publisher=fingerprint, tree_size=tree_size, root_hash=root_hash)
        checkpoint_envelope = log_mod.sign_checkpoint(checkpoint, release_private_key, release_key_id)

        atomic_write_json(checkpoint_path(store, fingerprint), checkpoint_envelope)
        atomic_write_json(checkpoint_history_path(store, fingerprint, tree_size), checkpoint_envelope)

    return new_index, checkpoint_envelope


def resign_checkpoint(store: Path, fingerprint: str, *, release_private_key, release_key_id: str) -> dict:
    """Re-sign the CURRENT checkpoint with a new release key, same
    tree_size/root_hash -- no new leaf. Used by `publish --resign-all`:
    without this, a checkpoint signed by a since-revoked release key would
    permanently strand V7 for every consumer until some unrelated future
    publish/rotate/revoke happened to refresh it, defeating the whole
    point of `--resign-all` as a recovery path.
    """
    leaves_path = log_leaves_path(store, fingerprint)
    with locked(leaves_path):
        current = read_checkpoint(store, fingerprint)
        if current is None:
            raise InternalError(f"no checkpoint to re-sign for {fingerprint}")
        payload = json.loads(base64.b64decode(current["payload"], validate=True))
        checkpoint_envelope = log_mod.sign_checkpoint(payload, release_private_key, release_key_id)
        atomic_write_json(checkpoint_path(store, fingerprint), checkpoint_envelope)
        atomic_write_json(checkpoint_history_path(store, fingerprint, payload["tree_size"]), checkpoint_envelope)
    return checkpoint_envelope
