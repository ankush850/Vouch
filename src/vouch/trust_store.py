"""Local trust pins, per 02_TECHNICAL_ARCHITECTURE.md section 2 and section 8.

A human-friendly publisher name is a purely local alias for a pinned root
key fingerprint, created by `trust add` -- exactly like an SSH
`known_hosts` entry. There is no global naming authority; the pin is the
trust bootstrap and this module is where it lives on disk.

Also holds the consumer's rollback high-water marks (03_SECURITY_AND_ACCESS.md
section 4.2, section 6 V2/V4/V6): the root document version, the timestamp
seq (plus equivocation detection), and each artifact's manifest seq, all
persisted per pinned publisher in `state.json`. This is the consumer's
*acceptance floor* -- a separate concern from `originstore.next_seq`, which
is the *publisher's* seq-assignment authority at publish time; the two
share no code, only the number that flows from one into the other via
`min_seq`/`min_version` parameters at verification time.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .errors import LogFailureError, PinMismatchError, RollbackError
from .store import atomic_write_json, read_json, trust_dir


def pin_dir(home: Path, name: str) -> Path:
    return trust_dir(home) / name


def pin_path(home: Path, name: str) -> Path:
    return pin_dir(home, name) / "pin.json"


def root_cache_path(home: Path, name: str) -> Path:
    return pin_dir(home, name) / "root.json"


def manifest_cache_path(home: Path, name: str, artifact: str, version: str) -> Path:
    return pin_dir(home, name) / "manifests" / artifact / f"{version}.json"


def state_path(home: Path, name: str) -> Path:
    return pin_dir(home, name) / "state.json"


def add_pin(home: Path, name: str, fingerprint: str, mirrors: list[str] | None = None) -> dict:
    """Pin NAME to FINGERPRINT. If NAME was already pinned to a DIFFERENT
    fingerprint, this is re-pinning to a new identity -- the documented
    recovery from root key compromise (03_SECURITY_AND_ACCESS.md section
    5.6: "publish a new fingerprint... and ask consumers to re-pin").
    `state.json`'s rollback/equivocation high-water marks and the cached
    root/manifest envelopes are all keyed by NAME, not by fingerprint, so
    without clearing them here a re-pin would silently carry the OLD
    identity's high-water marks over and compare them against the NEW,
    unrelated publisher's genuinely fresh state -- a real bug caught while
    writing the M4 root-key-compromise drill: re-pinning to a brand-new
    publisher produced a false "equivocation" at the new publisher's own
    first-ever timestamp, because its seq happened to coincide with the
    old publisher's already-seen seq.
    """
    existing_path = pin_path(home, name)
    if existing_path.exists() and read_json(existing_path).get("fingerprint") != fingerprint:
        _clear_pin_state(home, name)

    doc = {
        "vouch": "pin/v1",
        "name": name,
        "fingerprint": fingerprint,
        "mirrors": list(mirrors or []),
    }
    atomic_write_json(pin_path(home, name), doc)
    return doc


def _clear_pin_state(home: Path, name: str) -> None:
    state_path(home, name).unlink(missing_ok=True)
    root_cache_path(home, name).unlink(missing_ok=True)
    manifests_dir = pin_dir(home, name) / "manifests"
    if manifests_dir.is_dir():
        shutil.rmtree(manifests_dir)


def load_pin(home: Path, name: str) -> dict:
    path = pin_path(home, name)
    if not path.exists():
        raise PinMismatchError(f'no pin for "{name}"', name=name)
    return read_json(path)


def has_pin(home: Path, name: str) -> bool:
    return pin_path(home, name).exists()


def cache_root_envelope(home: Path, name: str, envelope: dict) -> None:
    atomic_write_json(root_cache_path(home, name), envelope)


def load_cached_root_envelope(home: Path, name: str) -> dict | None:
    path = root_cache_path(home, name)
    if not path.exists():
        return None
    return read_json(path)


def cache_manifest(home: Path, name: str, artifact: str, version: str, digest: str, envelope: dict) -> None:
    """Cache a verified manifest envelope alongside the digest it was
    resolved to, so `verify` can run offline for a reference already
    fetched once (V6's digest check has nothing else to check the payload
    against otherwise).
    """
    atomic_write_json(manifest_cache_path(home, name, artifact, version), {"digest": digest, "envelope": envelope})


def load_cached_manifest(home: Path, name: str, artifact: str, version: str) -> dict | None:
    path = manifest_cache_path(home, name, artifact, version)
    if not path.exists():
        return None
    return read_json(path)


def _empty_state() -> dict:
    return {
        "vouch": "trust-state/v1",
        "root_version_hwm": 0,
        "timestamp": {"seq_hwm": 0, "last_envelope": None},
        "artifacts": {},
        "log_checkpoint": None,
    }


def _load_state(home: Path, name: str) -> dict:
    path = state_path(home, name)
    if not path.exists():
        return _empty_state()
    return read_json(path)


def get_root_version_hwm(home: Path, name: str) -> int:
    return _load_state(home, name)["root_version_hwm"]


def get_manifest_seq_hwm(home: Path, name: str, artifact: str) -> int:
    return _load_state(home, name)["artifacts"].get(artifact, {"seq_hwm": 0})["seq_hwm"]


def get_timestamp_seq_hwm(home: Path, name: str) -> int:
    return _load_state(home, name)["timestamp"]["seq_hwm"]


def get_log_checkpoint_hwm(home: Path, name: str) -> dict | None:
    """Returns `{"tree_size": int, "root_hash": str}` for the last checkpoint
    this consumer has verified for this publisher, or None if it has never
    fetched one. `.get(...)` (not direct indexing) since this field was
    added in M3 -- a `state.json` written by an earlier version won't have
    it yet.
    """
    return _load_state(home, name).get("log_checkpoint")


def _save_state(home: Path, name: str, state: dict) -> None:
    atomic_write_json(state_path(home, name), state)


def check_and_advance_root_version(home: Path, name: str, version: int) -> None:
    """V2's rollback sub-check: a root document version older than one
    already validated is rejected. Equal or newer versions advance (or
    no-op) the stored high-water mark.
    """
    state = _load_state(home, name)
    hwm = state["root_version_hwm"]
    if version < hwm:
        raise RollbackError(
            f"root version {version} is older than the previously seen version {hwm}",
            seen=hwm,
            offered=version,
        )
    if version > hwm:
        state["root_version_hwm"] = version
        _save_state(home, name, state)


def check_and_advance_manifest_seq(home: Path, name: str, artifact: str, seq: int) -> None:
    """V6's rollback sub-check: a manifest whose seq is below the stored
    per-artifact high-water mark is rejected.
    """
    state = _load_state(home, name)
    artifact_state = state["artifacts"].setdefault(artifact, {"seq_hwm": 0})
    hwm = artifact_state["seq_hwm"]
    if seq < hwm:
        raise RollbackError(
            f"{artifact} seq {seq} is older than the previously seen seq {hwm}",
            seen=hwm,
            offered=seq,
        )
    if seq > hwm:
        artifact_state["seq_hwm"] = seq
        _save_state(home, name, state)


def check_and_advance_timestamp_seq(home: Path, name: str, seq: int, envelope: dict) -> None:
    """V4's rollback/equivocation sub-check. `seq` below the stored
    high-water mark is rollback (31). `seq` equal to the high-water mark
    requires the envelope to be byte-identical (as a structured value) to
    the one already seen at that seq -- Ed25519 signing is deterministic,
    so two honest issuances of the same statement produce identical
    envelopes; a mismatch here means two different statements were issued
    under the same seq, i.e. equivocation (44). `seq` above the high-water
    mark advances it and remembers this envelope for future equality checks.
    """
    state = _load_state(home, name)
    ts_state = state["timestamp"]
    hwm = ts_state["seq_hwm"]

    if seq < hwm:
        raise RollbackError(
            f"timestamp seq {seq} is older than the previously seen seq {hwm}",
            seen=hwm,
            offered=seq,
        )
    if seq == hwm:
        if ts_state["last_envelope"] is not None and ts_state["last_envelope"] != envelope:
            raise LogFailureError(
                f"equivocation: two different timestamp statements seen for seq {seq}",
                seq=seq,
            )
        return

    ts_state["seq_hwm"] = seq
    ts_state["last_envelope"] = envelope
    _save_state(home, name, state)


def advance_log_checkpoint(home: Path, name: str, tree_size: int, root_hash: str) -> None:
    """Record the latest transparency-log checkpoint this consumer has
    verified for this publisher. Pure state storage -- verifying that the
    new checkpoint is a genuine consistency-preserving extension of the
    previously stored one (V7's "consistency proof connects the consumer's
    stored checkpoint to the current one") is `freshness.py`'s job, since
    it requires a network round-trip (fetching the proof) this module
    never does.
    """
    state = _load_state(home, name)
    state["log_checkpoint"] = {"tree_size": tree_size, "root_hash": root_hash}
    _save_state(home, name, state)
