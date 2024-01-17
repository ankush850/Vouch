"""Quarantine: evidence capture on verification failure.

Per 03_SECURITY_AND_ACCESS.md section 7: on any verification failure that
involved received bytes, the offending material moves to
`quarantine/<utc-timestamp>-<code>/` containing the bytes, the expected and
actual digests, the peer identity/URL, and a machine-readable `report.json`.
Quarantine is evidence, never input: nothing in this codebase ever reads
bytes back out of quarantine into a verification path.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .store import atomic_write_bytes, atomic_write_json, quarantine_dir


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")[:-3] + "Z"


def _new_quarantine_dir(home: Path, code: int) -> tuple[Path, str]:
    """Create a fresh, collision-free quarantine directory. Returns (path, timestamp)."""
    ts = _utc_timestamp()
    base = quarantine_dir(home) / f"{ts}-{code}"
    qdir = base
    suffix = 0
    while True:
        try:
            qdir.mkdir(parents=True, exist_ok=False)
            return qdir, ts
        except FileExistsError:
            suffix += 1
            qdir = Path(f"{base}-{suffix}")


def _write_report(qdir: Path, *, ts: str, code: int, reason: str, expected, actual, peer, size: int, extra: dict | None) -> None:
    report = {
        "vouch": "quarantine-report/v1",
        "timestamp": ts,
        "exit_code": code,
        "reason": reason,
        "expected_digest": expected,
        "actual_digest": actual,
        "peer": peer,
        "size": size,
    }
    if extra:
        report["extra"] = extra
    atomic_write_json(qdir / "report.json", report)


def quarantine(
    home: Path,
    *,
    code: int,
    data: bytes,
    expected: str | None,
    actual: str | None,
    peer: str | None = None,
    reason: str = "",
    extra: dict | None = None,
) -> Path:
    """Move failing in-memory bytes + evidence into a fresh quarantine
    directory. Returns the directory. Intended for single-object-sized
    payloads (a chunk, a manifest) -- see `quarantine_file` for streaming a
    whole local file without buffering it in memory.
    """
    qdir, ts = _new_quarantine_dir(home, code)
    atomic_write_bytes(qdir / "bytes.bin", data)
    _write_report(qdir, ts=ts, code=code, reason=reason, expected=expected, actual=actual, peer=peer, size=len(data), extra=extra)
    return qdir


def quarantine_file(
    home: Path,
    *,
    code: int,
    path: Path,
    expected: str | None,
    actual: str | None,
    peer: str | None = None,
    reason: str = "",
    extra: dict | None = None,
) -> Path:
    """Copy a local file (streamed, not buffered) into quarantine alongside
    evidence. Used by `verify_flow.py`, where the failing artifact may be
    arbitrarily large.
    """
    qdir, ts = _new_quarantine_dir(home, code)
    dest = qdir / "bytes.bin"
    with open(path, "rb") as src, open(dest, "wb") as dst:
        shutil.copyfileobj(src, dst)
    os.chmod(dest, 0o644)
    size = dest.stat().st_size
    _write_report(qdir, ts=ts, code=code, reason=reason, expected=expected, actual=actual, peer=peer, size=size, extra=extra)
    return qdir
