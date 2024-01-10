"""Local storage layout, per 02_TECHNICAL_ARCHITECTURE.md section 8.

    <home>/
      config.toml
      trust/<publisher>/
      objects/<aa>/<digest>
      verified/<publisher>/<artifact>/<version>/
      quarantine/<timestamp>-<reason>/
      peers.json

No database; state is small JSON/TOML files written with atomic rename.
`<home>` is either the consumer's `~/.vouch` or an origin's `--store`
directory -- both share this same CAS-centric layout.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

DEFAULT_HOME_ENV = "VOUCH_HOME"


def default_home() -> Path:
    override = os.environ.get(DEFAULT_HOME_ENV)
    if override:
        return Path(override)
    return Path.home() / ".vouch"


def objects_dir(home: Path) -> Path:
    return home / "objects"


def trust_dir(home: Path) -> Path:
    return home / "trust"


def verified_dir(home: Path) -> Path:
    return home / "verified"


def quarantine_dir(home: Path) -> Path:
    return home / "quarantine"


def peers_path(home: Path) -> Path:
    return home / "peers.json"


def ensure_layout(home: Path) -> None:
    for d in (objects_dir(home), trust_dir(home), verified_dir(home), quarantine_dir(home)):
        d.mkdir(parents=True, exist_ok=True)
    (objects_dir(home) / ".tmp").mkdir(parents=True, exist_ok=True)


import threading
import time

_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _get_thread_lock(key: str) -> threading.Lock:
    with _THREAD_LOCKS_GUARD:
        if key not in _THREAD_LOCKS:
            _THREAD_LOCKS[key] = threading.Lock()
        return _THREAD_LOCKS[key]


def _long_path(p: Path | str) -> str:
    s = str(Path(p).resolve())
    if os.name == "nt" and not s.startswith("\\\\?\\") and not s.startswith("\\\\"):
        return "\\\\?\\" + s
    return s


def _long_path_obj(p: Path | str) -> Path:
    return Path(_long_path(p))


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    """Write `data` to `path` via a temp file + atomic rename in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_dir = _long_path(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=parent_dir, prefix=".tmp-")
    try:
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.chmod(tmp_name, mode)
        target_path = _long_path(path)
        source_path = _long_path(tmp_name)
        for attempt in range(10):
            try:
                os.replace(source_path, target_path)
                break
            except PermissionError:
                if attempt == 9 or os.name != "nt":
                    raise
                time.sleep(0.01 * (attempt + 1))
    except BaseException:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


def atomic_write_json(path: Path, obj, *, mode: int = 0o644) -> None:
    atomic_write_bytes(path, json.dumps(obj, indent=2, sort_keys=True).encode() + b"\n", mode=mode)


def read_json(path: Path):
    with open(_long_path(path), "rb") as f:
        return json.loads(f.read())


@contextlib.contextmanager
def locked(path: Path):
    """Hold an exclusive advisory lock on a `.lock` file next to `path` for
    the duration of the context. Protects a read-modify-write sequence
    (e.g. monotonic seq counter allocation) against two processes/threads racing
    on the same file -- without this, two concurrent `publish` invocations
    against the same origin store could allocate the same seq number
    twice, silently breaking the uniqueness the rollback high-water marks
    depend on. POSIX fcntl + cross-thread locking.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / f".{path.name}.lock"
    tlock = _get_thread_lock(str(lock_path.resolve()))
    with tlock:
        with open(lock_path, "a+") as f:
            if fcntl is not None:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            else:
                yield
