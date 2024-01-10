import pytest

from vouch import store
from vouch.cas import has_object, object_path, open_object, write_verified
from vouch.errors import DigestMismatchError
from vouch.hashing import b3_hex


@pytest.fixture
def home(tmp_path):
    store.ensure_layout(tmp_path)
    return tmp_path


def test_write_verified_success_roundtrip(home):
    data = b"the quick brown fox"
    digest = b3_hex(data)
    path = write_verified(home, digest, data)
    assert path.exists()
    assert path == object_path(home, digest)
    assert has_object(home, digest)
    assert open_object(home, digest) == data


def test_object_path_shards_by_first_two_hex_chars(home):
    data = b"shard-me"
    digest = b3_hex(data)
    path = object_path(home, digest)
    assert path.parent.name == digest.split(":", 1)[1][:2]
    assert path.name in (digest, digest.replace(":", "_"))


def test_write_verified_is_idempotent(home):
    data = b"same bytes twice"
    digest = b3_hex(data)
    p1 = write_verified(home, digest, data)
    p2 = write_verified(home, digest, data)
    assert p1 == p2
    assert open_object(home, digest) == data


def test_write_verified_rejects_mismatch_and_quarantines(home):
    data = b"real bytes"
    wrong_digest = b3_hex(b"different bytes")

    with pytest.raises(DigestMismatchError) as exc_info:
        write_verified(home, wrong_digest, data)

    err = exc_info.value
    assert err.exit_code == 40
    assert not has_object(home, wrong_digest)
    assert not object_path(home, wrong_digest).exists()

    # Evidence lands in quarantine, never at the trusted CAS path.
    qdir = err.evidence
    assert qdir is not None and qdir.is_dir()
    assert (qdir / "bytes.bin").read_bytes() == data
    report = store.read_json(qdir / "report.json")
    assert report["exit_code"] == 40
    assert report["expected_digest"] == wrong_digest
    assert report["actual_digest"] == b3_hex(data)


def test_no_partial_object_on_atomic_write_failure(home, monkeypatch):
    data = b"boom"
    digest = b3_hex(data)

    def failing_fdopen(*args, **kwargs):
        raise OSError("simulated mid-write failure")

    monkeypatch.setattr("vouch.store.os.fdopen", failing_fdopen)

    with pytest.raises(OSError):
        write_verified(home, digest, data)

    # No partial file at the final path, and no leftover temp files.
    final_path = object_path(home, digest)
    assert not final_path.exists()
    tmp_leftovers = list(final_path.parent.glob(".tmp-*")) if final_path.parent.exists() else []
    assert tmp_leftovers == []


def test_atomic_write_bytes_cleans_up_tmp_on_failure(home, monkeypatch):
    target = home / "somefile.bin"

    def failing_fdopen(*args, **kwargs):
        raise OSError("simulated failure")

    monkeypatch.setattr("vouch.store.os.fdopen", failing_fdopen)

    with pytest.raises(OSError):
        store.atomic_write_bytes(target, b"data")

    assert not target.exists()
    assert list(home.glob(".tmp-*")) == []
