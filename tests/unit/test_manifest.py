import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import store
from vouch.chunking import CHUNK_SIZE, compute_file_digest
from vouch.dsse import sign
from vouch.errors import DigestMismatchError, InternalError, KeyRevokedError, RollbackError, SignatureError
from vouch.hashing import b3_hex
from vouch.keys import key_id, public_bytes
from vouch.manifest import (
    _validate_relative_path,
    build_manifest,
    manifest_digest,
    sign_manifest,
    verify_manifest_envelope,
)


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "home"
    store.ensure_layout(home)
    return home


def test_build_manifest_single_small_file(tmp_path, home):
    src = tmp_path / "src"
    src.mkdir()
    (src / "weights.bin").write_bytes(b"tiny model bytes")

    m = build_manifest(
        src, home, publisher="b3:" + "0" * 64, name="bert-tiny", version="1.0.0", seq=1, artifact_type="model"
    )
    assert m["vouch"] == "manifest/v1"
    assert m["name"] == "bert-tiny"
    assert m["version"] == "1.0.0"
    assert m["seq"] == 1
    assert m["type"] == "model"
    assert m["provenance"] is None
    assert m["record_index"] is None
    assert len(m["files"]) == 1
    f = m["files"][0]
    assert f["path"] == "weights.bin"
    assert f["size"] == len(b"tiny model bytes")
    assert f["chunk_size"] == CHUNK_SIZE
    assert len(f["chunks"]) == 1
    assert f["digest"] == compute_file_digest(f["chunks"])
    assert m["total_size"] == f["size"]


def test_build_manifest_multi_chunk_file_and_writes_to_cas(tmp_path, home):
    src = tmp_path / "src"
    src.mkdir()
    data = b"a" * CHUNK_SIZE + b"b" * 12345
    (src / "big.bin").write_bytes(data)

    m = build_manifest(
        src, home, publisher="b3:" + "1" * 64, name="big", version="0.1.0", seq=1, artifact_type="dataset"
    )
    f = m["files"][0]
    assert len(f["chunks"]) == 2
    assert f["size"] == len(data)

    from vouch.cas import open_object

    assert open_object(home, f["chunks"][0]) == data[:CHUNK_SIZE]
    assert open_object(home, f["chunks"][1]) == data[CHUNK_SIZE:]


def test_build_manifest_multiple_files_sorted(tmp_path, home):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "b.txt").write_bytes(b"b")
    (src / "a.txt").write_bytes(b"a")
    (src / "sub" / "c.txt").write_bytes(b"c")

    m = build_manifest(
        src, home, publisher="b3:" + "2" * 64, name="n", version="1.0.0", seq=1, artifact_type="dataset"
    )
    assert [f["path"] for f in m["files"]] == ["a.txt", "b.txt", "sub/c.txt"]


def test_validate_relative_path_rejects_traversal_and_absolute():
    for bad in ["../evil", "a/../../evil", "/etc/passwd", "a//b", "a/./b", ""]:
        with pytest.raises(InternalError):
            _validate_relative_path(bad)
    _validate_relative_path("ok/path.txt")  # does not raise


def test_manifest_digest_deterministic_and_sensitive_to_mutation(tmp_path, home):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.bin").write_bytes(b"content")
    m = build_manifest(src, home, publisher="b3:" + "3" * 64, name="n", version="1.0.0", seq=1, artifact_type="model")

    d1 = manifest_digest(m)
    d2 = manifest_digest(dict(m))  # same content, different dict object
    assert d1 == d2

    mutated = dict(m)
    mutated["seq"] = m["seq"] + 1
    assert manifest_digest(mutated) != d1


def _signed_fixture(tmp_path, home, **overrides):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "f.bin").write_bytes(b"payload bytes for signing")

    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)

    kwargs = dict(publisher="b3:" + "4" * 64, name="bert-tiny", version="1.2.0", seq=1, artifact_type="model")
    kwargs.update(overrides)
    m = build_manifest(src, home, **kwargs)
    envelope = sign_manifest(m, sk, kid)
    digest = manifest_digest(m)
    return m, envelope, digest, {kid: pub}


def test_sign_and_verify_manifest_round_trip(tmp_path, home):
    m, envelope, digest, authorized = _signed_fixture(tmp_path, home)
    verified = verify_manifest_envelope(
        envelope,
        authorized_keys=authorized,
        expected_digest=digest,
        publisher=m["publisher"],
        name=m["name"],
        version=m["version"],
    )
    assert verified == m


def test_verify_manifest_rejects_wrong_expected_digest(tmp_path, home):
    m, envelope, digest, authorized = _signed_fixture(tmp_path, home)
    with pytest.raises(DigestMismatchError):
        verify_manifest_envelope(
            envelope,
            authorized_keys=authorized,
            expected_digest="b3:" + "f" * 64,
            publisher=m["publisher"],
            name=m["name"],
            version=m["version"],
        )


def test_verify_manifest_rejects_name_version_mismatch(tmp_path, home):
    m, envelope, digest, authorized = _signed_fixture(tmp_path, home)
    with pytest.raises(SignatureError):
        verify_manifest_envelope(
            envelope,
            authorized_keys=authorized,
            expected_digest=digest,
            publisher=m["publisher"],
            name="a-different-name",
            version=m["version"],
        )


def test_verify_manifest_rejects_unauthorized_signer(tmp_path, home):
    m, envelope, digest, _ = _signed_fixture(tmp_path, home)
    other_pub = public_bytes(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(SignatureError):
        verify_manifest_envelope(
            envelope,
            authorized_keys={"b3:" + "9" * 64: other_pub},
            expected_digest=digest,
            publisher=m["publisher"],
            name=m["name"],
            version=m["version"],
        )


def test_verify_manifest_accepts_seq_at_or_above_min_seq(tmp_path, home):
    m, envelope, digest, authorized = _signed_fixture(tmp_path, home, seq=5)
    verified = verify_manifest_envelope(
        envelope,
        authorized_keys=authorized,
        expected_digest=digest,
        publisher=m["publisher"],
        name=m["name"],
        version=m["version"],
        min_seq=5,
    )
    assert verified == m


def test_verify_manifest_rejects_seq_below_min_seq(tmp_path, home):
    m, envelope, digest, authorized = _signed_fixture(tmp_path, home, seq=2)
    with pytest.raises(RollbackError):
        verify_manifest_envelope(
            envelope,
            authorized_keys=authorized,
            expected_digest=digest,
            publisher=m["publisher"],
            name=m["name"],
            version=m["version"],
            min_seq=3,
        )


def test_verify_manifest_rejects_revoked_release_key(tmp_path, home):
    # T4C: a manifest that would otherwise verify fine is rejected once its
    # signer is in the revoked-key set -- no time-based carve-out (D13).
    m, envelope, digest, authorized = _signed_fixture(tmp_path, home)
    release_kid = next(iter(authorized))
    with pytest.raises(KeyRevokedError):
        verify_manifest_envelope(
            envelope,
            authorized_keys=authorized,
            expected_digest=digest,
            publisher=m["publisher"],
            name=m["name"],
            version=m["version"],
            revoked_keys=frozenset({release_kid}),
        )


def test_verify_manifest_accepts_when_a_different_key_is_revoked(tmp_path, home):
    m, envelope, digest, authorized = _signed_fixture(tmp_path, home)
    verified = verify_manifest_envelope(
        envelope,
        authorized_keys=authorized,
        expected_digest=digest,
        publisher=m["publisher"],
        name=m["name"],
        version=m["version"],
        revoked_keys=frozenset({"b3:" + "9" * 64}),
    )
    assert verified == m


def test_payload_that_is_not_a_json_object_is_rejected_cleanly():
    # M4: a validly-signed payload of `null`/a bare list/etc. must fail
    # closed with SignatureError, not crash with AttributeError on `.get()`.
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"42", sk, kid)
    with pytest.raises(SignatureError):
        verify_manifest_envelope(
            envelope,
            authorized_keys={kid: pub},
            expected_digest=b3_hex(b"42"),
            publisher="acme",
            name="x",
            version="1.0.0",
        )
