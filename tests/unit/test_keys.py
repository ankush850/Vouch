import inspect
import io
import os
import stat

import pytest

from vouch import keys
from vouch.errors import UsageError


def test_generate_and_save_load_round_trip(tmp_path):
    sk = keys.generate_keypair()
    path = tmp_path / "release.key"
    kid = keys.save_encrypted_key(path, sk, "release", "correct horse battery staple")

    loaded = keys.load_encrypted_key(path, "correct horse battery staple")
    assert loaded.role == "release"
    assert loaded.key_id == kid
    assert keys.public_bytes(loaded.public_key) == keys.public_bytes(sk.public_key())
    assert keys.private_seed_bytes(loaded.private_key) == keys.private_seed_bytes(sk)


def test_key_file_is_created_0600(tmp_path):
    sk = keys.generate_keypair()
    path = tmp_path / "root.key"
    keys.save_encrypted_key(path, sk, "root", "hunter2")
    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600


def test_load_encrypted_key_wrong_passphrase_fails(tmp_path):
    sk = keys.generate_keypair()
    path = tmp_path / "release.key"
    keys.save_encrypted_key(path, sk, "release", "right-passphrase")
    with pytest.raises(UsageError):
        keys.load_encrypted_key(path, "wrong-passphrase")


def test_save_encrypted_key_rejects_invalid_role(tmp_path):
    sk = keys.generate_keypair()
    with pytest.raises(UsageError):
        keys.save_encrypted_key(tmp_path / "x.key", sk, "not-a-role", "pw")


def test_key_id_matches_b3_of_public_bytes():
    sk = keys.generate_keypair()
    pub = keys.public_bytes(sk.public_key())
    from vouch.hashing import b3_hex

    assert keys.key_id(pub) == b3_hex(pub)


def test_public_key_file_round_trip(tmp_path):
    sk = keys.generate_keypair()
    path = tmp_path / "release.pub"
    kid = keys.save_public_key(path, sk.public_key(), "release")
    role, loaded_kid, pub = keys.load_public_key_file(path)
    assert role == "release"
    assert loaded_kid == kid
    assert pub == keys.public_bytes(sk.public_key())


def test_read_passphrase_from_fd_never_touches_argv_or_environ(monkeypatch):
    r, w = os.pipe()
    os.write(w, b"my-secret-passphrase\n")
    os.close(w)

    # Sanity: ensure the implementation isn't secretly reading argv/environ instead.
    monkeypatch.setattr("sys.argv", ["vouch", "keygen"])
    monkeypatch.delenv("VOUCH_PASSPHRASE", raising=False)

    passphrase = keys.read_passphrase(r)
    assert passphrase == "my-secret-passphrase"


def test_read_passphrase_confirm_mismatch_raises(monkeypatch):
    answers = iter(["first", "second"])
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: next(answers))
    with pytest.raises(UsageError):
        keys.read_passphrase(None, confirm=True)


def test_no_passphrase_read_from_argv_or_environ_in_source():
    # Static guard for the secrets-hygiene requirement (frontend spec section 4 /
    # security doc section 5.2): passphrase acquisition must never read
    # sys.argv or os.environ anywhere in keys.py.
    source = inspect.getsource(keys)
    assert "sys.argv" not in source
    assert "os.environ" not in source
    assert "os.getenv" not in source
