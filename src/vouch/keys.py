"""Key generation and encrypted-at-rest storage, per
03_SECURITY_AND_ACCESS.md section 5.1-5.2.

Ed25519 for all roles (root, release, timestamp). A key ID is `b3:` over the
raw public key bytes. Private keys at rest are encrypted with a
passphrase-derived key (scrypt, parameters stored in the key file header);
no plaintext private key ever touches disk. Passphrases are read only via an
interactive prompt or an explicit file descriptor (`--passphrase-fd`) --
never argv or environment, so they never end up in `ps`, shell history, or
a CI log.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import UsageError
from .hashing import b3_hex
from .store import atomic_write_bytes, read_json

ROLES = ("root", "release", "timestamp")

# scrypt parameters: interactive-login-strength defaults (RFC 7914 recommendation).
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

_INVALID_ROLE = "role must be one of {!r}, got {{!r}}".format(ROLES)


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise UsageError(_INVALID_ROLE.format(role))


def public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def private_seed_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def key_id(pub: bytes) -> str:
    return b3_hex(pub)


def generate_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=SCRYPT_KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


@dataclass
class LoadedKey:
    role: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def key_id(self) -> str:
        return key_id(public_bytes(self.public_key))


def save_encrypted_key(path: Path, private_key: Ed25519PrivateKey, role: str, passphrase: str) -> str:
    """Write an encrypted private-key file (mode 0600). Returns the key ID."""
    _check_role(role)
    pub = public_bytes(private_key.public_key())
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    derived = _derive_key(passphrase, salt)
    ciphertext = AESGCM(derived).encrypt(nonce, private_seed_bytes(private_key), None)

    doc = {
        "vouch": "key/v1",
        "role": role,
        "keyid": key_id(pub),
        "public": _b64(pub),
        "kdf": "scrypt",
        "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }
    atomic_write_bytes(path, json.dumps(doc, indent=2, sort_keys=True).encode() + b"\n", mode=0o600)
    return doc["keyid"]


def load_encrypted_key(path: Path, passphrase: str) -> LoadedKey:
    doc = read_json(path)
    if doc.get("vouch") != "key/v1" or doc.get("kdf") != "scrypt":
        raise UsageError(f"{path}: not a recognized Vouch key file")

    params = doc["kdf_params"]
    salt = _b64d(params["salt"])
    derived = Scrypt(
        salt=salt, length=SCRYPT_KEY_LEN, n=params["n"], r=params["r"], p=params["p"]
    ).derive(passphrase.encode("utf-8"))

    nonce = _b64d(doc["nonce"])
    ciphertext = _b64d(doc["ciphertext"])
    try:
        seed = AESGCM(derived).decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise UsageError(f"{path}: failed to decrypt (wrong passphrase?)") from e

    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return LoadedKey(role=doc["role"], private_key=private_key, public_key=private_key.public_key())


def save_public_key(path: Path, public_key: Ed25519PublicKey, role: str) -> str:
    """Write a plain (unencrypted) public key file. Returns the key ID."""
    _check_role(role)
    pub = public_bytes(public_key)
    doc = {
        "vouch": "pubkey/v1",
        "role": role,
        "keyid": key_id(pub),
        "public": _b64(pub),
    }
    atomic_write_bytes(path, json.dumps(doc, indent=2, sort_keys=True).encode() + b"\n", mode=0o644)
    return doc["keyid"]


def load_public_key_file(path: Path) -> tuple[str, str, bytes]:
    """Returns (role, keyid, raw_public_bytes)."""
    doc = read_json(path)
    if doc.get("vouch") not in ("pubkey/v1", "key/v1"):
        raise UsageError(f"{path}: not a recognized Vouch public key file")
    pub = _b64d(doc["public"])
    return doc["role"], doc.get("keyid", key_id(pub)), pub


def read_passphrase(passphrase_fd: int | None, *, confirm: bool = False) -> str:
    """Read a passphrase from an explicit file descriptor, or interactively
    prompt. Never reads from argv or the environment.
    """
    if passphrase_fd is not None:
        with os.fdopen(passphrase_fd, "r") as f:
            return f.readline().rstrip("\n")

    passphrase = getpass.getpass("passphrase: ")
    if confirm:
        again = getpass.getpass("confirm passphrase: ")
        if passphrase != again:
            raise UsageError("passphrases did not match")
    return passphrase


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)
