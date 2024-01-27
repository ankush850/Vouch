"""PBT-MANIFEST-MUTATE, per 03_SECURITY_AND_ACCESS.md section 4:

"for any valid signed manifest and any single-byte mutation of payload or
signature, verification fails."
"""

import base64
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, strategies as st

from vouch import store
from vouch.errors import DigestMismatchError, SignatureError
from vouch.keys import key_id, public_bytes
from vouch.manifest import build_manifest, manifest_digest, sign_manifest, verify_manifest_envelope


@pytest.fixture(scope="module")
def signed_fixture(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("pbt-manifest")
    home = tmp_path / "home"
    store.ensure_layout(home)
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.bin").write_bytes(b"a fixture worth mutating, repeatedly")

    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)

    m = build_manifest(
        src, home, publisher="b3:" + "a" * 64, name="bert-tiny", version="1.2.0", seq=1, artifact_type="model"
    )
    envelope = sign_manifest(m, sk, kid)
    digest = manifest_digest(m)
    return m, envelope, digest, {kid: pub}


def _verify(envelope, m, digest, authorized):
    return verify_manifest_envelope(
        envelope,
        authorized_keys=authorized,
        expected_digest=digest,
        publisher=m["publisher"],
        name=m["name"],
        version=m["version"],
    )


def test_unmutated_fixture_verifies(signed_fixture):
    m, envelope, digest, authorized = signed_fixture
    assert _verify(envelope, m, digest, authorized) == m


@given(target=st.sampled_from(["payload", "sig"]), data=st.data())
def test_single_byte_mutation_never_verifies(signed_fixture, target, data):
    m, envelope, digest, authorized = signed_fixture

    if target == "payload":
        raw = base64.b64decode(envelope["payload"])
    else:
        raw = base64.b64decode(envelope["signatures"][0]["sig"])

    idx = data.draw(st.integers(min_value=0, max_value=len(raw) - 1))
    original_byte = raw[idx]
    new_byte = data.draw(st.integers(min_value=0, max_value=255).filter(lambda b: b != original_byte))

    mutated_raw = bytearray(raw)
    mutated_raw[idx] = new_byte
    mutated_b64 = base64.b64encode(bytes(mutated_raw)).decode("ascii")

    mutated_envelope = copy.deepcopy(envelope)
    if target == "payload":
        mutated_envelope["payload"] = mutated_b64
    else:
        mutated_envelope["signatures"][0]["sig"] = mutated_b64

    with pytest.raises((SignatureError, DigestMismatchError)):
        _verify(mutated_envelope, m, digest, authorized)


@given(data=st.data())
def test_truncated_payload_never_verifies(signed_fixture, data):
    m, envelope, digest, authorized = signed_fixture
    raw = base64.b64decode(envelope["payload"])
    if len(raw) < 2:
        return
    cut = data.draw(st.integers(min_value=0, max_value=len(raw) - 1))

    mutated_envelope = copy.deepcopy(envelope)
    mutated_envelope["payload"] = base64.b64encode(raw[:cut]).decode("ascii")

    with pytest.raises((SignatureError, DigestMismatchError)):
        _verify(mutated_envelope, m, digest, authorized)
