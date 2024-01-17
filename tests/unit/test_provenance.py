import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch.dsse import sign
from vouch.errors import KeyRevokedError, ProvenanceInvalidError, SignatureError
from vouch.keys import key_id, public_bytes
from vouch.provenance import build_provenance, provenance_digest, sign_provenance, verify_provenance_envelope


def _fixture(**overrides):
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)

    kwargs = dict(
        name="bert-tiny",
        version="1.2.0",
        manifest_digest="b3:" + "7" * 64,
        materials=[
            {"role": "base-model", "ref": "acme-lab/bert-base@2.1.0", "digest": "b3:" + "5" * 64},
            {"role": "dataset", "ref": "acme-lab/sst5@1.4.2", "digest": "b3:" + "3" * 64},
        ],
        build={"kind": "finetune", "code": "git+https://github.com/acme/train@ab12cd3"},
    )
    kwargs.update(overrides)
    doc = build_provenance(**kwargs)
    digest = provenance_digest(doc)
    envelope = sign_provenance(doc, sk, kid)
    return doc, digest, envelope, kid, pub


def test_round_trip_success():
    doc, digest, envelope, kid, pub = _fixture()
    verified = verify_provenance_envelope(
        envelope, authorized_keys={kid: pub}, expected_digest=digest, subject_manifest_digest=doc["subject"]["digest"]
    )
    assert verified == doc


def test_rejects_wrong_expected_digest():
    doc, digest, envelope, kid, pub = _fixture()
    with pytest.raises(ProvenanceInvalidError):
        verify_provenance_envelope(
            envelope,
            authorized_keys={kid: pub},
            expected_digest="b3:" + "f" * 64,
            subject_manifest_digest=doc["subject"]["digest"],
        )


def test_rejects_subject_binding_mismatch():
    doc, digest, envelope, kid, pub = _fixture()
    with pytest.raises(ProvenanceInvalidError):
        verify_provenance_envelope(
            envelope, authorized_keys={kid: pub}, expected_digest=digest, subject_manifest_digest="b3:" + "0" * 64
        )


def test_rejects_revoked_signer():
    doc, digest, envelope, kid, pub = _fixture()
    with pytest.raises(KeyRevokedError):
        verify_provenance_envelope(
            envelope,
            authorized_keys={kid: pub},
            expected_digest=digest,
            subject_manifest_digest=doc["subject"]["digest"],
            revoked_keys=frozenset({kid}),
        )


def test_rejects_unauthorized_signer():
    doc, digest, envelope, kid, pub = _fixture()
    other_pub = public_bytes(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(SignatureError):
        verify_provenance_envelope(
            envelope,
            authorized_keys={"b3:" + "9" * 64: other_pub},
            expected_digest=digest,
            subject_manifest_digest=doc["subject"]["digest"],
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["subject"].__setitem__("digest", "b3:" + "0" * 64),
        lambda p: p["materials"][0].__setitem__("digest", "b3:" + "0" * 64),
        lambda p: p["materials"][0].__setitem__("ref", "acme-lab/an-entirely-different-model@9.9.9"),
        lambda p: p["materials"].append({"role": "dataset", "ref": "attacker/injected@1.0.0", "digest": "b3:" + "1" * 64}),
    ],
)
def test_t5a_mutating_any_field_of_a_signed_attestation_breaks_the_signature(mutate):
    # T5A-LINEAGE-FORGE: an attacker without the release key cannot fabricate
    # or alter a materials entry -- mutating ANY field of an otherwise-valid
    # signed envelope must break signature verification, since the
    # signature covers the whole canonical payload.
    doc, digest, envelope, kid, pub = _fixture()

    payload = json.loads(base64.b64decode(envelope["payload"]))
    mutate(payload)
    tampered = dict(envelope)
    tampered["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()

    with pytest.raises(SignatureError):
        verify_provenance_envelope(
            tampered, authorized_keys={kid: pub}, expected_digest=digest, subject_manifest_digest=doc["subject"]["digest"]
        )


def test_payload_that_is_not_a_json_object_is_rejected_cleanly():
    # M4: a validly-signed payload of `null`/a bare list/etc. must fail
    # closed with ProvenanceInvalidError, not crash with AttributeError.
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"null", sk, kid)
    with pytest.raises(ProvenanceInvalidError):
        verify_provenance_envelope(
            envelope, authorized_keys={kid: pub}, expected_digest="b3:" + "0" * 64, subject_manifest_digest="b3:" + "1" * 64
        )
