import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch.dsse import PAYLOAD_TYPE, add_signature, pae, sign, verify, verify_threshold
from vouch.errors import KeyRevokedError, SignatureError
from vouch.keys import key_id, public_bytes


def test_pae_byte_exactness():
    result = pae("application/vnd.vouch.v1+json", b"hello")
    expected = b"DSSEv1 29 application/vnd.vouch.v1+json 5 hello"
    assert result == expected


def test_pae_empty_body():
    result = pae("t", b"")
    assert result == b"DSSEv1 1 t 0 "


def test_sign_and_verify_round_trip():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)

    payload = b'{"hello":"world"}'
    envelope = sign(payload, sk, kid)
    assert envelope["payloadType"] == PAYLOAD_TYPE
    assert envelope["signatures"][0]["keyid"] == kid

    recovered = verify(envelope, {kid: pub})
    assert recovered == payload


def test_verify_rejects_unauthorized_key():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"payload", sk, kid)

    other_pub = public_bytes(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(SignatureError):
        verify(envelope, {"b3:someoneelse": other_pub})


def test_verify_rejects_tampered_payload():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b'{"a":1}', sk, kid)

    import base64

    tampered = dict(envelope)
    tampered["payload"] = base64.b64encode(b'{"a":2}').decode()
    with pytest.raises(SignatureError):
        verify(tampered, {kid: pub})


def test_verify_rejects_tampered_signature():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"payload", sk, kid)

    import base64

    bad_sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    bad_sig[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(bad_sig)).decode()

    with pytest.raises(SignatureError):
        verify(envelope, {kid: pub})


def test_verify_rejects_malformed_envelope():
    with pytest.raises(SignatureError):
        verify({}, {})
    with pytest.raises(SignatureError):
        verify({"payloadType": "t", "payload": "not-base64!!", "signatures": [{"keyid": "x", "sig": "eA=="}]}, {"x": b"\x00" * 32})
    with pytest.raises(SignatureError):
        verify({"payloadType": "t", "payload": "aGk=", "signatures": []}, {})


def test_verify_raises_key_revoked_when_only_valid_signer_is_revoked():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"payload", sk, kid)

    with pytest.raises(KeyRevokedError):
        verify(envelope, {kid: pub}, revoked_keys=frozenset({kid}))


def test_verify_succeeds_when_revoked_key_is_not_the_signer():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"payload", sk, kid)

    other_kid = "b3:" + "f" * 64
    assert verify(envelope, {kid: pub}, revoked_keys=frozenset({other_kid})) == b"payload"


def test_verify_threshold_two_of_two_succeeds():
    sk1 = Ed25519PrivateKey.generate()
    pub1 = public_bytes(sk1.public_key())
    kid1 = key_id(pub1)
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    envelope = sign(b"root doc bytes", sk1, kid1)
    envelope = add_signature(envelope, sk2, kid2)

    payload = verify_threshold(envelope, {kid1: pub1, kid2: pub2}, 2)
    assert payload == b"root doc bytes"


def test_verify_threshold_one_of_two_signatures_present_fails():
    sk1 = Ed25519PrivateKey.generate()
    pub1 = public_bytes(sk1.public_key())
    kid1 = key_id(pub1)
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    envelope = sign(b"root doc bytes", sk1, kid1)  # only signed by sk1

    with pytest.raises(SignatureError):
        verify_threshold(envelope, {kid1: pub1, kid2: pub2}, 2)


def test_verify_threshold_ignores_revoked_signer_when_counting():
    sk1 = Ed25519PrivateKey.generate()
    pub1 = public_bytes(sk1.public_key())
    kid1 = key_id(pub1)
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    envelope = sign(b"root doc bytes", sk1, kid1)
    envelope = add_signature(envelope, sk2, kid2)

    # kid1 is revoked -- even though both signatures are cryptographically
    # valid, only kid2 counts toward the threshold.
    with pytest.raises(KeyRevokedError):
        verify_threshold(envelope, {kid1: pub1, kid2: pub2}, 2, revoked_keys=frozenset({kid1}))

    # A lower threshold that the single remaining non-revoked signer satisfies still succeeds.
    payload = verify_threshold(envelope, {kid1: pub1, kid2: pub2}, 1, revoked_keys=frozenset({kid1}))
    assert payload == b"root doc bytes"


def test_verify_threshold_duplicate_signatures_from_same_key_do_not_double_count():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)

    envelope = sign(b"payload", sk, kid)
    envelope = add_signature(envelope, sk, kid)  # same key signs twice

    with pytest.raises(SignatureError):
        verify_threshold(envelope, {kid: pub}, 2)


def test_verify_rejects_unhashable_keyid_without_crashing():
    # M4: found by parser fuzzing at a deeper example budget -- a
    # signature entry's `keyid` is attacker-controlled and can be any
    # JSON value, including an unhashable one (a list, a dict), which
    # would otherwise crash the `keyid not in authorized_keys` lookup
    # itself with a bare TypeError instead of failing closed.
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": sign(b"payload", sk, kid)["payload"],
        "signatures": [{"keyid": ["not", "hashable"], "sig": "AAAA"}],
    }
    with pytest.raises(SignatureError):
        verify(envelope, {kid: pub})
