import base64
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch.dsse import sign
from vouch.errors import KeyRevokedError, SignatureError, StaleError
from vouch.keys import key_id, public_bytes
from vouch.timeutil import format_iso8601, utc_now
from vouch.timestamp import build_timestamp_statement, sign_timestamp, verify_timestamp_envelope


def _fixture(**overrides):
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    kwargs = dict(publisher="b3:" + "a" * 64, seq=1, snapshot_digest="b3:" + "b" * 64)
    kwargs.update(overrides)
    stmt = build_timestamp_statement(**kwargs)
    envelope = sign_timestamp(stmt, sk, kid)
    return stmt, envelope, kid, pub


def test_round_trip_success():
    stmt, envelope, kid, pub = _fixture()
    verified = verify_timestamp_envelope(envelope, authorized_keys={kid: pub}, publisher=stmt["publisher"])
    assert verified == stmt


def test_rejects_tampered_payload():
    stmt, envelope, kid, pub = _fixture()
    tampered = dict(envelope)
    payload = base64.b64decode(envelope["payload"])
    mutated = bytearray(payload)
    mutated[0] ^= 0xFF
    tampered["payload"] = base64.b64encode(bytes(mutated)).decode()
    with pytest.raises(SignatureError):
        verify_timestamp_envelope(tampered, authorized_keys={kid: pub}, publisher=stmt["publisher"])


def test_rejects_unauthorized_signer():
    stmt, envelope, kid, pub = _fixture()
    other_pub = public_bytes(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(SignatureError):
        verify_timestamp_envelope(envelope, authorized_keys={"b3:" + "9" * 64: other_pub}, publisher=stmt["publisher"])


def test_rejects_publisher_mismatch():
    stmt, envelope, kid, pub = _fixture()
    with pytest.raises(SignatureError):
        verify_timestamp_envelope(envelope, authorized_keys={kid: pub}, publisher="b3:" + "f" * 64)


def test_rejects_expired_timestamp():
    issued = format_iso8601(utc_now() - timedelta(days=2))
    stmt, envelope, kid, pub = _fixture(issued=issued, ttl=timedelta(hours=24))
    with pytest.raises(StaleError):
        verify_timestamp_envelope(envelope, authorized_keys={kid: pub}, publisher=stmt["publisher"])


def test_rejects_issued_too_far_in_future():
    issued = format_iso8601(utc_now() + timedelta(hours=1))
    stmt, envelope, kid, pub = _fixture(issued=issued)
    with pytest.raises(SignatureError):
        verify_timestamp_envelope(envelope, authorized_keys={kid: pub}, publisher=stmt["publisher"])


def test_tolerates_expiry_within_skew_window():
    issued = format_iso8601(utc_now() - timedelta(hours=24, minutes=5))
    stmt, envelope, kid, pub = _fixture(issued=issued, ttl=timedelta(hours=24))
    verified = verify_timestamp_envelope(envelope, authorized_keys={kid: pub}, publisher=stmt["publisher"])
    assert verified == stmt


def test_rejects_revoked_timestamp_key():
    stmt, envelope, kid, pub = _fixture()
    with pytest.raises(KeyRevokedError):
        verify_timestamp_envelope(
            envelope, authorized_keys={kid: pub}, publisher=stmt["publisher"], revoked_keys=frozenset({kid})
        )


def test_accepts_when_a_different_key_is_revoked():
    stmt, envelope, kid, pub = _fixture()
    verified = verify_timestamp_envelope(
        envelope,
        authorized_keys={kid: pub},
        publisher=stmt["publisher"],
        revoked_keys=frozenset({"b3:" + "9" * 64}),
    )
    assert verified == stmt


def test_payload_that_is_not_a_json_object_is_rejected_cleanly():
    # M4: a validly-signed payload of `null`/a bare list/etc. must fail
    # closed with SignatureError, not crash with AttributeError on `.get()`.
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"[1, 2, 3]", sk, kid)
    with pytest.raises(SignatureError):
        verify_timestamp_envelope(envelope, authorized_keys={kid: pub}, publisher="b3:" + "1" * 64)
