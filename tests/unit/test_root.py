import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch.dsse import add_signature
from vouch.errors import KeyRevokedError, PinMismatchError, RollbackError, SignatureError
from vouch.keys import key_id, public_bytes
from vouch.root import (
    authorized_keys_for_role,
    build_root_doc,
    revoked_key_ids,
    sign_root_doc,
    verify_root_chain,
    verify_root_doc,
    verify_root_genesis,
    verify_root_link,
)


def _root_fixture(**overrides):
    root_sk = Ed25519PrivateKey.generate()
    root_pub = public_bytes(root_sk.public_key())
    root_kid = key_id(root_pub)

    release_sk = Ed25519PrivateKey.generate()
    release_pub = public_bytes(release_sk.public_key())
    release_kid = key_id(release_pub)

    doc = build_root_doc(
        publisher=root_kid,
        root_keys=[(root_kid, root_pub)],
        release_keys=[(release_kid, release_pub)],
        **overrides,
    )
    envelope = sign_root_doc(doc, root_sk, root_kid)
    return doc, envelope, root_kid, root_sk, release_kid, release_pub


def test_verify_root_doc_success():
    doc, envelope, root_kid, _, release_kid, release_pub = _root_fixture()
    verified = verify_root_doc(envelope, pinned_fingerprint=root_kid)
    assert verified == doc
    authorized = authorized_keys_for_role(verified, "release")
    assert authorized == {release_kid: release_pub}


def test_verify_root_doc_rejects_fingerprint_mismatch_before_signature_check():
    # T4A: a lookalike publisher signs with an entirely different key.
    _, envelope, root_kid, _, _, _ = _root_fixture()
    wrong_fingerprint = "b3:" + "0" * 64
    with pytest.raises(PinMismatchError):
        verify_root_doc(envelope, pinned_fingerprint=wrong_fingerprint)


def test_verify_root_doc_rejects_corrupted_self_signature():
    doc, envelope, root_kid, _, _, _ = _root_fixture()
    import base64

    bad_sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    bad_sig[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(bad_sig)).decode()

    with pytest.raises(SignatureError):
        verify_root_doc(envelope, pinned_fingerprint=root_kid)


def test_verify_root_doc_rejects_expired():
    doc, envelope, root_kid, _, _, _ = _root_fixture(expires="2000-01-01T00:00:00Z")
    with pytest.raises(SignatureError):
        verify_root_doc(envelope, pinned_fingerprint=root_kid)


def test_verify_root_doc_rejects_malformed_envelope():
    with pytest.raises(SignatureError):
        verify_root_doc({}, pinned_fingerprint="b3:" + "0" * 64)
    with pytest.raises(SignatureError):
        verify_root_doc({"payload": "not-base64!!"}, pinned_fingerprint="b3:" + "0" * 64)


def test_authorized_keys_for_role_empty_when_no_keys():
    doc, envelope, root_kid, _, _, _ = _root_fixture()
    verified = verify_root_doc(envelope, pinned_fingerprint=root_kid)
    assert authorized_keys_for_role(verified, "timestamp") == {}


def test_verify_root_doc_accepts_version_at_or_above_min_version():
    doc, envelope, root_kid, _, _, _ = _root_fixture(root_version=3)
    assert verify_root_doc(envelope, pinned_fingerprint=root_kid, min_version=3) == doc
    assert verify_root_doc(envelope, pinned_fingerprint=root_kid, min_version=1) == doc


def test_verify_root_doc_rejects_version_below_min_version():
    doc, envelope, root_kid, _, _, _ = _root_fixture(root_version=2)
    with pytest.raises(RollbackError):
        verify_root_doc(envelope, pinned_fingerprint=root_kid, min_version=3)


# --- verify_root_genesis ---------------------------------------------------


def test_verify_root_genesis_success():
    doc, envelope, root_kid, _, _, _ = _root_fixture()
    assert verify_root_genesis(envelope, pinned_fingerprint=root_kid) == doc


def test_verify_root_genesis_rejects_mislabeled_key_entry():
    # T4A, closing the specific gap caught while writing this test: an
    # attacker crafts a root document with an entry claiming `"id"` equal
    # to the VICTIM's fingerprint but supplying the ATTACKER's own public
    # key bytes, then self-signs with their own key. If the id/pub pair
    # were trusted as declared, this would pass -- the fix is that a key
    # id must equal b3_hex(its own pub), checked independently of what the
    # document merely claims.
    victim_sk = Ed25519PrivateKey.generate()
    victim_pub = public_bytes(victim_sk.public_key())
    victim_kid = key_id(victim_pub)

    attacker_sk = Ed25519PrivateKey.generate()
    attacker_pub = public_bytes(attacker_sk.public_key())
    attacker_kid = key_id(attacker_pub)

    forged_doc = build_root_doc(publisher=victim_kid, root_keys=[(attacker_kid, attacker_pub)])
    # Mislabel the key entry's id as the victim's fingerprint.
    forged_doc["keys"]["root"][0]["id"] = victim_kid
    forged_envelope = sign_root_doc(forged_doc, attacker_sk, victim_kid)  # signed under the forged label

    with pytest.raises(PinMismatchError):
        verify_root_genesis(forged_envelope, pinned_fingerprint=victim_kid)


# --- verify_root_link / verify_root_chain (T4B-ROTATION) -------------------


def _rotate(prev_doc, prev_sk, prev_kid, new_sk, new_pub, new_kid, **overrides):
    kwargs = dict(publisher=prev_doc["publisher"], root_keys=[(new_kid, new_pub)], root_version=prev_doc["root_version"] + 1)
    kwargs.update(overrides)
    next_doc = build_root_doc(**kwargs)
    envelope = sign_root_doc(next_doc, new_sk, new_kid)  # satisfies next's own threshold
    envelope = add_signature(envelope, prev_sk, prev_kid)  # cross-signs against prev's threshold
    return next_doc, envelope


def test_verify_root_link_accepts_correctly_cross_signed_rotation():
    doc1, _, kid1, sk1, _, _ = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    doc2, envelope2 = _rotate(doc1, sk1, kid1, sk2, pub2, kid2)
    assert verify_root_link(doc1, envelope2) == doc2


def test_verify_root_link_rejects_missing_cross_signature():
    doc1, _, kid1, sk1, _, _ = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    # Self-signed by the NEW key only -- no signature from prev's key.
    doc2 = build_root_doc(publisher=doc1["publisher"], root_keys=[(kid2, pub2)], root_version=2)
    envelope2 = sign_root_doc(doc2, sk2, kid2)

    with pytest.raises(SignatureError):
        verify_root_link(doc1, envelope2)


def test_verify_root_link_rejects_skipped_version():
    doc1, _, kid1, sk1, _, _ = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    doc2, envelope2 = _rotate(doc1, sk1, kid1, sk2, pub2, kid2, root_version=doc1["root_version"] + 2)
    with pytest.raises(RollbackError):
        verify_root_link(doc1, envelope2)


def test_verify_root_link_rejects_publisher_identity_change():
    doc1, _, kid1, sk1, _, _ = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    other_publisher = "b3:" + "9" * 64
    next_doc = build_root_doc(publisher=other_publisher, root_keys=[(kid2, pub2)], root_version=2)
    envelope = sign_root_doc(next_doc, sk2, kid2)
    envelope = add_signature(envelope, sk1, kid1)

    with pytest.raises(PinMismatchError):
        verify_root_link(doc1, envelope)


def test_verify_root_chain_walks_multiple_hops():
    doc1, envelope1, kid1, sk1, _, _ = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)
    doc2, envelope2 = _rotate(doc1, sk1, kid1, sk2, pub2, kid2)

    sk3 = Ed25519PrivateKey.generate()
    pub3 = public_bytes(sk3.public_key())
    kid3 = key_id(pub3)
    doc3, envelope3 = _rotate(doc2, sk2, kid2, sk3, pub3, kid3)

    final_doc, revoked = verify_root_chain([envelope1, envelope2, envelope3], pinned_fingerprint=kid1)
    assert final_doc == doc3
    assert revoked == frozenset()


def test_verify_root_chain_rejects_result_older_than_min_version():
    doc1, envelope1, kid1, sk1, _, _ = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)
    doc2, envelope2 = _rotate(doc1, sk1, kid1, sk2, pub2, kid2)

    with pytest.raises(RollbackError):
        verify_root_chain([envelope1, envelope2], pinned_fingerprint=kid1, min_version=5)


# --- revocation (T4C-REVOCATION) --------------------------------------------


def test_revoked_key_ids_extraction():
    doc, _, _, _, _, _ = _root_fixture()
    assert revoked_key_ids(doc) == frozenset()

    doc["revoked"] = [{"id": "b3:" + "a" * 64, "at": "2026-01-01T00:00:00Z", "reason": "compromise"}]
    assert revoked_key_ids(doc) == frozenset({"b3:" + "a" * 64})


def test_verify_root_chain_accumulates_revoked_keys_across_hops():
    doc1, envelope1, kid1, sk1, release_kid, release_pub = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    # v2 revokes v1's root key (a routine "we rotated away from it" cleanup).
    doc2, envelope2 = _rotate(doc1, sk1, kid1, sk2, pub2, kid2, revoked=[{"id": kid1, "at": "2026-01-01T00:00:00Z", "reason": "rotated"}])

    final_doc, revoked = verify_root_chain([envelope1, envelope2], pinned_fingerprint=kid1)
    assert final_doc == doc2
    assert kid1 in revoked


def test_revocation_does_not_retroactively_invalidate_the_rotation_that_used_the_revoked_key():
    # The key being revoked in v2 is THE SAME key that cross-signed the
    # v1->v2 rotation -- this must still succeed (a root must be able to
    # revoke a key it just used one last time to rotate away from it).
    doc1, envelope1, kid1, sk1, _, _ = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    doc2, envelope2 = _rotate(
        doc1, sk1, kid1, sk2, pub2, kid2,
        revoked=[{"id": kid1, "at": "2026-01-01T00:00:00Z", "reason": "rotated"}],
    )
    final_doc, revoked = verify_root_chain([envelope1, envelope2], pinned_fingerprint=kid1)
    assert final_doc == doc2
    assert revoked == frozenset({kid1})


def test_revoked_key_cannot_authorize_a_further_rotation():
    # v2 keeps v1's key listed (threshold=1, e.g. mid-transition) but marks
    # it revoked, alongside a new key. A v2->v3 rotation cross-signed using
    # ONLY the revoked key (still cryptographically valid, still "listed")
    # must fail specifically as a revocation, not silently succeed just
    # because the key is still present in v2's keys.root.
    doc1, envelope1, kid1, sk1, _, _ = _root_fixture()
    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)

    doc2 = build_root_doc(
        publisher=doc1["publisher"],
        root_keys=[(kid1, public_bytes(sk1.public_key())), (kid2, pub2)],
        root_version=2,
        revoked=[{"id": kid1, "at": "2026-01-01T00:00:00Z", "reason": "compromise"}],
    )
    envelope2 = sign_root_doc(doc2, sk2, kid2)
    envelope2 = add_signature(envelope2, sk1, kid1)

    sk3 = Ed25519PrivateKey.generate()
    pub3 = public_bytes(sk3.public_key())
    kid3 = key_id(pub3)
    doc3 = build_root_doc(publisher=doc1["publisher"], root_keys=[(kid3, pub3)], root_version=3)
    envelope3 = sign_root_doc(doc3, sk3, kid3)
    envelope3 = add_signature(envelope3, sk1, kid1)  # only the revoked key cross-signs

    with pytest.raises(KeyRevokedError):
        verify_root_chain([envelope1, envelope2, envelope3], pinned_fingerprint=kid1)
