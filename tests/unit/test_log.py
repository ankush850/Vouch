import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch.dsse import sign
from vouch.errors import KeyRevokedError, LogFailureError, SignatureError
from vouch.hashing import b3_hex
from vouch.keys import key_id, public_bytes
from vouch.log import (
    EMPTY_TREE_HASH,
    build_checkpoint,
    build_leaf,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    sign_checkpoint,
    verify_checkpoint_envelope,
    verify_consistency,
    verify_inclusion,
)


def test_build_leaf_rejects_unknown_event():
    with pytest.raises(ValueError):
        build_leaf(seq=1, event="teleport", digest="b3:" + "0" * 64, publisher="b3:" + "1" * 64)


def test_leaf_hash_deterministic_and_sensitive_to_content():
    leaf = build_leaf(seq=1, event="publish", digest="b3:" + "a" * 64, publisher="b3:" + "1" * 64)
    h1 = leaf_hash(leaf)
    h2 = leaf_hash(dict(leaf))
    assert h1 == h2

    other = build_leaf(seq=2, event="publish", digest="b3:" + "a" * 64, publisher="b3:" + "1" * 64)
    assert leaf_hash(other) != h1


def test_merkle_root_empty_tree():
    assert merkle_root([]) == EMPTY_TREE_HASH


def test_merkle_root_single_leaf_is_the_leaf_itself():
    h = b3_hex(b"x")
    assert merkle_root([h]) == h


def test_merkle_root_two_leaves_matches_hand_computation():
    from vouch.log import NODE_PREFIX
    from vouch.hashing import parse_b3

    h0, h1 = b3_hex(b"a"), b3_hex(b"b")
    expected = b3_hex(NODE_PREFIX + parse_b3(h0) + parse_b3(h1))
    assert merkle_root([h0, h1]) == expected


def _leaves(n: int) -> list[str]:
    return [b3_hex(f"leaf-{i}".encode()) for i in range(n)]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 16, 17])
def test_inclusion_proof_round_trips_for_every_index(n):
    hashes = _leaves(n)
    root = merkle_root(hashes)
    for i in range(n):
        proof = inclusion_proof(hashes, i)
        verify_inclusion(hashes[i], i, n, root, proof)  # must not raise


def test_inclusion_proof_rejects_out_of_range_index():
    hashes = _leaves(4)
    with pytest.raises(LogFailureError):
        inclusion_proof(hashes, 4)
    with pytest.raises(LogFailureError):
        inclusion_proof(hashes, -1)


def test_verify_inclusion_rejects_wrong_leaf():
    hashes = _leaves(8)
    root = merkle_root(hashes)
    proof = inclusion_proof(hashes, 3)
    with pytest.raises(LogFailureError):
        verify_inclusion(b3_hex(b"not-the-real-leaf"), 3, 8, root, proof)


def test_verify_inclusion_rejects_tampered_proof_element():
    hashes = _leaves(8)
    root = merkle_root(hashes)
    proof = inclusion_proof(hashes, 5)
    tampered = list(proof)
    tampered[0] = b3_hex(b"tampered")
    with pytest.raises(LogFailureError):
        verify_inclusion(hashes[5], 5, 8, root, tampered)


def test_verify_inclusion_rejects_wrong_root():
    hashes = _leaves(8)
    proof = inclusion_proof(hashes, 2)
    wrong_root = b3_hex(b"not-the-real-root")
    with pytest.raises(LogFailureError):
        verify_inclusion(hashes[2], 2, 8, wrong_root, proof)


@pytest.mark.parametrize("old,new", [(0, 0), (0, 1), (1, 1), (1, 4), (3, 8), (8, 8), (5, 17)])
def test_consistency_proof_round_trips(old, new):
    hashes = _leaves(20)
    old_root = merkle_root(hashes[:old])
    new_root = merkle_root(hashes[:new])
    proof = consistency_proof(hashes, old, new)
    verify_consistency(old, old_root, new, new_root, proof)  # must not raise


def test_consistency_proof_rejects_invalid_range():
    hashes = _leaves(5)
    with pytest.raises(LogFailureError):
        consistency_proof(hashes, 3, 1)  # old > new
    with pytest.raises(LogFailureError):
        consistency_proof(hashes, 0, 10)  # new > len(hashes)


def test_verify_consistency_detects_a_forked_history():
    # T5B in miniature: a "new" tree that shares the same old_size prefix in
    # SIZE but not in CONTENT (some earlier leaf was swapped) must fail --
    # this is exactly what an equivocating publisher/mirror would produce.
    honest = _leaves(8)
    honest_old_root = merkle_root(honest[:4])

    forked = list(honest)
    forked[1] = b3_hex(b"a-different-leaf-1")  # rewrite history at index 1
    forked_new_root = merkle_root(forked)
    forked_proof = consistency_proof(forked, 4, 8)

    with pytest.raises(LogFailureError):
        verify_consistency(4, honest_old_root, 8, forked_new_root, forked_proof)


def test_verify_consistency_rejects_old_size_larger_than_new_size():
    hashes = _leaves(5)
    root = merkle_root(hashes)
    with pytest.raises(LogFailureError):
        verify_consistency(5, root, 3, root, hashes[:3])


# --- checkpoint envelope ----------------------------------------------------


def _checkpoint_fixture(**overrides):
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    kwargs = dict(publisher="b3:" + "1" * 64, tree_size=4, root_hash=b3_hex(b"root"))
    kwargs.update(overrides)
    cp = build_checkpoint(**kwargs)
    envelope = sign_checkpoint(cp, sk, kid)
    return cp, envelope, kid, pub


def test_checkpoint_round_trip():
    cp, envelope, kid, pub = _checkpoint_fixture()
    verified = verify_checkpoint_envelope(envelope, authorized_keys={kid: pub}, publisher=cp["publisher"])
    assert verified == cp


def test_checkpoint_rejects_publisher_mismatch():
    cp, envelope, kid, pub = _checkpoint_fixture()
    with pytest.raises(SignatureError):
        verify_checkpoint_envelope(envelope, authorized_keys={kid: pub}, publisher="b3:" + "9" * 64)


def test_checkpoint_rejects_revoked_signer():
    cp, envelope, kid, pub = _checkpoint_fixture()
    with pytest.raises(KeyRevokedError):
        verify_checkpoint_envelope(
            envelope, authorized_keys={kid: pub}, publisher=cp["publisher"], revoked_keys=frozenset({kid})
        )


def test_checkpoint_rejects_tampered_tree_size():
    cp, envelope, kid, pub = _checkpoint_fixture()
    import base64
    import json

    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["tree_size"] = 999
    tampered = dict(envelope)
    tampered["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    with pytest.raises(SignatureError):
        verify_checkpoint_envelope(tampered, authorized_keys={kid: pub}, publisher=cp["publisher"])


def test_checkpoint_payload_that_is_not_a_json_object_is_rejected_cleanly():
    # M4: a validly-signed payload of `null`/a bare list/etc. must fail
    # closed with SignatureError, not crash with AttributeError on `.get()`.
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    envelope = sign(b"null", sk, kid)
    with pytest.raises(SignatureError):
        verify_checkpoint_envelope(envelope, authorized_keys={kid: pub}, publisher="b3:" + "1" * 64)


def test_verify_inclusion_rejects_malformed_proof_element():
    # M4: a non-hex proof element must fail closed with LogFailureError,
    # not crash with a bare ValueError out of hashing.parse_b3.
    with pytest.raises(LogFailureError):
        verify_inclusion(b3_hex(b"leaf"), 0, 2, b3_hex(b"root"), ["not-a-digest"])


def test_verify_consistency_rejects_malformed_proof_element():
    with pytest.raises(LogFailureError):
        verify_consistency(1, b3_hex(b"old"), 2, b3_hex(b"new"), [b3_hex(b"a"), "not-a-digest"])
