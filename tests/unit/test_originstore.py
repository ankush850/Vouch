import concurrent.futures

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import log as log_mod
from vouch import originstore, store as store_mod
from vouch.keys import key_id, public_bytes


@pytest.fixture
def store(tmp_path):
    store_mod.ensure_layout(tmp_path)
    return tmp_path


FP = "b3:" + "1" * 64


def test_timestamp_round_trip(store):
    assert originstore.read_timestamp(store, FP) is None
    envelope = {"payloadType": "t", "payload": "cGF5bG9hZA==", "signatures": [{"keyid": "k", "sig": "s"}]}
    originstore.write_timestamp(store, FP, envelope)
    assert originstore.read_timestamp(store, FP) == envelope


def test_next_timestamp_seq_monotonic(store):
    assert originstore.next_timestamp_seq(store, FP) == 1
    assert originstore.next_timestamp_seq(store, FP) == 2
    assert originstore.next_timestamp_seq(store, FP) == 3


def test_next_seq_is_lock_protected_against_concurrent_publish(store):
    # Without the lock in originstore.next_seq, concurrent callers could
    # both read the same "current" value and allocate the same seq twice --
    # silently breaking the uniqueness the rollback high-water marks
    # depend on. Real OS threads (not asyncio tasks) are needed here since
    # fcntl locks are contended at the OS level, and file I/O/flock releases
    # the GIL, so this genuinely exercises the race the lock prevents.
    n = 40
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(lambda _: originstore.next_seq(store, FP, "bert-tiny"), range(n)))

    assert sorted(results) == list(range(1, n + 1)), "every seq must be allocated exactly once, with no gaps"


def test_next_timestamp_seq_is_lock_protected_against_concurrent_reissue(store):
    n = 40
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(lambda _: originstore.next_timestamp_seq(store, FP), range(n)))

    assert sorted(results) == list(range(1, n + 1))


def test_snapshot_raw_bytes_round_trip_not_rebuilt_json(store):
    # The whole point: snapshot storage must not touch json.dumps/loads at
    # all on the write/read path, only raw bytes in, raw bytes out.
    from vouch.hashing import b3_hex

    canonical_bytes = b'{"artifacts":{},"publisher":"b3:1111","vouch":"snapshot/v1"}'
    digest = b3_hex(canonical_bytes)

    assert originstore.read_snapshot_bytes(store, FP, digest) is None
    originstore.write_snapshot(store, FP, digest, canonical_bytes)
    round_tripped = originstore.read_snapshot_bytes(store, FP, digest)
    assert round_tripped == canonical_bytes
    assert b3_hex(round_tripped) == digest


def test_snapshot_path_rejects_invalid_digest(store):
    from vouch.errors import InternalError

    with pytest.raises(InternalError):
        originstore.snapshot_path(store, FP, "not-a-digest")


def test_list_artifacts_and_versions_from_current_pointers(store):
    assert originstore.list_artifacts(store, FP) == []

    originstore.write_current_pointer(store, FP, "bert-tiny", "1.0.0", "b3:" + "a" * 64)
    originstore.write_current_pointer(store, FP, "bert-tiny", "1.2.0", "b3:" + "b" * 64)
    originstore.write_current_pointer(store, FP, "sst5", "0.1.0", "b3:" + "c" * 64)

    assert originstore.list_artifacts(store, FP) == ["bert-tiny", "sst5"]
    assert originstore.list_versions(store, FP, "bert-tiny") == ["1.0.0", "1.2.0"]
    assert originstore.list_versions(store, FP, "sst5") == ["0.1.0"]
    assert originstore.list_versions(store, FP, "nonexistent") == []


def test_current_pointer_carries_log_index(store):
    originstore.write_current_pointer(store, FP, "bert-tiny", "1.0.0", "b3:" + "a" * 64, log_index=3)
    pointer = originstore.read_current_pointer(store, FP, "bert-tiny", "1.0.0")
    assert pointer == {"digest": "b3:" + "a" * 64, "log_index": 3}

    # log_index defaults to None when not given (M2-era callers unaffected).
    originstore.write_current_pointer(store, FP, "bert-tiny", "1.2.0", "b3:" + "b" * 64)
    pointer2 = originstore.read_current_pointer(store, FP, "bert-tiny", "1.2.0")
    assert pointer2 == {"digest": "b3:" + "b" * 64, "log_index": None}


def _release_key():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return sk, key_id(pub)


def test_append_log_leaf_assigns_sequential_indices_and_advances_checkpoint(store):
    sk, kid = _release_key()

    assert originstore.read_log_leaves(store, FP) == []
    assert originstore.read_checkpoint(store, FP) is None

    idx0, cp0_envelope = originstore.append_log_leaf(
        store, FP, event="publish", digest="b3:" + "a" * 64, release_private_key=sk, release_key_id=kid
    )
    assert idx0 == 0

    idx1, cp1_envelope = originstore.append_log_leaf(
        store, FP, event="publish", digest="b3:" + "b" * 64, release_private_key=sk, release_key_id=kid
    )
    assert idx1 == 1

    leaves = originstore.read_log_leaves(store, FP)
    assert len(leaves) == 2
    assert leaves[0]["seq"] == 0 and leaves[0]["digest"] == "b3:" + "a" * 64
    assert leaves[1]["seq"] == 1 and leaves[1]["digest"] == "b3:" + "b" * 64

    # The stored "latest" checkpoint matches the second append.
    latest = originstore.read_checkpoint(store, FP)
    assert latest == cp1_envelope

    # Both checkpoint history entries are retained and match the tree at
    # that point in time.
    cp_at_1 = originstore.read_checkpoint_at(store, FP, 1)
    cp_at_2 = originstore.read_checkpoint_at(store, FP, 2)
    assert cp_at_1 == cp0_envelope
    assert cp_at_2 == cp1_envelope

    expected_root_at_2 = log_mod.merkle_root([log_mod.leaf_hash(entry) for entry in leaves])
    import base64
    import json

    cp2_payload = json.loads(base64.b64decode(cp1_envelope["payload"]))
    assert cp2_payload["tree_size"] == 2
    assert cp2_payload["root_hash"] == expected_root_at_2


def test_append_log_leaf_is_lock_protected_against_concurrent_publish(store):
    sk, kid = _release_key()
    n = 20

    def _append(i):
        return originstore.append_log_leaf(
            store, FP, event="publish", digest=f"b3:{i:064x}", release_private_key=sk, release_key_id=kid
        )[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        indices = list(pool.map(_append, range(n)))

    assert sorted(indices) == list(range(n)), "every leaf index must be allocated exactly once, with no gaps"
    leaves = originstore.read_log_leaves(store, FP)
    assert len(leaves) == n
    assert sorted(leaf["seq"] for leaf in leaves) == list(range(n))
