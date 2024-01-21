"""Property tests for log.py's Merkle math -- the heaviest PBT surface in
M3. Complements the parametrized unit tests in tests/unit/test_log.py with
randomized tree sizes/indices and mutation testing, in the same spirit as
PBT-MANIFEST-MUTATE/PBT-CHUNK-MUTATE: for any valid tree and any single-
element mutation of a proof or a leaf, verification must fail.
"""

from __future__ import annotations

from hypothesis import assume, given, strategies as st

from vouch.errors import LogFailureError
from vouch.hashing import b3_hex
from vouch.log import consistency_proof, inclusion_proof, merkle_root, verify_consistency, verify_inclusion


def _leaves(n: int) -> list[str]:
    return [b3_hex(f"leaf-{i}".encode()) for i in range(n)]


@given(n=st.integers(min_value=1, max_value=64), data=st.data())
def test_inclusion_proof_round_trips_for_any_tree_size_and_index(n, data):
    index = data.draw(st.integers(min_value=0, max_value=n - 1))
    hashes = _leaves(n)
    root = merkle_root(hashes)
    proof = inclusion_proof(hashes, index)
    verify_inclusion(hashes[index], index, n, root, proof)  # must not raise


@given(n=st.integers(min_value=2, max_value=64), data=st.data())
def test_inclusion_proof_rejects_any_single_element_mutation(n, data):
    index = data.draw(st.integers(min_value=0, max_value=n - 1))
    hashes = _leaves(n)
    root = merkle_root(hashes)
    proof = inclusion_proof(hashes, index)
    assume(len(proof) > 0)

    mutate_at = data.draw(st.integers(min_value=0, max_value=len(proof) - 1))
    mutated = list(proof)
    mutated[mutate_at] = b3_hex(mutated[mutate_at].encode() + b"-mutated")

    try:
        verify_inclusion(hashes[index], index, n, root, mutated)
        raised = False
    except LogFailureError:
        raised = True
    assert raised, "a mutated inclusion proof element must never verify"


@given(n=st.integers(min_value=1, max_value=64), data=st.data())
def test_consistency_proof_round_trips_for_any_valid_range(n, data):
    old = data.draw(st.integers(min_value=0, max_value=n))
    new = data.draw(st.integers(min_value=old, max_value=n))
    hashes = _leaves(n)
    old_root = merkle_root(hashes[:old])
    new_root = merkle_root(hashes[:new])
    proof = consistency_proof(hashes, old, new)
    verify_consistency(old, old_root, new, new_root, proof)  # must not raise


@given(n=st.integers(min_value=2, max_value=64), data=st.data())
def test_consistency_proof_detects_any_single_leaf_rewrite_in_the_shared_prefix(n, data):
    old = data.draw(st.integers(min_value=1, max_value=n))
    new = data.draw(st.integers(min_value=old, max_value=n))
    rewrite_index = data.draw(st.integers(min_value=0, max_value=old - 1))

    hashes = _leaves(n)
    old_root = merkle_root(hashes[:old])

    forked = list(hashes)
    forked[rewrite_index] = b3_hex(forked[rewrite_index].encode() + b"-forked")
    forked_new_root = merkle_root(forked[:new])
    forked_proof = consistency_proof(forked, old, new)

    try:
        verify_consistency(old, old_root, new, forked_new_root, forked_proof)
        raised = False
    except LogFailureError:
        raised = True
    assert raised, "rewriting a leaf within the already-checkpointed prefix must always be caught"
