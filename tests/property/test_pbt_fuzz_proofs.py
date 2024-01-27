"""M4 parser fuzzing (see test_pbt_fuzz_envelope.py's docstring for the
overall property).

Target: `log.verify_inclusion`/`verify_consistency`, the "proof inputs"
named explicitly in the milestone's list. Fed arbitrary `proof: list[str]`
(non-hex strings, wrong-typed entries, empty/huge lists, or not even a
list at all) and arbitrary `leaf_index`/`tree_size`/`old_size`/`new_size`
integers. Directly exercises the `_validate_proof_elements` fix (see
DECISIONS.md M4 section) added ahead of writing this file: before that
fix, a malformed proof element reached `hashing.parse_b3`, which raises a
bare `ValueError` rather than a `VouchError`, letting a malicious
peer's malformed proof crash the whole `vouch fetch` process.
"""

from __future__ import annotations

from hypothesis import given, strategies as st

from vouch.errors import LogFailureError
from vouch.hashing import b3_hex
from vouch.log import verify_consistency, verify_inclusion

_proof_element = st.one_of(
    st.text(max_size=20),
    st.integers(),
    st.none(),
    st.binary(max_size=20),
    st.just("b3:" + "a" * 64),  # occasionally a well-formed digest
)
_proof_strategy = st.one_of(
    st.lists(_proof_element, max_size=12),
    st.text(max_size=20),
    st.none(),
    st.integers(),
)


@given(
    leaf_index=st.integers(min_value=-100, max_value=1000),
    tree_size=st.integers(min_value=-100, max_value=1000),
    proof=_proof_strategy,
)
def test_verify_inclusion_never_crashes(leaf_index, tree_size, proof):
    try:
        verify_inclusion(b3_hex(b"leaf"), leaf_index, tree_size, b3_hex(b"root"), proof)
    except LogFailureError:
        pass


@given(
    old_size=st.integers(min_value=-100, max_value=1000),
    new_size=st.integers(min_value=-100, max_value=1000),
    proof=_proof_strategy,
)
def test_verify_consistency_never_crashes(old_size, new_size, proof):
    try:
        verify_consistency(old_size, b3_hex(b"old"), new_size, b3_hex(b"new"), proof)
    except LogFailureError:
        pass


@given(proof=st.lists(_proof_element, min_size=1, max_size=12))
def test_verify_inclusion_never_crashes_with_a_valid_tree_shape_but_bad_elements(proof):
    # A tree_size/leaf_index combination that passes the bounds check, so
    # the fuzzed proof elements actually reach hex-decoding.
    try:
        verify_inclusion(b3_hex(b"leaf"), 0, len(proof) + 1, b3_hex(b"root"), proof)
    except LogFailureError:
        pass
