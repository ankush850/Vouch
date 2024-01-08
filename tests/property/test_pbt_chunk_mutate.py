"""PBT-CHUNK-MUTATE, per 03_SECURITY_AND_ACCESS.md section 4:

"for any chunk and any mutation, including truncation and extension, the
chunk is rejected before write."

`cas.write_verified` is the single choke point every chunk passes through
on both the fetch path (V8) and at publish time, so this property test
targets it directly rather than routing mutated bytes through the full
fetch pipeline -- the guarantee transfers, since `fetch_flow.py`'s V8 step
is just a caller of this same function.
"""

from __future__ import annotations

from hypothesis import given, strategies as st

from vouch import store
from vouch.cas import has_object, object_path, write_verified
from vouch.errors import DigestMismatchError
from vouch.hashing import b3_hex


@given(
    original=st.binary(min_size=1, max_size=4096),
    mutation=st.sampled_from(["flip_byte", "truncate", "extend"]),
    data=st.data(),
)
def test_any_mutated_chunk_is_rejected_before_write(tmp_path_factory, original, mutation, data):
    home = tmp_path_factory.mktemp("pbt-chunk")
    store.ensure_layout(home)

    true_digest = b3_hex(original)

    if mutation == "flip_byte":
        idx = data.draw(st.integers(min_value=0, max_value=len(original) - 1))
        orig_byte = original[idx]
        new_byte = data.draw(st.integers(min_value=0, max_value=255).filter(lambda b: b != orig_byte))
        mutated = bytearray(original)
        mutated[idx] = new_byte
        mutated = bytes(mutated)
    elif mutation == "truncate":
        cut = data.draw(st.integers(min_value=0, max_value=len(original) - 1))
        mutated = original[:cut]
    else:  # extend
        tail = data.draw(st.binary(min_size=1, max_size=64))
        mutated = original + tail

    if mutated == original:
        return  # only possible if flip degenerates; strategies above prevent this, but stay safe

    try:
        write_verified(home, true_digest, mutated)
        raised = False
    except DigestMismatchError:
        raised = True

    assert raised, "a mutated chunk must never verify against the original digest"
    # The mutated bytes must never land at the CAS path for the true digest.
    assert not has_object(home, true_digest)
    assert not object_path(home, true_digest).exists()


def test_unmutated_chunk_is_accepted():
    home_data = b"control case: unmutated bytes must still write successfully"
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        store.ensure_layout(home)
        digest = b3_hex(home_data)
        path = write_verified(home, digest, home_data)
        assert path.exists()
        assert has_object(home, digest)
