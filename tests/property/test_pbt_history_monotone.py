"""PBT-HISTORY-MONOTONE, per 03_SECURITY_AND_ACCESS.md section 4:

"for any valid metadata history and any replayed prefix or reordering, the
consumer rejects with a rollback or staleness error."

Targets `trust_store.check_and_advance_timestamp_seq` directly -- the
consumer's high-water-mark-checking logic the property's wording refers
to -- rather than routing through a full signed-envelope fetch, since the
crypto/expiry half of V4 is already covered by test_timestamp.py and
PBT-MANIFEST-MUTATE-style tests; this property is specifically about the
state machine's ordering guarantees.
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, strategies as st

from vouch import store as store_mod
from vouch.errors import LogFailureError, RollbackError
from vouch.trust_store import check_and_advance_timestamp_seq, get_timestamp_seq_hwm

SEQ_LISTS = st.lists(st.integers(min_value=1, max_value=50), unique=True, min_size=1, max_size=8).map(sorted)


def _envelope(seq: int, marker: str = "a") -> dict:
    return {"seq": seq, "marker": marker}


@given(seqs=SEQ_LISTS)
def test_true_increasing_order_always_succeeds(tmp_path_factory, seqs):
    home = tmp_path_factory.mktemp("pbt-history")
    store_mod.ensure_layout(home)
    for seq in seqs:
        check_and_advance_timestamp_seq(home, "acme-lab", seq, _envelope(seq))
    assert get_timestamp_seq_hwm(home, "acme-lab") == seqs[-1]


@given(data=st.data())
def test_any_genuine_reordering_is_rejected(tmp_path_factory, data):
    seqs = data.draw(SEQ_LISTS.filter(lambda s: len(s) >= 2))
    permuted = list(data.draw(st.permutations(seqs)))
    assume(permuted != seqs)  # only test genuine reorderings/replays

    home = tmp_path_factory.mktemp("pbt-history")
    store_mod.ensure_layout(home)

    running_max = None
    raised = False
    for seq in permuted:
        if running_max is not None and seq < running_max:
            with pytest.raises(RollbackError):
                check_and_advance_timestamp_seq(home, "acme-lab", seq, _envelope(seq))
            raised = True
            break
        check_and_advance_timestamp_seq(home, "acme-lab", seq, _envelope(seq))
        running_max = seq if running_max is None else max(running_max, seq)

    assert raised, "a genuine reordering of unique values must contain a rollback-triggering element"


@given(seq=st.integers(min_value=1, max_value=1000))
def test_identical_duplicate_at_current_hwm_is_idempotent(tmp_path_factory, seq):
    home = tmp_path_factory.mktemp("pbt-history")
    store_mod.ensure_layout(home)
    envelope = _envelope(seq, marker="same-statement")
    check_and_advance_timestamp_seq(home, "acme-lab", seq, envelope)
    # A different dict object, but equal content -- must not raise.
    check_and_advance_timestamp_seq(home, "acme-lab", seq, dict(envelope))
    assert get_timestamp_seq_hwm(home, "acme-lab") == seq


@given(seq=st.integers(min_value=1, max_value=1000))
def test_mutated_duplicate_at_current_hwm_is_equivocation(tmp_path_factory, seq):
    home = tmp_path_factory.mktemp("pbt-history")
    store_mod.ensure_layout(home)
    check_and_advance_timestamp_seq(home, "acme-lab", seq, _envelope(seq, marker="original"))
    with pytest.raises(LogFailureError):
        check_and_advance_timestamp_seq(home, "acme-lab", seq, _envelope(seq, marker="different"))


@given(seqs=SEQ_LISTS.filter(lambda s: len(s) >= 2))
def test_replaying_a_superseded_prefix_is_rejected_as_rollback(tmp_path_factory, seqs):
    # Once the hwm has advanced past a seq, replaying that (already-
    # superseded, not just-at-hwm) seq again is rejected -- only a replay
    # of the CURRENT hwm value is idempotent (see the identical-duplicate
    # test above); anything strictly below it is a rollback attempt.
    home = tmp_path_factory.mktemp("pbt-history")
    store_mod.ensure_layout(home)
    for seq in seqs:
        check_and_advance_timestamp_seq(home, "acme-lab", seq, _envelope(seq))

    prefix_len = len(seqs) // 2 or 1
    for seq in seqs[:prefix_len]:
        with pytest.raises(RollbackError):
            check_and_advance_timestamp_seq(home, "acme-lab", seq, _envelope(seq))

    assert get_timestamp_seq_hwm(home, "acme-lab") == seqs[-1]
