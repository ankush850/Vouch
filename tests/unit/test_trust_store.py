import pytest

from vouch import store, trust_store
from vouch.errors import LogFailureError, PinMismatchError, RollbackError


@pytest.fixture
def home(tmp_path):
    store.ensure_layout(tmp_path)
    return tmp_path


def test_add_and_load_pin(home):
    trust_store.add_pin(home, "acme-lab", "b3:" + "a" * 64, mirrors=["https://mirror.example.org"])
    assert trust_store.has_pin(home, "acme-lab")
    pin = trust_store.load_pin(home, "acme-lab")
    assert pin["name"] == "acme-lab"
    assert pin["fingerprint"] == "b3:" + "a" * 64
    assert pin["mirrors"] == ["https://mirror.example.org"]


def test_load_pin_missing_raises(home):
    assert not trust_store.has_pin(home, "nobody")
    with pytest.raises(PinMismatchError):
        trust_store.load_pin(home, "nobody")


def test_root_envelope_cache_round_trip(home):
    assert trust_store.load_cached_root_envelope(home, "acme-lab") is None
    envelope = {"payloadType": "t", "payload": "cGF5bG9hZA==", "signatures": []}
    trust_store.cache_root_envelope(home, "acme-lab", envelope)
    assert trust_store.load_cached_root_envelope(home, "acme-lab") == envelope


def test_root_version_hwm_advances_and_rejects_rollback(home):
    trust_store.check_and_advance_root_version(home, "acme-lab", 1)
    trust_store.check_and_advance_root_version(home, "acme-lab", 1)  # equal is fine (idempotent)
    trust_store.check_and_advance_root_version(home, "acme-lab", 3)  # advances

    with pytest.raises(RollbackError):
        trust_store.check_and_advance_root_version(home, "acme-lab", 2)


def test_manifest_seq_hwm_is_per_artifact(home):
    trust_store.check_and_advance_manifest_seq(home, "acme-lab", "bert-tiny", 5)
    trust_store.check_and_advance_manifest_seq(home, "acme-lab", "sst5", 1)  # independent artifact

    with pytest.raises(RollbackError):
        trust_store.check_and_advance_manifest_seq(home, "acme-lab", "bert-tiny", 4)

    # Unaffected artifact still accepts its own lower-than-bert-tiny seq.
    trust_store.check_and_advance_manifest_seq(home, "acme-lab", "sst5", 2)


def test_get_timestamp_seq_hwm_defaults_to_zero_and_reflects_advances(home):
    assert trust_store.get_timestamp_seq_hwm(home, "acme-lab") == 0
    trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 5, {"payload": "x", "signatures": []})
    assert trust_store.get_timestamp_seq_hwm(home, "acme-lab") == 5


def test_timestamp_seq_hwm_advances_and_rejects_rollback(home):
    envelope_v1 = {"payload": "aa", "signatures": [{"keyid": "k", "sig": "s1"}]}
    trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 1, envelope_v1)

    with pytest.raises(RollbackError):
        trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 0, {"payload": "zz", "signatures": []})


def test_timestamp_seq_equal_and_identical_envelope_is_a_noop(home):
    envelope = {"payload": "aa", "signatures": [{"keyid": "k", "sig": "s1"}]}
    trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 1, envelope)
    # Re-presenting the exact same statement at the same seq must not raise.
    trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 1, dict(envelope))


def test_get_root_version_hwm_defaults_to_zero_and_reflects_advances(home):
    assert trust_store.get_root_version_hwm(home, "acme-lab") == 0
    trust_store.check_and_advance_root_version(home, "acme-lab", 4)
    assert trust_store.get_root_version_hwm(home, "acme-lab") == 4


def test_get_manifest_seq_hwm_defaults_to_zero_and_reflects_advances(home):
    assert trust_store.get_manifest_seq_hwm(home, "acme-lab", "bert-tiny") == 0
    trust_store.check_and_advance_manifest_seq(home, "acme-lab", "bert-tiny", 7)
    assert trust_store.get_manifest_seq_hwm(home, "acme-lab", "bert-tiny") == 7
    assert trust_store.get_manifest_seq_hwm(home, "acme-lab", "sst5") == 0


def test_timestamp_seq_equal_but_different_envelope_is_equivocation(home):
    envelope_a = {"payload": "aa", "signatures": [{"keyid": "k", "sig": "s1"}]}
    envelope_b = {"payload": "bb", "signatures": [{"keyid": "k", "sig": "s2"}]}
    trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 1, envelope_a)

    with pytest.raises(LogFailureError):
        trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 1, envelope_b)


def test_log_checkpoint_hwm_defaults_to_none_and_advances(home):
    assert trust_store.get_log_checkpoint_hwm(home, "acme-lab") is None
    trust_store.advance_log_checkpoint(home, "acme-lab", 5, "b3:" + "a" * 64)
    assert trust_store.get_log_checkpoint_hwm(home, "acme-lab") == {"tree_size": 5, "root_hash": "b3:" + "a" * 64}

    trust_store.advance_log_checkpoint(home, "acme-lab", 8, "b3:" + "b" * 64)
    assert trust_store.get_log_checkpoint_hwm(home, "acme-lab") == {"tree_size": 8, "root_hash": "b3:" + "b" * 64}


def test_repinning_to_a_new_fingerprint_clears_old_identitys_state(home):
    # M4: root-key-compromise recovery re-pins an existing local alias to a
    # brand-new, unrelated fingerprint. Without clearing state.json (keyed
    # by NAME, not fingerprint), the old identity's high-water marks would
    # be silently compared against the new publisher's own genuinely fresh
    # state -- e.g. a false equivocation at the new publisher's first-ever
    # timestamp, if its seq happens to coincide with the old one already seen.
    trust_store.add_pin(home, "acme-lab", "b3:" + "a" * 64)
    trust_store.check_and_advance_root_version(home, "acme-lab", 3)
    trust_store.check_and_advance_manifest_seq(home, "acme-lab", "bert-tiny", 7)
    envelope = {"payload": "aa", "signatures": [{"keyid": "k", "sig": "s1"}]}
    trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 1, envelope)
    trust_store.advance_log_checkpoint(home, "acme-lab", 5, "b3:" + "c" * 64)
    trust_store.cache_root_envelope(home, "acme-lab", {"payloadType": "t", "payload": "cGF5bG9hZA==", "signatures": []})

    trust_store.add_pin(home, "acme-lab", "b3:" + "b" * 64)

    assert trust_store.get_root_version_hwm(home, "acme-lab") == 0
    assert trust_store.get_manifest_seq_hwm(home, "acme-lab", "bert-tiny") == 0
    assert trust_store.get_timestamp_seq_hwm(home, "acme-lab") == 0
    assert trust_store.get_log_checkpoint_hwm(home, "acme-lab") is None
    assert trust_store.load_cached_root_envelope(home, "acme-lab") is None
    # A re-issued statement at the SAME seq the old identity had already
    # reached no longer looks like equivocation against the new pin.
    trust_store.check_and_advance_timestamp_seq(home, "acme-lab", 1, envelope)


def test_repinning_to_the_same_fingerprint_preserves_state(home):
    trust_store.add_pin(home, "acme-lab", "b3:" + "a" * 64)
    trust_store.check_and_advance_root_version(home, "acme-lab", 3)

    trust_store.add_pin(home, "acme-lab", "b3:" + "a" * 64, mirrors=["https://new-mirror.example.org"])

    assert trust_store.get_root_version_hwm(home, "acme-lab") == 3
