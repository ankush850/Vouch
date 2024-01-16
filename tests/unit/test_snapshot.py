import json

import pytest

from vouch.errors import DigestMismatchError
from vouch.snapshot import build_and_digest_snapshot, verify_snapshot


ARTIFACTS = {
    "bert-tiny": {
        "current_version": "1.2.0",
        "versions": {
            "1.0.0": {"seq": 1, "manifest_digest": "b3:" + "a" * 64},
            "1.2.0": {"seq": 2, "manifest_digest": "b3:" + "b" * 64},
        },
    }
}


def test_build_and_verify_round_trip():
    doc, canonical_bytes, digest = build_and_digest_snapshot(publisher="b3:" + "9" * 64, artifacts=ARTIFACTS)
    verified = verify_snapshot(canonical_bytes, expected_digest=digest)
    assert verified == doc


def test_digest_is_over_raw_wire_bytes_not_rebuilt_json():
    # The whole point of D6: re-serializing the parsed dict through a
    # different (but semantically equivalent) JSON encoder must NOT still
    # hash to the same digest as the original canonical bytes -- if it did,
    # this test wouldn't be exercising anything real about the byte-exactness
    # requirement.
    doc, canonical_bytes, digest = build_and_digest_snapshot(publisher="b3:" + "9" * 64, artifacts=ARTIFACTS)
    rebuilt = json.dumps(doc, indent=2, sort_keys=True).encode() + b"\n"  # vouch.store's own house style
    assert rebuilt != canonical_bytes
    with pytest.raises(DigestMismatchError):
        verify_snapshot(rebuilt, expected_digest=digest)


def test_rejects_wrong_digest():
    _, canonical_bytes, digest = build_and_digest_snapshot(publisher="b3:" + "9" * 64, artifacts=ARTIFACTS)
    with pytest.raises(DigestMismatchError):
        verify_snapshot(canonical_bytes, expected_digest="b3:" + "f" * 64)


def test_rejects_any_single_byte_mutation():
    _, canonical_bytes, digest = build_and_digest_snapshot(publisher="b3:" + "9" * 64, artifacts=ARTIFACTS)
    mutated = bytearray(canonical_bytes)
    mutated[0] ^= 0xFF
    with pytest.raises(DigestMismatchError):
        verify_snapshot(bytes(mutated), expected_digest=digest)


def test_rejects_malformed_json_even_if_digest_happened_to_match():
    garbage = b"not json at all"
    from vouch.hashing import b3_hex

    with pytest.raises(DigestMismatchError):
        verify_snapshot(garbage, expected_digest=b3_hex(garbage))


def test_empty_artifacts_round_trips():
    doc, canonical_bytes, digest = build_and_digest_snapshot(publisher="b3:" + "0" * 64, artifacts={})
    verified = verify_snapshot(canonical_bytes, expected_digest=digest)
    assert verified["artifacts"] == {}


def test_rejects_valid_json_that_is_not_an_object_without_crashing():
    # M4: found by parser fuzzing -- bytes that are valid, canonical JSON
    # but not a JSON object (e.g. a bare integer) must fail closed with
    # DigestMismatchError, not crash with AttributeError from an
    # unconditional `.get()` call in the error-message construction.
    from vouch.hashing import b3_hex

    data = b"0"  # canonicalizes to itself; parses to the int 0, not a dict
    with pytest.raises(DigestMismatchError):
        verify_snapshot(data, expected_digest=b3_hex(data))
