import pytest

from vouch.hashing import b3_hex, format_digest, is_valid_digest, parse_b3


def test_b3_hex_known_vector():
    # BLAKE3 of the empty string is a published test vector.
    assert b3_hex(b"") == (
        "b3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    )


def test_parse_and_format_round_trip():
    digest = b3_hex(b"hello world")
    raw = parse_b3(digest)
    assert len(raw) == 32
    assert format_digest(raw) == digest


def test_parse_b3_rejects_malformed():
    for bad in ["not-a-digest", "b3:short", "sha256:" + "a" * 64, "b3:" + "g" * 64]:
        with pytest.raises(ValueError):
            parse_b3(bad)


def test_is_valid_digest():
    assert is_valid_digest(b3_hex(b"x"))
    assert not is_valid_digest("garbage")


def test_different_inputs_different_digests():
    assert b3_hex(b"a") != b3_hex(b"b")
