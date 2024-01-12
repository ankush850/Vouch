import pytest

from vouch.errors import UsageError
from vouch.hashing import b3_hex
from vouch.records import build_record_index, diff_record_indices, parse_granularity


def test_parse_granularity_none():
    assert parse_granularity("none") == ("none", 0)


def test_parse_granularity_line():
    assert parse_granularity("line") == ("line", 1)


def test_parse_granularity_block():
    assert parse_granularity("block:5") == ("block", 5)


@pytest.mark.parametrize("bad", ["block:0", "block:-1", "block:abc", "banana", ""])
def test_parse_granularity_rejects_invalid(bad):
    with pytest.raises(UsageError):
        parse_granularity(bad)


def test_build_record_index_none_returns_none(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_bytes(b'{"a":1}\n{"a":2}\n')
    assert build_record_index(path, "none") is None


def test_build_record_index_line_granularity(tmp_path):
    path = tmp_path / "data.jsonl"
    lines = [b'{"a":1}\n', b'{"a":2}\n', b'{"a":3}\n']
    path.write_bytes(b"".join(lines))

    index = build_record_index(path, "line")
    assert index == [b3_hex(line) for line in lines]


def test_build_record_index_block_granularity(tmp_path):
    path = tmp_path / "data.jsonl"
    lines = [b'{"a":1}\n', b'{"a":2}\n', b'{"a":3}\n', b'{"a":4}\n', b'{"a":5}\n']
    path.write_bytes(b"".join(lines))

    index = build_record_index(path, "block:2")
    assert index == [
        b3_hex(lines[0] + lines[1]),
        b3_hex(lines[2] + lines[3]),
        b3_hex(lines[4]),  # trailing partial block
    ]


def test_build_record_index_empty_file(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    assert build_record_index(path, "line") == []


def test_diff_no_changes():
    idx = [b3_hex(b"a"), b3_hex(b"b"), b3_hex(b"c")]
    result = diff_record_indices(idx, list(idx))
    assert result["added_count"] == 0
    assert result["removed_count"] == 0
    assert result["modified_count"] == 0
    assert result["duplicates_among_added"] == []


def test_diff_detects_added_records():
    old = [b3_hex(b"a"), b3_hex(b"b")]
    new = [b3_hex(b"a"), b3_hex(b"b"), b3_hex(b"c"), b3_hex(b"d")]
    result = diff_record_indices(old, new)
    assert result["added_count"] == 2
    assert result["added_digests"] == [b3_hex(b"c"), b3_hex(b"d")]
    assert result["removed_count"] == 0
    assert result["modified_count"] == 0


def test_diff_detects_removed_records():
    old = [b3_hex(b"a"), b3_hex(b"b"), b3_hex(b"c")]
    new = [b3_hex(b"a")]
    result = diff_record_indices(old, new)
    assert result["removed_count"] == 2
    assert result["removed_digests"] == [b3_hex(b"b"), b3_hex(b"c")]


def test_diff_detects_modified_records_label_flip():
    old = [b3_hex(b"label=0"), b3_hex(b"label=1")]
    new = [b3_hex(b"label=1"), b3_hex(b"label=1")]  # first record's label flipped
    result = diff_record_indices(old, new)
    assert result["modified_count"] == 1
    assert result["modified"] == [{"index": 0, "old_digest": old[0], "new_digest": new[0]}]
    assert result["added_count"] == 0
    assert result["removed_count"] == 0


def test_diff_detects_duplicate_among_added():
    old = [b3_hex(b"a")]
    new = [b3_hex(b"a"), b3_hex(b"dup"), b3_hex(b"dup")]
    result = diff_record_indices(old, new)
    assert result["added_count"] == 2
    assert result["duplicates_among_added"] == [b3_hex(b"dup")]


def test_diff_requires_both_indices_present():
    idx = [b3_hex(b"a")]
    with pytest.raises(UsageError):
        diff_record_indices(None, idx)
    with pytest.raises(UsageError):
        diff_record_indices(idx, None)
