import io

from vouch.chunking import CHUNK_SIZE, compute_file_digest, iter_chunks, iter_chunks_fileobj
from vouch.hashing import b3_hex, new_hasher, parse_b3


def test_single_short_chunk():
    chunks = list(iter_chunks_fileobj(io.BytesIO(b"hello")))
    assert len(chunks) == 1
    assert chunks[0].index == 0
    assert chunks[0].digest == b3_hex(b"hello")
    assert chunks[0].data == b"hello"


def test_empty_file_yields_no_chunks():
    assert list(iter_chunks_fileobj(io.BytesIO(b""))) == []


def test_exact_multiple_of_chunk_size(tmp_path):
    data = b"x" * (CHUNK_SIZE * 2)
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    chunks = list(iter_chunks(path))
    assert len(chunks) == 2
    assert [c.index for c in chunks] == [0, 1]
    assert chunks[0].data == data[:CHUNK_SIZE]
    assert chunks[1].data == data[CHUNK_SIZE:]


def test_chunk_boundaries_and_last_short_chunk(tmp_path):
    data = b"a" * CHUNK_SIZE + b"b" * 100
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    chunks = list(iter_chunks(path))
    assert len(chunks) == 2
    assert len(chunks[0].data) == CHUNK_SIZE
    assert len(chunks[1].data) == 100


def test_streaming_never_buffers_whole_file(tmp_path, monkeypatch):
    # Assert the generator never reads more than CHUNK_SIZE bytes at a time,
    # regardless of file size -- this is the O(chunk size) memory guarantee.
    path = tmp_path / "big.bin"
    path.write_bytes(b"z" * (CHUNK_SIZE * 3 + 7))

    real_open = open

    class TrackingFile:
        def __init__(self, f):
            self._f = f

        def read(self, n=-1):
            assert n == CHUNK_SIZE, "iter_chunks must always request exactly CHUNK_SIZE bytes"
            return self._f.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self._f.close()

    def tracking_open(p, mode):
        return TrackingFile(real_open(p, mode))

    monkeypatch.setattr("builtins.open", tracking_open)
    chunks = list(iter_chunks(path))
    assert len(chunks) == 4
    assert sum(len(c.data) for c in chunks) == CHUNK_SIZE * 3 + 7


def test_compute_file_digest_hashes_concatenated_digest_bytes():
    # Deliberately does NOT hash raw file bytes -- section 3.3.
    chunk_digests = [b3_hex(b"chunk-a"), b3_hex(b"chunk-b")]
    expected = new_hasher()
    expected.update(parse_b3(chunk_digests[0]))
    expected.update(parse_b3(chunk_digests[1]))
    assert compute_file_digest(chunk_digests) == "b3:" + expected.hexdigest()

    # And confirm it's NOT simply the hash of the raw concatenated bytes.
    assert compute_file_digest(chunk_digests) != b3_hex(b"chunk-achunk-b")


def test_compute_file_digest_order_matters():
    a, b = b3_hex(b"1"), b3_hex(b"2")
    assert compute_file_digest([a, b]) != compute_file_digest([b, a])
