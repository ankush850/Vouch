"""Fixed-size chunking, per 02_TECHNICAL_ARCHITECTURE.md section 3.2.

Files are split into fixed 4 MiB chunks; each chunk is content-addressed by
its own BLAKE3 digest. Chunking streams a fixed-size buffer at a time so
memory use is O(chunk size), never O(file size).

A file's digest is BLAKE3 over the *concatenation of the raw chunk digest
bytes* (not the raw file bytes) -- section 3.3. This is easy to get backwards
so it lives in its own well-tested function.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, NamedTuple

from .hashing import b3_hex, new_hasher, parse_b3

CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB


class Chunk(NamedTuple):
    index: int
    digest: str
    data: bytes


def iter_chunks_fileobj(fileobj: BinaryIO) -> Iterator[Chunk]:
    """Stream fixed CHUNK_SIZE reads from an open binary file object.

    Yields one Chunk per CHUNK_SIZE-byte (or shorter, for the last chunk)
    span read in file order, starting at index 0. Never buffers more than one
    chunk at a time.
    """
    index = 0
    while True:
        data = fileobj.read(CHUNK_SIZE)
        if not data:
            return
        yield Chunk(index=index, digest=b3_hex(data), data=data)
        index += 1


def iter_chunks(path: Path) -> Iterator[Chunk]:
    with open(path, "rb") as f:
        yield from iter_chunks_fileobj(f)


def compute_file_digest(chunk_digests: list[str]) -> str:
    """BLAKE3 over the concatenation of raw chunk-digest bytes (not file bytes)."""
    hasher = new_hasher()
    for digest in chunk_digests:
        hasher.update(parse_b3(digest))
    return "b3:" + hasher.hexdigest()
