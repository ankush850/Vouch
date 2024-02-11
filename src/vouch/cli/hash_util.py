"""`vouch hash FILE`: compute BLAKE3 digests and chunk trees."""

from __future__ import annotations

import json
from pathlib import Path

import blake3
import click


@click.command("hash")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--chunk-size", default=1024 * 1024, help="Chunk size in bytes (default: 1MB)")
@click.pass_context
def hash_command(ctx: click.Context, file_path: Path, chunk_size: int) -> None:
    """Compute BLAKE3 digest and chunk structure for a file."""
    hasher = blake3.blake3()
    chunks = []
    total_size = 0

    with file_path.open("rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf:
                break
            chunk_hash = blake3.blake3(buf).hexdigest()
            chunks.append({"offset": total_size, "length": len(buf), "digest": f"b3:{chunk_hash}"})
            hasher.update(buf)
            total_size += len(buf)

    overall_digest = f"b3:{hasher.hexdigest()}"
    res = {
        "file": str(file_path),
        "size": total_size,
        "overall_digest": overall_digest,
        "chunks_count": len(chunks),
        "chunks": chunks,
    }

    if ctx.obj and ctx.obj.get("json"):
        click.echo(json.dumps(res))
    else:
        click.echo(f"File:   {file_path}")
        click.echo(f"Size:   {total_size:,} bytes ({len(chunks)} chunks)")
        click.echo(f"Digest: {overall_digest}")
