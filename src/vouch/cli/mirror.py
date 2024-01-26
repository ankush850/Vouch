"""`mirror sync` / `mirror serve`, per 04_FRONTEND_SPEC.md section 6 and
02_TECHNICAL_ARCHITECTURE.md UC8.

No credentials, no accounts, no key material -- ever. A mirror holds no
pin (there is nothing to pin to: it isn't a consumer, it just moves
bytes), so `mirror sync` takes the publisher's root-key fingerprint
directly, not a local alias. Whatever ingest-time checks this module runs
are advisory only, to avoid wasting the mirror's own disk on obviously
corrupt garbage -- they are NEVER trust-relevant to a consumer, who
verifies everything itself, from a mirror or from the origin, identically
(PRD section 4, UC8). `mirror serve` reuses `httpserver.build_app`
verbatim: a mirror serves the exact same routes an origin does, from a
store `mirror sync` populated instead of one `publish` populated.

Transparency log replication (M3) is an explicit added step here, not
automatic the way chunks are: `originstore.py`'s log storage is a single
JSON array + checkpoint (Decision 5 in the M3 plan), not per-leaf
content-addressed objects the way the architecture doc's text frames it,
so a mirror can't pick the log up "for free" by walking manifests/chunks
-- it fetches `log/checkpoint` and every root version explicitly, and
replicates `log/leaves.json` verbatim so a consumer fetching from this
mirror can still build inclusion proofs against it (`log/proof/...` is
served by the SAME route handlers a mirror shares with an origin, reading
whatever `leaves.json`/`checkpoint.json` sit in its own store).
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import click
from aiohttp import web

from .. import cas, httpserver, originstore
from ..canonical import canonicalize
from ..hashing import b3_hex
from ..httpclient import OriginClient
from ..store import ensure_layout


@click.group("mirror")
def mirror_group() -> None:
    """Mirror operator commands. No keys, no accounts, no trust decisions."""


@mirror_group.command("sync")
@click.argument("publisher")
@click.option("--from", "from_url", required=True, help="Base URL of any existing source (origin or mirror)")
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Local mirror store directory")
def mirror_sync(publisher: str, from_url: str, store: Path) -> None:
    """Pull PUBLISHER's (a root-key fingerprint) current state from --from
    into --store: every root version, timestamp, snapshot, every manifest
    the snapshot names, every chunk those manifests name, and the
    transparency log (checkpoint + leaves, M3).
    """
    ensure_layout(store)
    counts = asyncio.run(_sync(publisher, from_url, store))
    click.echo(
        f"synced: {counts['root_versions']} root version(s), timestamp, snapshot, "
        f"{counts['manifests']} manifest(s), {counts['chunks']} chunk(s), "
        f"log ({counts['log_leaves']} leaf/leaves)"
    )
    click.echo("note: mirror verified content on ingest (advisory only; consumers never rely on this)")


async def _sync(publisher: str, from_url: str, store: Path) -> dict:
    async with OriginClient(from_url) as client:
        root_version_count = 0
        version = 1
        while True:
            root_envelope = await client.get_root(publisher, version)
            if root_envelope is None:
                break
            if version == 1:
                root_doc = _decode_payload(root_envelope)
                if root_doc.get("keys", {}).get("root", [{}])[0].get("id") != publisher:
                    raise click.ClickException("root document is not self-consistent with the requested fingerprint")
            originstore.write_root_doc(store, publisher, version, root_envelope)
            root_version_count += 1
            version += 1
        if root_version_count == 0:
            raise click.ClickException(f"{from_url}: no root document for {publisher}")

        checkpoint_envelope = await client.get_checkpoint(publisher)
        leaf_count = 0
        if checkpoint_envelope is not None:
            originstore.atomic_write_json(originstore.checkpoint_path(store, publisher), checkpoint_envelope)
            leaves = await client.get_log_leaves(publisher)
            if leaves is not None:
                originstore.atomic_write_json(originstore.log_leaves_path(store, publisher), leaves)
                leaf_count = len(leaves)

        timestamp_envelope = await client.get_timestamp(publisher)
        if timestamp_envelope is None:
            raise click.ClickException(f"{from_url}: no timestamp for {publisher}")
        timestamp_stmt = _decode_payload(timestamp_envelope)
        originstore.write_timestamp(store, publisher, timestamp_envelope)

        snapshot_digest = timestamp_stmt["snapshot"]
        snapshot_bytes = await client.get_snapshot(publisher, snapshot_digest)
        if snapshot_bytes is None:
            raise click.ClickException(f"{from_url}: no snapshot {snapshot_digest}")
        if b3_hex(snapshot_bytes) != snapshot_digest:
            raise click.ClickException(f"snapshot bytes do not match digest {snapshot_digest}")
        originstore.write_snapshot(store, publisher, snapshot_digest, snapshot_bytes)
        snapshot_doc = json.loads(snapshot_bytes)

        manifest_count = 0
        chunk_count = 0
        for artifact_entry in snapshot_doc.get("artifacts", {}).values():
            for version_entry in artifact_entry.get("versions", {}).values():
                manifest_digest = version_entry["manifest_digest"]
                manifest_envelope = await client.get_manifest(manifest_digest)
                if manifest_envelope is None:
                    raise click.ClickException(f"{from_url}: no manifest {manifest_digest}")
                manifest = _decode_payload(manifest_envelope)
                if b3_hex(canonicalize(manifest)) != manifest_digest:
                    raise click.ClickException(f"manifest bytes do not match digest {manifest_digest}")
                originstore.write_manifest_envelope(store, manifest_digest, manifest_envelope)
                manifest_count += 1

                for file_entry in manifest["files"]:
                    for chunk_digest in file_entry["chunks"]:
                        if cas.has_object(store, chunk_digest):
                            continue
                        data = await client.get_chunk(chunk_digest)
                        if data is None:
                            raise click.ClickException(f"{from_url}: no chunk {chunk_digest}")
                        cas.write_verified(store, chunk_digest, data, peer=from_url)
                        chunk_count += 1

    return {
        "root_versions": root_version_count,
        "manifests": manifest_count,
        "chunks": chunk_count,
        "log_leaves": leaf_count,
    }


def _decode_payload(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"], validate=True))


@mirror_group.command("serve")
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Mirror store directory")
@click.option("--bind", default="127.0.0.1:7433", help="host:port to listen on")
def mirror_serve(store: Path, bind: str) -> None:
    """Serve STORE (built by `mirror sync`) over the same routes an origin
    serves. No keys are loaded by this process."""
    ensure_layout(store)
    host, _, port_s = bind.rpartition(":")
    if not host:
        raise click.ClickException(f"--bind must be host:port, got {bind!r}")
    port = int(port_s)

    app = httpserver.build_app(store)
    click.echo(f"serving {store} on {host}:{port}; no keys loaded")
    web.run_app(app, host=host, port=port, print=None)
