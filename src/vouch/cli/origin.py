from __future__ import annotations

import base64
import json
from pathlib import Path

import click
from aiohttp import web

from .. import httpserver, keys, originstore
from .. import snapshot as snapshot_mod
from .. import timestamp as timestamp_mod
from ..store import ensure_layout
from ._common import find_sole_publisher


@click.group("origin")
def origin_group() -> None:
    """Origin-server commands."""


@origin_group.command("serve")
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Origin store directory")
@click.option("--bind", default="127.0.0.1:7433", help="host:port to listen on")
def origin_serve(store: Path, bind: str) -> None:
    """Serve STORE over HTTP. No keys are loaded; this process only reads
    what `publish` already wrote."""
    ensure_layout(store)
    host, _, port_s = bind.rpartition(":")
    if not host:
        raise click.ClickException(f"--bind must be host:port, got {bind!r}")
    port = int(port_s)

    app = httpserver.build_app(store)
    click.echo(f"serving {store} on {host}:{port}")
    web.run_app(app, host=host, port=port, print=None)


@origin_group.command("reissue-timestamp")
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Origin store directory")
@click.option("--timestamp-key", "timestamp_key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--passphrase-fd", type=int, default=None)
def origin_reissue_timestamp(store: Path, timestamp_key_path: Path, passphrase_fd: int | None) -> None:
    """Rebuild the snapshot from current on-disk state and sign a fresh
    timestamp over it. Deliberately separate from `publish` (the timestamp
    key is meant to live on a different, more frequently-online host than
    the release key -- D5's role separation): run this on its own cadence,
    well inside the timestamp's TTL, to keep freshness alive even when
    nothing new has been published.
    """
    passphrase = keys.read_passphrase(passphrase_fd)
    ts_loaded = keys.load_encrypted_key(timestamp_key_path, passphrase)
    if ts_loaded.role != "timestamp":
        raise click.ClickException(f"{timestamp_key_path} is a {ts_loaded.role} key, not a timestamp key")

    ensure_layout(store)
    fingerprint = find_sole_publisher(store)

    artifacts: dict = {}
    for artifact in originstore.list_artifacts(store, fingerprint):
        versions: dict = {}
        best_version, best_seq = None, -1
        for version in originstore.list_versions(store, fingerprint, artifact):
            pointer = originstore.read_current_pointer(store, fingerprint, artifact, version)
            digest = pointer["digest"]
            envelope = originstore.read_manifest_envelope(store, digest)
            payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
            seq = payload["seq"]
            versions[version] = {"seq": seq, "manifest_digest": digest, "log_index": pointer.get("log_index")}
            if seq > best_seq:
                best_seq, best_version = seq, version
        artifacts[artifact] = {"current_version": best_version, "versions": versions}

    _doc, canonical_bytes, snapshot_digest = snapshot_mod.build_and_digest_snapshot(
        publisher=fingerprint, artifacts=artifacts
    )
    originstore.write_snapshot(store, fingerprint, snapshot_digest, canonical_bytes)

    seq = originstore.next_timestamp_seq(store, fingerprint)
    statement = timestamp_mod.build_timestamp_statement(publisher=fingerprint, seq=seq, snapshot_digest=snapshot_digest)
    envelope = timestamp_mod.sign_timestamp(statement, ts_loaded.private_key, ts_loaded.key_id)
    originstore.write_timestamp(store, fingerprint, envelope)

    click.echo(f"snapshot {snapshot_digest} ({len(artifacts)} artifact(s))")
    click.echo(f"timestamp seq {seq} signed (timestamp key {ts_loaded.key_id}), expires {statement['expires']}")
