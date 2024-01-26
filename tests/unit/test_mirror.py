"""`mirror sync` + `mirror serve`: pull a publisher's state from an honest
origin into a mirror store with no keys, then confirm a consumer can fetch
and verify from the mirror exactly as it would from the origin -- the
mirror never touches trust, it just moves content-addressed and signed
bytes around.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import originstore, store as store_mod, trust_store
from vouch.chunking import CHUNK_SIZE
from vouch.cli.main import main
from vouch.fetch_flow import fetch as fetch_flow_fetch
from vouch.httpserver import build_app
from vouch.keys import key_id, public_bytes
from vouch.manifest import build_manifest, manifest_digest, sign_manifest
from vouch.peers import PeerPool
from vouch.root import build_root_doc, sign_root_doc
from vouch.snapshot import build_and_digest_snapshot
from vouch.timestamp import build_timestamp_statement, sign_timestamp

pytestmark = pytest.mark.asyncio


def _passphrase_fd(passphrase: str) -> int:
    r, w = os.pipe()
    os.write(w, (passphrase + "\n").encode())
    os.close(w)
    return r


async def invoke(runner: CliRunner, args: list[str]):
    return await asyncio.to_thread(runner.invoke, main, args, catch_exceptions=False)


@pytest.fixture
def origin_store(tmp_path):
    origin = tmp_path / "origin"
    store_mod.ensure_layout(origin)
    return origin


@pytest.fixture
def published_artifact(tmp_path, origin_store):
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.bin").write_bytes(b"B" * (CHUNK_SIZE + 999))
    (src / "small.bin").write_bytes(b"small file")

    root_sk = Ed25519PrivateKey.generate()
    root_pub = public_bytes(root_sk.public_key())
    root_kid = key_id(root_pub)
    release_sk = Ed25519PrivateKey.generate()
    release_pub = public_bytes(release_sk.public_key())
    release_kid = key_id(release_pub)
    timestamp_sk = Ed25519PrivateKey.generate()
    timestamp_pub = public_bytes(timestamp_sk.public_key())
    timestamp_kid = key_id(timestamp_pub)

    root_doc = build_root_doc(
        publisher=root_kid,
        root_keys=[(root_kid, root_pub)],
        release_keys=[(release_kid, release_pub)],
        timestamp_keys=[(timestamp_kid, timestamp_pub)],
    )
    root_envelope = sign_root_doc(root_doc, root_sk, root_kid)
    originstore.write_root_doc(origin_store, root_kid, 1, root_envelope)

    manifest = build_manifest(
        src, origin_store, publisher=root_kid, name="bert-tiny", version="1.2.0", seq=1, artifact_type="model"
    )
    digest = manifest_digest(manifest)
    envelope = sign_manifest(manifest, release_sk, release_kid)
    originstore.write_manifest_envelope(origin_store, digest, envelope)
    log_index, _checkpoint = originstore.append_log_leaf(
        origin_store, root_kid, event="publish", digest=digest, release_private_key=release_sk, release_key_id=release_kid
    )
    originstore.write_current_pointer(origin_store, root_kid, "bert-tiny", "1.2.0", digest, log_index=log_index)

    _doc, canonical, snapshot_digest = build_and_digest_snapshot(
        publisher=root_kid,
        artifacts={
            "bert-tiny": {
                "current_version": "1.2.0",
                "versions": {"1.2.0": {"seq": 1, "manifest_digest": digest, "log_index": log_index}},
            }
        },
    )
    originstore.write_snapshot(origin_store, root_kid, snapshot_digest, canonical)
    stmt = build_timestamp_statement(publisher=root_kid, seq=1, snapshot_digest=snapshot_digest)
    ts_envelope = sign_timestamp(stmt, timestamp_sk, timestamp_kid)
    originstore.write_timestamp(origin_store, root_kid, ts_envelope)

    return {"fingerprint": root_kid, "manifest_digest": digest, "src": src}


async def test_mirror_sync_then_fetch_from_mirror(tmp_path, origin_store, published_artifact):
    fingerprint = published_artifact["fingerprint"]

    origin_server = TestServer(build_app(origin_store))
    await origin_server.start_server()

    mirror_store = tmp_path / "mirror"
    runner = CliRunner()
    try:
        result = await invoke(
            runner,
            ["mirror", "sync", fingerprint, "--from", str(origin_server.make_url("")), "--store", str(mirror_store)],
        )
        assert result.exit_code == 0, result.output
        assert "synced:" in result.output

        # The mirror now serves the exact same routes, from its own copy.
        mirror_server = TestServer(build_app(mirror_store))
        await mirror_server.start_server()
        try:
            consumer_home = tmp_path / "consumer"
            store_mod.ensure_layout(consumer_home)
            trust_store.add_pin(consumer_home, "acme-lab", fingerprint)

            async with PeerPool(consumer_home, [str(mirror_server.make_url(""))]) as pool:
                fetch_result = await fetch_flow_fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")

            assert fetch_result["ok"] is True, fetch_result
            materialized = Path(fetch_result["materialized"])
            assert (materialized / "big.bin").read_bytes() == (published_artifact["src"] / "big.bin").read_bytes()
            assert (materialized / "small.bin").read_bytes() == (published_artifact["src"] / "small.bin").read_bytes()
        finally:
            await mirror_server.close()
    finally:
        await origin_server.close()


async def test_mirror_sync_ingests_chunks_into_cas(tmp_path, origin_store, published_artifact):
    from vouch import cas as cas_mod

    fingerprint = published_artifact["fingerprint"]
    origin_server = TestServer(build_app(origin_store))
    await origin_server.start_server()
    mirror_store = tmp_path / "mirror"
    runner = CliRunner()
    try:
        result = await invoke(
            runner,
            ["mirror", "sync", fingerprint, "--from", str(origin_server.make_url("")), "--store", str(mirror_store)],
        )
        assert result.exit_code == 0, result.output

        envelope = originstore.read_manifest_envelope(mirror_store, published_artifact["manifest_digest"])
        manifest = json.loads(base64.b64decode(envelope["payload"]))
        for file_entry in manifest["files"]:
            for chunk_digest in file_entry["chunks"]:
                assert cas_mod.has_object(mirror_store, chunk_digest)
    finally:
        await origin_server.close()


async def test_mirror_sync_rejects_missing_publisher(tmp_path, origin_store, published_artifact):
    origin_server = TestServer(build_app(origin_store))
    await origin_server.start_server()
    mirror_store = tmp_path / "mirror"
    runner = CliRunner()
    try:
        result = await invoke(
            runner,
            ["mirror", "sync", "b3:" + "0" * 64, "--from", str(origin_server.make_url("")), "--store", str(mirror_store)],
        )
        assert result.exit_code != 0
    finally:
        await origin_server.close()
