"""T2B-REPLAY-ROLLBACK, per 03_SECURITY_AND_ACCESS.md section 4:

"mirror serves last month's valid-but-superseded metadata to freeze a
victim on a withdrawn release. Primary mitigation: timestamp role: signed,
TTL-bounded, monotonic seq; consumer-persisted high-water marks; snapshot
digest-bound to timestamp."

Scenario: publish v1, reissue-timestamp (seq 1); the consumer fetches v1,
establishing high-water marks. The publisher then publishes v2 and
reissues the timestamp (seq 2); the consumer fetches v2, advancing the
marks further. A "stale mirror" -- a byte-exact copy of the origin as it
stood right after the SEQ-1 reissue, which is a legitimate state that
genuinely existed, not a forgery -- is then served to the same consumer.
The consumer must reject it as a rollback (exit 31) rather than silently
accepting metadata it has already seen superseded.
"""

from __future__ import annotations

import base64
import json
import os
import shutil

import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import fetch_flow, originstore, store as store_mod, trust_store
from vouch.chunking import CHUNK_SIZE
from vouch.httpserver import build_app
from vouch.keys import key_id, public_bytes
from vouch.manifest import build_manifest, manifest_digest, sign_manifest
from vouch.peers import PeerPool
from vouch.root import build_root_doc, sign_root_doc
from vouch.snapshot import build_and_digest_snapshot
from vouch.timestamp import build_timestamp_statement, sign_timestamp

pytestmark = pytest.mark.asyncio


def _reissue_timestamp(origin_store, fingerprint, timestamp_sk, timestamp_kid):
    artifacts = {}
    for artifact in originstore.list_artifacts(origin_store, fingerprint):
        versions = {}
        best_version, best_seq = None, -1
        for version in originstore.list_versions(origin_store, fingerprint, artifact):
            pointer = originstore.read_current_pointer(origin_store, fingerprint, artifact, version)
            manifest_env = originstore.read_manifest_envelope(origin_store, pointer["digest"])
            seq = json.loads(base64.b64decode(manifest_env["payload"]))["seq"]
            versions[version] = {"seq": seq, "manifest_digest": pointer["digest"], "log_index": pointer.get("log_index")}
            if seq > best_seq:
                best_seq, best_version = seq, version
        artifacts[artifact] = {"current_version": best_version, "versions": versions}

    _doc, canonical, digest = build_and_digest_snapshot(publisher=fingerprint, artifacts=artifacts)
    originstore.write_snapshot(origin_store, fingerprint, digest, canonical)
    seq = originstore.next_timestamp_seq(origin_store, fingerprint)
    stmt = build_timestamp_statement(publisher=fingerprint, seq=seq, snapshot_digest=digest)
    envelope = sign_timestamp(stmt, timestamp_sk, timestamp_kid)
    originstore.write_timestamp(origin_store, fingerprint, envelope)


async def test_t2b_stale_mirror_replay_rejected_as_rollback(tmp_path):
    origin_store = tmp_path / "origin"
    store_mod.ensure_layout(origin_store)
    consumer_home = tmp_path / "consumer"
    store_mod.ensure_layout(consumer_home)

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
    originstore.write_root_doc(origin_store, root_kid, 1, sign_root_doc(root_doc, root_sk, root_kid))

    trust_store.add_pin(consumer_home, "acme-lab", root_kid)

    # --- v1: publish, reissue-timestamp (seq 1), consumer fetches it ---
    src_v1 = tmp_path / "src_v1"
    src_v1.mkdir()
    (src_v1 / "model.bin").write_bytes(b"v1 weights" * 50)
    m1 = build_manifest(src_v1, origin_store, publisher=root_kid, name="bert-tiny", version="1.0.0", seq=1, artifact_type="model")
    d1 = manifest_digest(m1)
    originstore.write_manifest_envelope(origin_store, d1, sign_manifest(m1, release_sk, release_kid))
    log_index1, _cp1 = originstore.append_log_leaf(
        origin_store, root_kid, event="publish", digest=d1, release_private_key=release_sk, release_key_id=release_kid
    )
    originstore.write_current_pointer(origin_store, root_kid, "bert-tiny", "1.0.0", d1, log_index=log_index1)
    _reissue_timestamp(origin_store, root_kid, timestamp_sk, timestamp_kid)

    server = TestServer(build_app(origin_store))
    await server.start_server()
    try:
        async with PeerPool(consumer_home, [str(server.make_url(""))]) as pool:
            result_v1 = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.0.0")
        assert result_v1["ok"] is True, result_v1

        # Snapshot the origin's on-disk state right here -- a legitimate
        # state that genuinely existed, the "last month's metadata" a stale
        stale_mirror_store = tmp_path / "stale_mirror"
        src_path = str(origin_store.resolve())
        dst_path = str(stale_mirror_store.resolve())
        if os.name == "nt":
            src_path = "\\\\?\\" + src_path
            dst_path = "\\\\?\\" + dst_path
        shutil.copytree(src_path, dst_path)

        # --- v2: publish, reissue-timestamp (seq 2), consumer fetches it ---
        src_v2 = tmp_path / "src_v2"
        src_v2.mkdir()
        (src_v2 / "model.bin").write_bytes(b"v2 weights, new and improved" * 50)
        m2 = build_manifest(src_v2, origin_store, publisher=root_kid, name="bert-tiny", version="2.0.0", seq=2, artifact_type="model")
        d2 = manifest_digest(m2)
        originstore.write_manifest_envelope(origin_store, d2, sign_manifest(m2, release_sk, release_kid))
        log_index2, _cp2 = originstore.append_log_leaf(
            origin_store, root_kid, event="publish", digest=d2, release_private_key=release_sk, release_key_id=release_kid
        )
        originstore.write_current_pointer(origin_store, root_kid, "bert-tiny", "2.0.0", d2, log_index=log_index2)
        _reissue_timestamp(origin_store, root_kid, timestamp_sk, timestamp_kid)

        async with PeerPool(consumer_home, [str(server.make_url(""))]) as pool:
            result_v2 = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@2.0.0")
        assert result_v2["ok"] is True, result_v2
    finally:
        await server.close()

    # --- the stale mirror, frozen at the seq-1 state, is now the consumer's only source ---
    stale_server = TestServer(build_app(stale_mirror_store))
    await stale_server.start_server()
    try:
        async with PeerPool(consumer_home, [str(stale_server.make_url(""))]) as pool:
            result_stale = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.0.0")
    finally:
        await stale_server.close()

    assert result_stale["ok"] is False
    assert result_stale["exit_code"] == 31
    fail_check = next(c for c in result_stale["checks"] if not c["ok"])
    assert fail_check["id"] == "V4"
