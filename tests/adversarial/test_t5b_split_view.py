"""T5B-SPLIT-VIEW, per 03_SECURITY_AND_ACCESS.md section 4:

"A publisher (or an attacker holding the release key) shows different
consumers different 'latest' transparency-log states, with nothing to
catch it." Primary mitigation: `cross_check_checkpoints` compares the
primary checkpoint against every OTHER configured peer's checkpoint in
the same session; two release-key-signed checkpoints reporting different
root hashes at the same tree size is unambiguous equivocation.

No monkeypatching needed for determinism here (unlike T1): checkpoint/
metadata resolution goes through `PeerPool.clients_by_score()`, which is
score-ordered with ties broken by insertion order -- not the weighted-
random `select_peer()` chunk scheduling uses -- so which peer serves as
"primary" is already deterministic.
"""

from __future__ import annotations

import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import fetch_flow, originstore, store as store_mod, trust_store
from vouch.httpserver import build_app
from vouch.keys import key_id, public_bytes
from vouch.manifest import build_manifest, manifest_digest, sign_manifest
from vouch.peers import PeerPool
from vouch.root import build_root_doc, sign_root_doc
from vouch.snapshot import build_and_digest_snapshot
from vouch.timestamp import build_timestamp_statement, sign_timestamp

pytestmark = pytest.mark.asyncio


def _new_keypair():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return sk, pub, key_id(pub)


def _seed_store(store, root_kid, root_envelope, release_sk, release_kid, timestamp_sk, timestamp_kid, src, *, leaf_digest=None):
    originstore.write_root_doc(store, root_kid, 1, root_envelope)

    manifest = build_manifest(
        src, store, publisher=root_kid, name="bert-tiny", version="1.0.0", seq=1, artifact_type="model"
    )
    digest = manifest_digest(manifest)
    originstore.write_manifest_envelope(store, digest, sign_manifest(manifest, release_sk, release_kid))
    log_index, checkpoint_envelope = originstore.append_log_leaf(
        store, root_kid, event="publish", digest=leaf_digest or digest,
        release_private_key=release_sk, release_key_id=release_kid,
    )
    originstore.write_current_pointer(store, root_kid, "bert-tiny", "1.0.0", digest, log_index=log_index)

    artifacts = {
        "bert-tiny": {
            "current_version": "1.0.0",
            "versions": {"1.0.0": {"seq": 1, "manifest_digest": digest, "log_index": log_index}},
        }
    }
    _doc, canonical, snapshot_digest = build_and_digest_snapshot(publisher=root_kid, artifacts=artifacts)
    originstore.write_snapshot(store, root_kid, snapshot_digest, canonical)
    stmt = build_timestamp_statement(publisher=root_kid, seq=1, snapshot_digest=snapshot_digest)
    originstore.write_timestamp(store, root_kid, sign_timestamp(stmt, timestamp_sk, timestamp_kid))

    return digest, checkpoint_envelope


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


async def test_t5b_two_sources_report_different_root_hashes_at_the_same_tree_size(tmp_path, consumer_home):
    root_sk, root_pub, root_kid = _new_keypair()
    release_sk, release_pub, release_kid = _new_keypair()
    timestamp_sk, timestamp_pub, timestamp_kid = _new_keypair()

    root_doc = build_root_doc(
        publisher=root_kid,
        root_keys=[(root_kid, root_pub)],
        release_keys=[(release_kid, release_pub)],
        timestamp_keys=[(timestamp_kid, timestamp_pub)],
    )
    root_envelope = sign_root_doc(root_doc, root_sk, root_kid)

    store_a = tmp_path / "origin_a"
    store_b = tmp_path / "origin_b"
    store_mod.ensure_layout(store_a)
    store_mod.ensure_layout(store_b)

    src = tmp_path / "src"
    src.mkdir()
    (src / "weights.bin").write_bytes(b"identical published content" * 20)

    # Source A: honest -- the log leaf's digest matches what was actually published
    # (leaf_digest defaults to the real manifest digest).
    digest_a, _cp_a = _seed_store(
        store_a, root_kid, root_envelope, release_sk, release_kid, timestamp_sk, timestamp_kid, src,
    )
    # Source B: same root/manifest/content, but a DIFFERENT (still
    # release-key-signed) leaf at the same tree position -- the publisher
    # (or whoever holds the release key) showing a different history to a
    # different audience.
    digest_b, _cp_b = _seed_store(
        store_b, root_kid, root_envelope, release_sk, release_kid, timestamp_sk, timestamp_kid, src,
        leaf_digest="b3:" + "b" * 64,
    )
    assert digest_a == digest_b  # the artifact itself is identical; only the log diverges

    trust_store.add_pin(consumer_home, "acme-lab", root_kid)

    server_a = TestServer(build_app(store_a))
    server_b = TestServer(build_app(store_b))
    await server_a.start_server()
    await server_b.start_server()
    try:
        url_a, url_b = str(server_a.make_url("")), str(server_b.make_url(""))
        async with PeerPool(consumer_home, [url_a, url_b]) as pool:
            result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.0.0")
    finally:
        await server_a.close()
        await server_b.close()

    assert result["ok"] is False
    assert result["exit_code"] == 44
    fail_check = next(c for c in result["checks"] if not c["ok"])
    assert fail_check["id"] == "V7"
    assert "equivocation" in fail_check["detail"]

    # Neither checkpoint was accepted as trustworthy -- nothing materialized.
    assert not (consumer_home / "verified").exists() or not list((consumer_home / "verified").iterdir())
