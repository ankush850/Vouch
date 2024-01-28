"""T4B-ROTATION, per 03_SECURITY_AND_ACCESS.md section 5.4 and
02_TECHNICAL_ARCHITECTURE.md section 4.1 (TUF-style cross-signing).

"A publisher must be able to rotate its root key (planned rotation, or
recovery after a suspected compromise) without every consumer having to
re-pin out of band." Primary mitigation: a rotation must be cross-signed
by both the previous root's threshold and the new root's own threshold; a
consumer pinned only to the genesis fingerprint walks the chain over the
network and lands on the current version.
"""

from __future__ import annotations

import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import fetch_flow, originstore, store as store_mod, trust_store
from vouch.dsse import add_signature
from vouch.errors import SignatureError
from vouch.httpserver import build_app
from vouch.keys import key_id, public_bytes
from vouch.manifest import build_manifest, manifest_digest, sign_manifest
from vouch.peers import PeerPool
from vouch.root import build_root_doc, sign_root_doc, verify_root_chain
from vouch.snapshot import build_and_digest_snapshot
from vouch.timestamp import build_timestamp_statement, sign_timestamp


def _new_keypair():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return sk, pub, key_id(pub)


def test_t4b_unit_rotation_missing_cross_signature_rejected():
    root_sk1, root_pub1, root_kid1 = _new_keypair()
    root_sk2, root_pub2, root_kid2 = _new_keypair()

    doc1 = build_root_doc(publisher=root_kid1, root_keys=[(root_kid1, root_pub1)])
    envelope1 = sign_root_doc(doc1, root_sk1, root_kid1)

    doc2 = build_root_doc(publisher=root_kid1, root_keys=[(root_kid2, root_pub2)], root_version=2)
    # Self-signed by the NEW key only -- no cross-signature from the old root key.
    envelope2 = sign_root_doc(doc2, root_sk2, root_kid2)

    with pytest.raises(SignatureError):
        verify_root_chain([envelope1, envelope2], pinned_fingerprint=root_kid1)


def test_t4b_unit_correctly_cross_signed_chain_accepted():
    root_sk1, root_pub1, root_kid1 = _new_keypair()
    root_sk2, root_pub2, root_kid2 = _new_keypair()
    root_sk3, root_pub3, root_kid3 = _new_keypair()

    doc1 = build_root_doc(publisher=root_kid1, root_keys=[(root_kid1, root_pub1)])
    envelope1 = sign_root_doc(doc1, root_sk1, root_kid1)

    doc2 = build_root_doc(publisher=root_kid1, root_keys=[(root_kid2, root_pub2)], root_version=2)
    envelope2 = sign_root_doc(doc2, root_sk2, root_kid2)
    envelope2 = add_signature(envelope2, root_sk1, root_kid1)

    doc3 = build_root_doc(publisher=root_kid1, root_keys=[(root_kid3, root_pub3)], root_version=3)
    envelope3 = sign_root_doc(doc3, root_sk3, root_kid3)
    envelope3 = add_signature(envelope3, root_sk2, root_kid2)

    final_doc, revoked = verify_root_chain([envelope1, envelope2, envelope3], pinned_fingerprint=root_kid1)
    assert final_doc["root_version"] == 3
    assert revoked == frozenset()


@pytest.fixture
def origin_store(tmp_path):
    origin = tmp_path / "origin"
    store_mod.ensure_layout(origin)
    return origin


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


@pytest.mark.asyncio
async def test_t4b_e2e_consumer_pinned_to_genesis_walks_to_current_head(tmp_path, origin_store, consumer_home):
    root_sk1, root_pub1, root_kid1 = _new_keypair()
    root_sk2, root_pub2, root_kid2 = _new_keypair()
    root_sk3, root_pub3, root_kid3 = _new_keypair()
    release_sk, release_pub, release_kid = _new_keypair()
    timestamp_sk, timestamp_pub, timestamp_kid = _new_keypair()

    doc1 = build_root_doc(
        publisher=root_kid1,
        root_keys=[(root_kid1, root_pub1)],
        release_keys=[(release_kid, release_pub)],
        timestamp_keys=[(timestamp_kid, timestamp_pub)],
    )
    originstore.write_root_doc(origin_store, root_kid1, 1, sign_root_doc(doc1, root_sk1, root_kid1))

    doc2 = build_root_doc(
        publisher=root_kid1,
        root_keys=[(root_kid2, root_pub2)],
        release_keys=[(release_kid, release_pub)],
        timestamp_keys=[(timestamp_kid, timestamp_pub)],
        root_version=2,
    )
    envelope2 = sign_root_doc(doc2, root_sk2, root_kid2)
    envelope2 = add_signature(envelope2, root_sk1, root_kid1)
    originstore.write_root_doc(origin_store, root_kid1, 2, envelope2)

    doc3 = build_root_doc(
        publisher=root_kid1,
        root_keys=[(root_kid3, root_pub3)],
        release_keys=[(release_kid, release_pub)],
        timestamp_keys=[(timestamp_kid, timestamp_pub)],
        root_version=3,
    )
    envelope3 = sign_root_doc(doc3, root_sk3, root_kid3)
    envelope3 = add_signature(envelope3, root_sk2, root_kid2)
    originstore.write_root_doc(origin_store, root_kid1, 3, envelope3)

    src = tmp_path / "src"
    src.mkdir()
    (src / "weights.bin").write_bytes(b"post-rotation release" * 20)
    manifest = build_manifest(
        src, origin_store, publisher=root_kid1, name="bert-tiny", version="1.0.0", seq=1, artifact_type="model"
    )
    digest = manifest_digest(manifest)
    originstore.write_manifest_envelope(origin_store, digest, sign_manifest(manifest, release_sk, release_kid))
    log_index, _cp = originstore.append_log_leaf(
        origin_store, root_kid1, event="publish", digest=digest, release_private_key=release_sk, release_key_id=release_kid
    )
    originstore.write_current_pointer(origin_store, root_kid1, "bert-tiny", "1.0.0", digest, log_index=log_index)

    _doc, canonical, snapshot_digest = build_and_digest_snapshot(
        publisher=root_kid1,
        artifacts={
            "bert-tiny": {
                "current_version": "1.0.0",
                "versions": {"1.0.0": {"seq": 1, "manifest_digest": digest, "log_index": log_index}},
            }
        },
    )
    originstore.write_snapshot(origin_store, root_kid1, snapshot_digest, canonical)
    stmt = build_timestamp_statement(publisher=root_kid1, seq=1, snapshot_digest=snapshot_digest)
    originstore.write_timestamp(origin_store, root_kid1, sign_timestamp(stmt, timestamp_sk, timestamp_kid))

    # The consumer only ever pinned the GENESIS fingerprint -- never re-pinned
    # after either rotation.
    trust_store.add_pin(consumer_home, "acme-lab", root_kid1)

    server = TestServer(build_app(origin_store))
    await server.start_server()
    try:
        async with PeerPool(consumer_home, [str(server.make_url(""))]) as pool:
            result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.0.0")
    finally:
        await server.close()

    assert result["ok"] is True, result
    assert trust_store.get_root_version_hwm(consumer_home, "acme-lab") == 3
