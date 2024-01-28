"""T4C-REVOCATION, per 03_SECURITY_AND_ACCESS.md section 5.5 (D13: fail
closed, retroactive, no time-based carve-out).

"A release key is suspected compromised (leaked from CI, stolen laptop).
The publisher must be able to invalidate it immediately, including for
signatures made before anyone knew it was compromised." Primary
mitigation: a revoked key's signature is rejected everywhere, and
`vouch status` flags artifacts already materialized under it.
"""

from __future__ import annotations

import base64
import json

import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import fetch_flow, originstore, status as status_mod, store as store_mod, trust_store
from vouch.errors import KeyRevokedError
from vouch.fetch_flow import STATUS_BREADCRUMB_NAME
from vouch.httpclient import OriginClient
from vouch.httpserver import build_app
from vouch.keys import key_id, public_bytes
from vouch.manifest import build_manifest, manifest_digest, sign_manifest, verify_manifest_envelope
from vouch.peers import PeerPool
from vouch.root import build_root_doc, revoked_key_ids, sign_root_doc
from vouch.snapshot import build_and_digest_snapshot
from vouch.timestamp import build_timestamp_statement, sign_timestamp


def _new_keypair():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return sk, pub, key_id(pub)


def test_t4c_unit_revoked_signer_rejected_even_though_cryptographically_valid():
    release_sk, release_pub, release_kid = _new_keypair()

    payload_manifest = {
        "vouch": "manifest/v1",
        "publisher": "b3:" + "1" * 64,
        "name": "bert-tiny",
        "version": "1.0.0",
        "seq": 1,
        "type": "model",
        "created": "2026-01-01T00:00:00Z",
        "files": [],
        "total_size": 0,
        "record_index": None,
        "provenance": None,
    }
    envelope = sign_manifest(payload_manifest, release_sk, release_kid)
    digest = manifest_digest(payload_manifest)

    # Valid, no revocations: passes.
    verify_manifest_envelope(
        envelope,
        authorized_keys={release_kid: release_pub},
        expected_digest=digest,
        publisher=payload_manifest["publisher"],
        name="bert-tiny",
        version="1.0.0",
    )

    # A root version 2 revokes release_kid; once its revoked_keys are
    # threaded in, the SAME signature over the SAME bytes must now fail --
    # no re-signing, no re-fetch, nothing about the manifest itself changed.
    root_sk, root_pub, root_kid = _new_keypair()
    doc2 = build_root_doc(
        publisher=root_kid, root_keys=[(root_kid, root_pub)], root_version=1,
        revoked=[{"id": release_kid, "at": "2026-01-02T00:00:00Z", "reason": "compromised"}],
    )
    revoked = revoked_key_ids(doc2)
    assert release_kid in revoked

    with pytest.raises(KeyRevokedError):
        verify_manifest_envelope(
            envelope,
            authorized_keys={release_kid: release_pub},
            expected_digest=digest,
            publisher=payload_manifest["publisher"],
            name="bert-tiny",
            version="1.0.0",
            revoked_keys=revoked,
        )


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
    originstore.write_timestamp(origin_store, fingerprint, sign_timestamp(stmt, timestamp_sk, timestamp_kid))


def _publish(origin_store, fingerprint, name, version, seq, src, release_sk, release_kid):
    manifest = build_manifest(
        src, origin_store, publisher=fingerprint, name=name, version=version, seq=seq, artifact_type="model"
    )
    digest = manifest_digest(manifest)
    originstore.write_manifest_envelope(origin_store, digest, sign_manifest(manifest, release_sk, release_kid))
    log_index, _cp = originstore.append_log_leaf(
        origin_store, fingerprint, event="publish", digest=digest, release_private_key=release_sk, release_key_id=release_kid
    )
    originstore.write_current_pointer(origin_store, fingerprint, name, version, digest, log_index=log_index)
    return digest


@pytest.mark.asyncio
async def test_t4c_e2e_compromised_key_still_in_use_after_revocation_is_rejected(tmp_path, origin_store, consumer_home):
    root_sk, root_pub, root_kid = _new_keypair()
    release_sk, release_pub, release_kid = _new_keypair()
    timestamp_sk, timestamp_pub, timestamp_kid = _new_keypair()

    doc1 = build_root_doc(
        publisher=root_kid,
        root_keys=[(root_kid, root_pub)],
        release_keys=[(release_kid, release_pub)],
        timestamp_keys=[(timestamp_kid, timestamp_pub)],
    )
    originstore.write_root_doc(origin_store, root_kid, 1, sign_root_doc(doc1, root_sk, root_kid))

    src1 = tmp_path / "src1"
    src1.mkdir()
    (src1 / "model.bin").write_bytes(b"legitimate v1 weights" * 20)
    _publish(origin_store, root_kid, "bert-tiny", "1.0.0", 1, src1, release_sk, release_kid)
    _reissue_timestamp(origin_store, root_kid, timestamp_sk, timestamp_kid)

    trust_store.add_pin(consumer_home, "acme-lab", root_kid)

    server = TestServer(build_app(origin_store))
    await server.start_server()
    try:
        # v1, before revocation: fetches cleanly and materializes.
        async with PeerPool(consumer_home, [str(server.make_url(""))]) as pool:
            result_v1 = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.0.0")
        assert result_v1["ok"] is True, result_v1

        # The release key is now revoked (root v2) -- the SAME root key
        # signs the revocation (no rotation, just a revocation entry).
        doc2 = build_root_doc(
            publisher=root_kid,
            root_keys=[(root_kid, root_pub)],
            release_keys=[(release_kid, release_pub)],
            timestamp_keys=[(timestamp_kid, timestamp_pub)],
            root_version=2,
            revoked=[{"id": release_kid, "at": "2026-01-02T00:00:00Z", "reason": "compromised"}],
        )
        originstore.write_root_doc(origin_store, root_kid, 2, sign_root_doc(doc2, root_sk, root_kid))

        # An attacker who still holds the compromised key publishes v2.
        src2 = tmp_path / "src2"
        src2.mkdir()
        (src2 / "model.bin").write_bytes(b"attacker-controlled v2 weights" * 20)
        _publish(origin_store, root_kid, "bert-tiny", "2.0.0", 2, src2, release_sk, release_kid)
        _reissue_timestamp(origin_store, root_kid, timestamp_sk, timestamp_kid)

        async with PeerPool(consumer_home, [str(server.make_url(""))]) as pool:
            result_v2 = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@2.0.0")
        assert result_v2["ok"] is False
        assert result_v2["exit_code"] == 42
        fail_check = next(c for c in result_v2["checks"] if not c["ok"])
        assert fail_check["id"] == "V6"

        # `status` reconciles the PRE-revocation-materialized v1 artifact
        # against the now-current (v2) root and flags it, even though v1
        # itself was never re-verified or touched.
        breadcrumb_path = (
            consumer_home / "verified" / "acme-lab" / "bert-tiny" / "1.0.0" / STATUS_BREADCRUMB_NAME
        )
        assert breadcrumb_path.is_file()

        async with OriginClient(str(server.make_url(""))) as client:
            status_result = await status_mod.check_publisher(consumer_home, client, "acme-lab")
    finally:
        await server.close()

    assert status_result["artifacts"] == [
        {
            "artifact": "bert-tiny",
            "version": "1.0.0",
            "manifest_digest": result_v1["artifact"]["digest"],
            "release_key_id": release_kid,
            "revoked": True,
        }
    ]
