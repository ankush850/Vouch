"""M4 chaos scenario, per 03_SECURITY_AND_ACCESS.md section 9: "a chaos
scenario combining T1, T2b, and T6a simultaneously against one fetch."

T1 (tampering mirror), T2b (stale/superseded mirror), and T6a (withholding/
eclipsing peers) are all configured in the SAME `PeerPool` at once, rather
than each proven in isolation as their own dedicated adversarial test.

Two variants, against the same evolving setup: publish v1, reissue
timestamp (seq 1), consumer fetches v1 (establishes the timestamp
high-water mark at seq 1) through the plain honest origin. `shutil.
copytree` the origin store at this exact point -- peer `S`, T2b's frozen,
once-legitimate-now-superseded state. Publish v2, reissue timestamp
(seq 2) on the live store (signed by a second release key delegated via a
root v2 -- `published_artifact`'s original release private key isn't
exposed by the fixture, and a same-keys root bump needs only the already-
exposed root key to self-sign, matching the M3 "revoke" ceremony's
same-keys-unchanged reasoning).

- **Variant A** (an honest peer survives among the chaos): the consumer,
  still only at hwm=1, fetches v2 through a pool of `T` (T1, `conftest.py`'s
  `TamperingProxy` in front of the live honest origin `H`, corrupting v2's
  target chunk, `random` monkeypatched exactly as `test_t1_mirror_tamper.py`
  does to force it tried and blacklisted deterministically), `H` itself,
  `E1-E3` (T6a, real servers with nothing published -- instant
  NetworkError everywhere), and `S` (T2b, offers seq=1 which merely
  matches the not-yet-advanced hwm -- an honest, once-current, just-older
  snapshot, not a rollback or equivocation; ordered last so metadata
  resolution reaches `T`/`H` first rather than locking onto `S`'s v2-less
  state and failing the whole fetch at V6 before an honest source is ever
  tried). Must succeed: exit 0, correct bytes materialized, `T` blacklisted
  with a large score penalty and scored strictly worse than `H`. This also
  advances the consumer's hwm to seq 2.
- **Variant B** (total chaos, no honest peer left): the SAME consumer,
  now at hwm=2 after Variant A, is pointed at a pool of only `E1-E3` and
  `S` -- and this time `S`'s frozen seq=1 IS a rollback relative to the
  consumer's own advanced hwm. Every peer must fail; the fetch must fail
  loud (never silently accept `S`'s now-stale-relative-to-what-this-
  consumer-has-already-seen state), never hang, and materialize nothing
  new.
"""

from __future__ import annotations

import base64
import json
import os
import shutil

import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import fetch_flow, originstore, peers as peers_mod, store as store_mod, trust_store
from vouch import root as root_mod
from vouch.httpserver import build_app
from vouch.keys import key_id, public_bytes
from vouch.manifest import build_manifest, manifest_digest, sign_manifest
from vouch.peers import PeerPool
from vouch.snapshot import build_and_digest_snapshot
from vouch.store import peers_path
from vouch.timestamp import build_timestamp_statement, sign_timestamp

pytestmark = pytest.mark.asyncio


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


def _decode(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"], validate=True))


def _reissue_timestamp(origin_store, fingerprint, ts_sk, ts_kid):
    artifacts = {}
    for artifact in originstore.list_artifacts(origin_store, fingerprint):
        versions = {}
        best_version, best_seq = None, -1
        for version in originstore.list_versions(origin_store, fingerprint, artifact):
            pointer = originstore.read_current_pointer(origin_store, fingerprint, artifact, version)
            seq = _decode(originstore.read_manifest_envelope(origin_store, pointer["digest"]))["seq"]
            versions[version] = {"seq": seq, "manifest_digest": pointer["digest"], "log_index": pointer.get("log_index")}
            if seq > best_seq:
                best_seq, best_version = seq, version
        artifacts[artifact] = {"current_version": best_version, "versions": versions}

    _doc, canonical, digest = build_and_digest_snapshot(publisher=fingerprint, artifacts=artifacts)
    originstore.write_snapshot(origin_store, fingerprint, digest, canonical)
    seq = originstore.next_timestamp_seq(origin_store, fingerprint)
    stmt = build_timestamp_statement(publisher=fingerprint, seq=seq, snapshot_digest=digest)
    originstore.write_timestamp(origin_store, fingerprint, sign_timestamp(stmt, ts_sk, ts_kid))


async def _withholding_peers(tmp_path, n: int):
    servers, urls = [], []
    for i in range(n):
        path = tmp_path / f"eclipse_{i}"
        store_mod.ensure_layout(path)
        server = TestServer(build_app(path))
        await server.start_server()
        servers.append(server)
        urls.append(str(server.make_url("")))
    return servers, urls


def _publish_v2_with_a_second_release_key(origin_store, published_artifact, src_v2):
    """Publish v2, delegating a second release key via a same-root-keys
    root v2 bump (published_artifact's original release private key isn't
    exposed by the fixture; the root's own key IS, and since `keys.root`
    doesn't change, one self-signature satisfies both `verify_root_link`'s
    prev- and next-threshold checks -- same reasoning as the M3 "revoke"
    ceremony). Returns (manifest, digest, chunk_digest).
    """
    fingerprint = published_artifact["fingerprint"]
    root_sk = published_artifact["root_sk"]
    root_pub = published_artifact["root_pub"]

    root_doc_v1 = _decode(originstore.read_root_doc(origin_store, fingerprint, 1))
    release2_sk = Ed25519PrivateKey.generate()
    release2_pub = public_bytes(release2_sk.public_key())
    release2_kid = key_id(release2_pub)

    new_root_doc = root_mod.build_root_doc(
        publisher=fingerprint,
        root_keys=[(fingerprint, root_pub)],
        release_keys=[(e["id"], base64.b64decode(e["pub"])) for e in root_doc_v1["keys"]["release"]]
        + [(release2_kid, release2_pub)],
        timestamp_keys=[(e["id"], base64.b64decode(e["pub"])) for e in root_doc_v1["keys"]["timestamp"]],
        root_version=2,
    )
    originstore.write_root_doc(origin_store, fingerprint, 2, root_mod.sign_root_doc(new_root_doc, root_sk, fingerprint))

    manifest = build_manifest(
        src_v2, origin_store, publisher=fingerprint, name="bert-tiny", version="2.0.0", seq=2, artifact_type="model"
    )
    digest = manifest_digest(manifest)
    originstore.write_manifest_envelope(origin_store, digest, sign_manifest(manifest, release2_sk, release2_kid))
    log_index, _cp = originstore.append_log_leaf(
        origin_store, fingerprint, event="publish", digest=digest,
        release_private_key=release2_sk, release_key_id=release2_kid,
    )
    originstore.write_current_pointer(origin_store, fingerprint, "bert-tiny", "2.0.0", digest, log_index=log_index)
    return manifest, digest, manifest["files"][0]["chunks"][0]


async def test_m4_chaos_scenario(
    tmp_path, consumer_home, published_artifact, origin_store, fake_origin, tampering_proxy_factory, monkeypatch
):
    fingerprint = published_artifact["fingerprint"]

    # Establish the baseline: consumer fetches v1 through the plain honest
    # origin, advancing its timestamp hwm to seq 1.
    trust_store.add_pin(consumer_home, "acme-lab", fingerprint)
    async with PeerPool(consumer_home, [str(fake_origin.make_url(""))]) as pool:
        baseline = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")
    assert baseline["ok"] is True, baseline

    # Reset peer scores (but not the rollback high-water marks in
    # trust_store, a separate file) before the chaos pools -- otherwise
    # the honest peer's already-high score from the baseline fetch alone
    # would make `clients_by_score()` route every metadata check straight
    # to it, and the chaos peers configured below would never actually be
    # exercised at all.
    peers_path(consumer_home).unlink(missing_ok=True)

    stale_store = tmp_path / "stale_S"
    src_p = str(origin_store.resolve())
    dst_p = str(stale_store.resolve())
    if os.name == "nt":
        src_p = "\\\\?\\" + src_p
        dst_p = "\\\\?\\" + dst_p
    shutil.copytree(src_p, dst_p)

    # Publish v2 on the live store; `fake_origin` serves it immediately
    # (it reads origin_store live, no restart needed).
    src_v2 = tmp_path / "src_v2"
    src_v2.mkdir()
    (src_v2 / "weights.bin").write_bytes(b"v2, chaos scenario target" * 50)
    _manifest_v2, _digest_v2, chunk_digest_v2 = _publish_v2_with_a_second_release_key(
        origin_store, published_artifact, src_v2
    )
    _reissue_timestamp(origin_store, fingerprint, published_artifact["timestamp_sk"], published_artifact["timestamp_kid"])

    # --- Variant A: chaos, but an honest peer survives ---
    e_servers, e_urls = await _withholding_peers(tmp_path, 3)
    stale_server = TestServer(build_app(stale_store))
    await stale_server.start_server()

    proxy = await tampering_proxy_factory(chunk_digest_v2)
    tampering_url = proxy.base_url()
    honest_url = proxy.upstream  # fake_origin's own URL

    def _fake_choice(seq):
        # Prefer the tampering peer while it's still healthy (so it gets
        # tried and blacklisted); once blacklisted, prefer the honest peer
        # over the eclipse/stale Sybils rather than falling back to
        # whichever happens to be first in the pool's insertion order.
        if tampering_url in seq:
            return tampering_url
        if honest_url in seq:
            return honest_url
        return seq[0]

    monkeypatch.setattr(peers_mod.random, "random", lambda: 0.0)
    monkeypatch.setattr(peers_mod.random, "choice", _fake_choice)

    # Metadata resolution (V2/V4/V5/V6) goes through `clients_by_score()`,
    # score-ordered with ties broken by insertion order -- since every peer
    # starts tied at DEFAULT_SCORE, `tampering_url`/`honest_url` are listed
    # FIRST so metadata resolves through them (root/timestamp/manifest
    # responses are untouched by the chunk-specific tamper), matching what
    # V8's chunk-fetch monkeypatch also forces. `S` legitimately matches
    # the not-yet-advanced hwm (no rollback, no equivocation -- it's an
    # honest, once-current snapshot, just older), so if it were tried
    # first it would "succeed" at V2/V4/V5 with its stale, v2-less
    # snapshot and lock the whole fetch into a V6 ReferenceNotFoundError
    # before ever reaching an honest source -- exactly the failure mode a
    # real multi-peer consumer must avoid, which is why peer-list ordering
    # (an availability/scoring concern, not a trust one) matters here.
    chaos_urls_a = [tampering_url, honest_url] + e_urls + [str(stale_server.make_url(""))]
    async with PeerPool(consumer_home, chaos_urls_a) as pool:
        result_a = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@2.0.0")

    assert result_a["ok"] is True, result_a
    assert result_a["exit_code"] == 0
    materialized = consumer_home / "verified" / "acme-lab" / "bert-tiny" / "2.0.0" / "weights.bin"
    assert materialized.read_bytes() == (src_v2 / "weights.bin").read_bytes()

    # T took the large, immediate MISMATCH_PENALTY hit and was blacklisted
    # (any metadata successes it also racked up before the mismatch --
    # untouched by the chunk-specific tamper -- don't erase that): its
    # final score is still negative and strictly worse than the honest
    # peer's.
    scores = peers_mod.load_scores(consumer_home)
    assert scores[tampering_url] < peers_mod.DEFAULT_SCORE
    assert scores.get(honest_url, peers_mod.DEFAULT_SCORE) > scores[tampering_url]

    # --- Variant B: total chaos, no honest peer left ---
    chaos_urls_b = e_urls + [str(stale_server.make_url(""))]
    async with PeerPool(consumer_home, chaos_urls_b) as pool:
        result_b = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@2.0.0")

    await stale_server.close()
    for s in e_servers:
        await s.close()

    assert result_b["ok"] is False
    assert result_b["exit_code"] in (30, 31, 21)
    fail_check = next(c for c in result_b["checks"] if not c["ok"])
    assert fail_check["id"] in ("V2", "V4", "V5", "V6")
    # No THIRD version appeared, and v2 wasn't re-materialized differently.
    assert materialized.read_bytes() == (src_v2 / "weights.bin").read_bytes()
