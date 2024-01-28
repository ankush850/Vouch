"""T6A-ECLIPSE-FREEZE, per 03_SECURITY_AND_ACCESS.md section 4:

"attacker controls all of a victim's peers and withholds fresh metadata.
Primary mitigation: freshness hard-fails when the TTL lapses (exit 30),
so an eclipse converts to a loud availability failure, never silent stale
data; metadata fetched from >=2 sources when configured; pinned mirrors
recommended."

Two sub-cases, both simulating "every configured peer is attacker-
controlled" via a multi-peer pool where NONE of the peers can produce a
fresh, obtainable timestamp: (a) peers serve a genuinely expired but
validly-signed timestamp (the literal "freeze" -- a statement that was
once legitimate but has since lapsed); (b) peers have no timestamp at all
obtainable (StaleError's "no timestamp obtainable" path). Both must fail
loud with exit 30 and V4 as the failing check, never silently accept
stale metadata, and never hang regardless of how many eclipsing peers are
configured -- `_try_each_peer` (fetch_flow.py) already bounds this to one
pass per peer with no retry loop.
"""

from __future__ import annotations

import os
import shutil
from datetime import timedelta

import pytest
from aiohttp.test_utils import TestServer

from vouch import fetch_flow, originstore, store as store_mod, trust_store
from vouch.httpserver import build_app
from vouch.peers import PeerPool
from vouch.timeutil import format_iso8601, utc_now
from vouch.timestamp import build_timestamp_statement, sign_timestamp

pytestmark = pytest.mark.asyncio


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


async def _eclipsing_pool(tmp_path, origin_store, n: int):
    """N independent TestServers, each a byte-for-byte copy of
    `origin_store` at whatever state it's currently in -- N attacker-
    controlled peers. An eclipse doesn't require the attacker's peers to
    disagree with each other (that would be T5B), just to jointly
    withhold freshness from the victim.
    """
    servers = []
    urls = []
    for i in range(n):
        copy_path = tmp_path / f"eclipse_{i}"
        src_p = str(origin_store.resolve())
        dst_p = str(copy_path.resolve())
        if os.name == "nt":
            src_p = "\\\\?\\" + src_p
            dst_p = "\\\\?\\" + dst_p
        shutil.copytree(src_p, dst_p)
        server = TestServer(build_app(copy_path))
        await server.start_server()
        servers.append(server)
        urls.append(str(server.make_url("")))
    return servers, urls


async def test_t6a_eclipse_via_expired_timestamp(tmp_path, consumer_home, published_artifact, origin_store):
    fingerprint = published_artifact["fingerprint"]
    timestamp_sk = published_artifact["timestamp_sk"]
    timestamp_kid = published_artifact["timestamp_kid"]

    # Overwrite the origin's timestamp with one that was validly issued
    # but has since lapsed -- the literal "freeze."
    issued = format_iso8601(utc_now() - timedelta(hours=48))
    stmt = build_timestamp_statement(
        publisher=fingerprint,
        seq=99,
        snapshot_digest=published_artifact["snapshot_digest"],
        issued=issued,
        ttl=timedelta(hours=24),
    )
    envelope = sign_timestamp(stmt, timestamp_sk, timestamp_kid)
    originstore.write_timestamp(origin_store, fingerprint, envelope)

    trust_store.add_pin(consumer_home, "acme-lab", fingerprint)
    servers, urls = await _eclipsing_pool(tmp_path, origin_store, 3)
    try:
        async with PeerPool(consumer_home, urls) as pool:
            result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")
    finally:
        for s in servers:
            await s.close()

    assert result["ok"] is False
    assert result["exit_code"] == 30
    fail_check = next(c for c in result["checks"] if not c["ok"])
    assert fail_check["id"] == "V4"
    assert not (consumer_home / "verified").exists() or not list((consumer_home / "verified").iterdir())


async def test_t6a_eclipse_via_no_timestamp_obtainable(tmp_path, consumer_home, published_artifact, origin_store):
    fingerprint = published_artifact["fingerprint"]

    # Delete the timestamp entirely -- every peer still has a valid root
    # document (V2 succeeds) but none can produce ANY timestamp statement.
    originstore.timestamp_path(origin_store, fingerprint).unlink()

    trust_store.add_pin(consumer_home, "acme-lab", fingerprint)
    servers, urls = await _eclipsing_pool(tmp_path, origin_store, 3)
    try:
        async with PeerPool(consumer_home, urls) as pool:
            result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")
    finally:
        for s in servers:
            await s.close()

    assert result["ok"] is False
    assert result["exit_code"] == 30
    fail_check = next(c for c in result["checks"] if not c["ok"])
    assert fail_check["id"] == "V4"
    assert not (consumer_home / "verified").exists() or not list((consumer_home / "verified").iterdir())
