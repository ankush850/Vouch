"""T6B-SYBIL-EXHAUST, per 03_SECURITY_AND_ACCESS.md section 4:

"attacker spins up many fake mirrors serving garbage or nothing. Primary
mitigation: endpoint verification makes Sybils unable to poison; per-peer
scoring, session blacklists on digest mismatch, and bounded retries cap
wasted bandwidth; no open DHT exists to capture."

15 Sybils (8 withholding -- real servers with nothing published at all,
an instant 404/NetworkError on every request -- and 7 corrupting -- real
servers with ONLY the target chunk digest present, and wrong bytes at it,
an instant 200-with-wrong-bytes/DigestMismatchError for that one request)
plus 1 honest peer, 16 total. Every Sybil fails INSTANTLY: neither flavor
ever accepts a connection and stalls, which would cost up to
REQUEST_TIMEOUT's 30s per attempt and risk a pathologically slow (or,
with a badly-built fixture, effectively hanging) test -- see
DECISIONS.md. `max_attempts = max(2 * len(pool.base_urls), 2)`
(fetch_flow.py) is 32 for 16 peers; at loopback speed with instant-
failing peers this stays comfortably sub-second.
"""

from __future__ import annotations

import time

import pytest
from aiohttp.test_utils import TestServer

from vouch import cas as cas_mod
from vouch import fetch_flow, peers as peers_mod, store as store_mod, trust_store
from vouch.httpserver import build_app
from vouch.peers import DEFAULT_SCORE, PeerPool

pytestmark = pytest.mark.asyncio

WITHHOLDING_PEER_COUNT = 8
CORRUPTING_PEER_COUNT = 7
WALL_TIME_BOUND_S = 10.0


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


async def _withholding_peers(tmp_path, n: int):
    """Real servers over stores that have nothing published for any
    publisher -- every request 404s instantly.
    """
    servers, urls = [], []
    for i in range(n):
        path = tmp_path / f"withhold_{i}"
        store_mod.ensure_layout(path)
        server = TestServer(build_app(path))
        await server.start_server()
        servers.append(server)
        urls.append(str(server.make_url("")))
    return servers, urls


async def _corrupting_peers(tmp_path, chunk_digest: str, n: int):
    """Stores with ONLY the target chunk digest present, and WRONG bytes at
    it -- deliberately no root/timestamp/manifest, so these peers can only
    ever be reached during V8 chunk fetching (where they always produce an
    instant DigestMismatchError), never accidentally "succeed" at V2/V4/V5/
    V6 metadata resolution the way a full-store copy with just one chunk
    corrupted could (a full copy's metadata is untouched by that
    corruption, so it could rack up real metadata successes before ever
    being asked for the bad chunk -- this minimal store removes that
    ambiguity and keeps every Sybil's behavior uniform at the metadata
    layer, regardless of flavor).
    """
    servers, urls = [], []
    for i in range(n):
        path = tmp_path / f"corrupt_{i}"
        store_mod.ensure_layout(path)
        obj_path = cas_mod.object_path(path, chunk_digest)
        store_mod.atomic_write_bytes(obj_path, b"WRONG BYTES, not the real chunk content")
        server = TestServer(build_app(path))
        await server.start_server()
        servers.append(server)
        urls.append(str(server.make_url("")))
    return servers, urls


async def test_t6b_fetch_succeeds_fast_among_many_sybils(tmp_path, consumer_home, published_artifact, fake_origin):
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])
    chunk_digest = published_artifact["chunk_digest"]

    withhold_servers, withhold_urls = await _withholding_peers(tmp_path, WITHHOLDING_PEER_COUNT)
    corrupt_servers, corrupt_urls = await _corrupting_peers(tmp_path, chunk_digest, CORRUPTING_PEER_COUNT)
    honest_url = str(fake_origin.make_url(""))
    all_urls = withhold_urls + corrupt_urls + [honest_url]
    assert len(all_urls) == WITHHOLDING_PEER_COUNT + CORRUPTING_PEER_COUNT + 1

    try:
        started = time.monotonic()
        async with PeerPool(consumer_home, all_urls) as pool:
            result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")
        elapsed = time.monotonic() - started
    finally:
        for s in withhold_servers + corrupt_servers:
            await s.close()

    assert result["ok"] is True, result
    assert elapsed < WALL_TIME_BOUND_S, f"fetch took {elapsed:.2f}s among {len(all_urls) - 1} Sybils, expected < {WALL_TIME_BOUND_S}s"

    materialized = consumer_home / "verified" / "acme-lab" / "bert-tiny" / "1.2.0" / "weights.bin"
    assert materialized.read_bytes() == published_artifact["src_file"].read_bytes()

    # Scoring discriminates. Metadata resolution (V2/V4/V5/V6) tries peers
    # via `clients_by_score()` -- score-ordered, not weighted-random -- so
    # with all 15 Sybils tied at the same starting score, EVERY one of them
    # is tried and fails at EVERY one of the four metadata checks before
    # the honest peer (last in score order, since it hasn't failed yet
    # either) is reached: 15 guaranteed TRANSPORT_PENALTY hits per Sybil,
    # 4 guaranteed SUCCESS_BONUS hits for the honest peer, regardless of
    # which Sybils chunk-fetching's weighted-random `select_peer()` later
    # happens to touch. This alone guarantees the honest peer ends up
    # strictly best-scored and every Sybil strictly negative, without
    # depending on random selection order for the assertion to hold.
    scores = peers_mod.load_scores(consumer_home)
    honest_score = scores.get(honest_url, DEFAULT_SCORE)
    sybil_urls = withhold_urls + corrupt_urls
    sybil_scores = {url: scores.get(url, DEFAULT_SCORE) for url in sybil_urls}

    assert honest_score > DEFAULT_SCORE
    assert honest_score > max(sybil_scores.values())
    for url, score in sybil_scores.items():
        assert score < DEFAULT_SCORE, f"Sybil {url} should never end up with a non-negative score, got {score}"

    # The severe, immediate, one-shot MISMATCH_PENALTY (blacklist-on-first-
    # hit) mechanism itself is unit-tested directly in test_peers.py and
    # proven live for a single tampering peer in test_t1_mirror_tamper.py;
    # which specific corrupting Sybil (if any) chunk-fetching's weighted-
    # random selection happens to touch this run isn't asserted
    # deterministically here -- what's guaranteed and checked above is that
    # no amount of Sybil noise, of either flavor, ever earns a better score
    # than the one honest peer, or a non-negative score at all.
