"""T1-MIRROR-TAMPER, per 03_SECURITY_AND_ACCESS.md section 4:

"Malicious or compromised mirror serves altered weights or datasets...
Primary mitigation: every chunk hash-verified against the signed manifest
before write; peer blacklisted on mismatch."

This is the M2 behavioral headline: with a second, honest peer configured,
the fetch must SUCCEED (M1's single-peer fetch would have failed the whole
operation on the first mismatch). Peer selection in `peers.py` is
weighted-random with an exploration share, so which peer serves any given
chunk isn't deterministic across runs by default -- this test forces
determinism by monkeypatching the `random` calls `peers.py` makes, so the
tampering peer is guaranteed to be tried first (and therefore blacklisted)
rather than possibly getting skipped by chance.
"""

from __future__ import annotations

import pytest

from vouch import fetch_flow, peers as peers_mod, store as store_mod, trust_store
from vouch.peers import PeerPool

pytestmark = pytest.mark.asyncio


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


async def test_t1_fetch_succeeds_via_honest_peer_after_tampering_peer_blacklisted(
    consumer_home, published_artifact, tampering_proxy_factory, monkeypatch
):
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])
    proxy = await tampering_proxy_factory(published_artifact["chunk_digest"])
    tampering_url = proxy.base_url()

    # Force select_peer()'s exploration branch every call, and force the
    # exploration pick to prefer the tampering peer whenever it's still
    # healthy -- guaranteeing it gets tried (and therefore caught) instead
    # of possibly never being selected by chance.
    monkeypatch.setattr(peers_mod.random, "random", lambda: 0.0)
    monkeypatch.setattr(peers_mod.random, "choice", lambda seq: tampering_url if tampering_url in seq else seq[0])

    # The proxy already knows its own upstream (the honest fake_origin);
    # no separate fixture parameter needed.
    honest_url = proxy.upstream

    async with PeerPool(consumer_home, [tampering_url, honest_url]) as pool:
        result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")

    assert result["ok"] is True, result
    assert result["exit_code"] == 0
    assert all(c["ok"] for c in result["checks"])

    materialized = consumer_home / "verified" / "acme-lab" / "bert-tiny" / "1.2.0" / "weights.bin"
    assert materialized.read_bytes() == published_artifact["src_file"].read_bytes()

    # The tampering peer was blacklisted for the session and took a
    # persistent score penalty, saved to disk immediately on the mismatch.
    scores = peers_mod.load_scores(consumer_home)
    assert scores[tampering_url] < peers_mod.DEFAULT_SCORE
    assert scores[tampering_url] <= peers_mod.DEFAULT_SCORE + peers_mod.MISMATCH_PENALTY + 5 * peers_mod.SUCCESS_BONUS
