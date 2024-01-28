"""T2A-TRANSIT-TAMPER, per 03_SECURITY_AND_ACCESS.md section 4:

"Tampering in transit: on-path attacker rewrites bytes or swaps responses.
Primary mitigation: same end-to-end content addressing; nothing is trusted
for being 'from' anyone."

The consumer talks only to `tampering_proxy_factory`'s proxy (never to the
honest origin directly), simulating a compromised mirror or an on-path
attacker sitting between the consumer and an otherwise-honest origin.
"""

from __future__ import annotations

import pytest

from vouch import fetch_flow, store as store_mod, trust_store
from vouch.peers import PeerPool

pytestmark = pytest.mark.asyncio


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


async def test_t2a_tampered_chunk_in_transit_fails_closed(consumer_home, published_artifact, tampering_proxy_factory):
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])
    proxy = await tampering_proxy_factory(published_artifact["chunk_digest"])

    async with PeerPool(consumer_home, [proxy.base_url()]) as pool:
        result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")

    assert result["ok"] is False
    assert result["exit_code"] == 40

    fail_check = next(c for c in result["checks"] if not c["ok"])
    assert fail_check["id"] == "V8"
    assert "evidence" in fail_check
    assert fail_check["expected"] == published_artifact["chunk_digest"]
    assert fail_check["actual"] != published_artifact["chunk_digest"]
    # Peer attribution: the offending bytes are attributed to whoever served
    # them (the proxy), not the honest upstream origin.
    assert fail_check["peer"] == proxy.base_url()

    # Quarantine evidence exists and carries expected/actual digests.
    qdirs = list(store_mod.quarantine_dir(consumer_home).iterdir())
    assert len(qdirs) == 1
    report = store_mod.read_json(qdirs[0] / "report.json")
    assert report["exit_code"] == 40
    assert report["expected_digest"] == published_artifact["chunk_digest"]
    assert report["peer"] == proxy.base_url()
    assert (qdirs[0] / "bytes.bin").exists()

    # Materialization gate held, and the corrupted bytes never entered the CAS
    # at the true digest's path.
    assert not (consumer_home / "verified" / "acme-lab").exists()
    from vouch.cas import has_object

    assert not has_object(consumer_home, published_artifact["chunk_digest"])


async def test_t2a_honest_proxy_passes_through_unaffected(consumer_home, published_artifact, tampering_proxy_factory):
    # Control case: a proxy configured to tamper with a digest that never
    # appears in this fetch must not affect an otherwise-honest fetch.
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])
    proxy = await tampering_proxy_factory("b3:" + "0" * 64)

    async with PeerPool(consumer_home, [proxy.base_url()]) as pool:
        result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")

    assert result["ok"] is True
    assert result["exit_code"] == 0
