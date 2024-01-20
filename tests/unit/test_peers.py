import pytest

from vouch import peers as peers_mod
from vouch.errors import NetworkError
from vouch.peers import PeerPool, load_scores

pytestmark = pytest.mark.asyncio


@pytest.fixture
def home(tmp_path):
    return tmp_path


async def test_pool_requires_at_least_one_mirror(home):
    with pytest.raises(NetworkError):
        PeerPool(home, [])


async def test_select_peer_single_peer_always_returned(home):
    async with PeerPool(home, ["http://a"]) as pool:
        for _ in range(5):
            assert pool.select_peer() == "http://a"


async def test_record_digest_mismatch_blacklists_for_session(home):
    async with PeerPool(home, ["http://a", "http://b"]) as pool:
        pool.record_digest_mismatch("http://a")
        assert pool.healthy_peers() == ["http://b"]
        for _ in range(10):
            assert pool.select_peer() == "http://b"


async def test_record_digest_mismatch_persists_immediately(home):
    async with PeerPool(home, ["http://a", "http://b"]) as pool:
        pool.record_digest_mismatch("http://a")
        # Read straight from disk, not from the in-memory pool -- this must
        # survive even if the process crashed right after this call.
        on_disk = load_scores(home)
        assert on_disk["http://a"] < peers_mod.DEFAULT_SCORE


async def test_record_transport_error_deprioritizes_but_does_not_blacklist(home):
    async with PeerPool(home, ["http://a", "http://b"]) as pool:
        pool.record_transport_error("http://a")
        assert "http://a" in pool.healthy_peers()
        assert pool.scores["http://a"] == peers_mod.DEFAULT_SCORE + peers_mod.TRANSPORT_PENALTY


async def test_record_success_increases_score(home):
    async with PeerPool(home, ["http://a"]) as pool:
        pool.record_success("http://a")
        assert pool.scores["http://a"] == peers_mod.DEFAULT_SCORE + peers_mod.SUCCESS_BONUS


async def test_scores_persist_across_pool_instances(home):
    async with PeerPool(home, ["http://a"]) as pool:
        pool.record_success("http://a")
        pool.record_success("http://a")
    # New pool, same home -- should pick up the persisted score.
    async with PeerPool(home, ["http://a"]) as pool2:
        assert pool2.scores["http://a"] == peers_mod.DEFAULT_SCORE + 2 * peers_mod.SUCCESS_BONUS


async def test_scores_are_clamped(home):
    async with PeerPool(home, ["http://a"]) as pool:
        for _ in range(1000):
            pool.record_success("http://a")
        assert pool.scores["http://a"] == peers_mod.SCORE_CLAMP[1]
        for _ in range(1000):
            pool.record_transport_error("http://a")
        assert pool.scores["http://a"] == peers_mod.SCORE_CLAMP[0]


async def test_weighted_selection_favors_higher_score(home, monkeypatch):
    # Force the exploration branch off so this exercises pure weighted choice.
    monkeypatch.setattr(peers_mod.random, "random", lambda: 1.0)
    peers_mod.random.seed(1234)
    async with PeerPool(home, ["http://good", "http://bad"]) as pool:
        pool.scores["http://good"] = 20.0
        pool.scores["http://bad"] = -40.0
        # weight(good)=71, weight(bad)=11 -> expected share ~0.866; a wide
        # margin below that keeps this non-flaky while still proving bias
        # (an unweighted/uniform choice would land near 0.5).
        picks = [pool.select_peer() for _ in range(500)]
        good_share = picks.count("http://good") / len(picks)
        assert good_share > 0.75


async def test_exploration_share_still_picks_the_bad_peer_sometimes(home, monkeypatch):
    # Force the exploration branch on every call.
    monkeypatch.setattr(peers_mod.random, "random", lambda: 0.0)
    monkeypatch.setattr(peers_mod.random, "choice", lambda seq: seq[-1])
    async with PeerPool(home, ["http://good", "http://bad"]) as pool:
        pool.scores["http://good"] = 20.0
        pool.scores["http://bad"] = -40.0
        assert pool.select_peer() == "http://bad"


async def test_clients_by_score_orders_best_first(home):
    async with PeerPool(home, ["http://a", "http://b", "http://c"]) as pool:
        pool.scores["http://a"] = 1.0
        pool.scores["http://b"] = 5.0
        pool.scores["http://c"] = -1.0
        ordered = pool.clients_by_score()
        assert [c.base_url for c in ordered] == ["http://b", "http://a", "http://c"]


async def test_clients_by_score_excludes_blacklisted(home):
    async with PeerPool(home, ["http://a", "http://b"]) as pool:
        pool.record_digest_mismatch("http://a")
        ordered = pool.clients_by_score()
        assert [c.base_url for c in ordered] == ["http://b"]


async def test_select_peer_raises_when_all_blacklisted(home):
    async with PeerPool(home, ["http://a"]) as pool:
        pool.record_digest_mismatch("http://a")
        with pytest.raises(NetworkError):
            pool.select_peer()


async def test_duplicate_base_urls_are_deduped(home):
    async with PeerPool(home, ["http://a", "http://a", "http://b"]) as pool:
        assert pool.base_urls == ["http://a", "http://b"]
