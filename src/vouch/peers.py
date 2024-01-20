"""Multi-peer fetch pool: persistent scoring and session blacklisting, per
02_TECHNICAL_ARCHITECTURE.md section 6.2.

Every chunk is still hash-verified before it touches the CAS regardless of
which peer served it (`cas.write_verified` is unchanged) -- this module
only decides *which* peer to ask next and *how much to trust* a peer for
future sessions. A digest mismatch is a hard, immediate signal (the peer
served bad bytes): it blacklists that peer for the rest of this session and
persists a large score penalty right away, so even a crash mid-fetch
doesn't lose that signal. A transport error (timeout, connection refused,
5xx) is a much weaker signal (could be a blip, could be overload) and only
deprioritizes the peer, saved at the end of the session along with any
successes. Selection is weighted-random with a small exploration share, so
a peer that was bad in a past session isn't permanently locked out --
scores are clamped to keep that exploration share meaningful at both ends.
"""

from __future__ import annotations

import random
from pathlib import Path

from .errors import NetworkError
from .httpclient import OriginClient
from .store import atomic_write_json, peers_path, read_json

DEFAULT_SCORE = 0.0
SUCCESS_BONUS = 1.0
TRANSPORT_PENALTY = -1.0
MISMATCH_PENALTY = -10.0
SCORE_CLAMP = (-50.0, 20.0)
EXPLORATION_SHARE = 0.10


def _clamp(score: float) -> float:
    lo, hi = SCORE_CLAMP
    return max(lo, min(hi, score))


def load_scores(home: Path) -> dict[str, float]:
    path = peers_path(home)
    if not path.exists():
        return {}
    return read_json(path).get("scores", {})


def save_scores(home: Path, scores: dict[str, float]) -> None:
    atomic_write_json(peers_path(home), {"vouch": "peers/v1", "scores": scores})


class PeerPool:
    def __init__(self, home: Path, base_urls: list[str]):
        if not base_urls:
            raise NetworkError("no mirrors configured")
        self.home = home
        self.base_urls = list(dict.fromkeys(base_urls))  # de-dup, preserve order
        self.scores: dict[str, float] = load_scores(home)
        for url in self.base_urls:
            self.scores.setdefault(url, DEFAULT_SCORE)
        self._blacklist: set[str] = set()
        self._clients: dict[str, OriginClient] = {}

    async def __aenter__(self) -> "PeerPool":
        for url in self.base_urls:
            client = OriginClient(url)
            await client.__aenter__()
            self._clients[url] = client
        return self

    async def __aexit__(self, *exc_info) -> None:
        for client in self._clients.values():
            await client.__aexit__(*exc_info)
        self._clients.clear()
        save_scores(self.home, self.scores)

    def healthy_peers(self) -> list[str]:
        return [url for url in self.base_urls if url not in self._blacklist]

    def clients_by_score(self) -> list[OriginClient]:
        """Healthy peers, best-scored first -- used for metadata fetches
        (root/timestamp/snapshot/manifest), which fall back across peers in
        order rather than needing the full weighted-selection machinery
        chunk scheduling uses (each document is independently verified
        regardless of which peer served it, so trying the best peer first
        is just an availability optimization, not a trust decision).
        """
        healthy = self.healthy_peers()
        healthy.sort(key=lambda url: self.scores.get(url, DEFAULT_SCORE), reverse=True)
        return [self._clients[url] for url in healthy]

    def client_for(self, url: str) -> OriginClient:
        return self._clients[url]

    def select_peer(self) -> str:
        """Weighted-random selection over healthy peers, with a small
        exploration share so a formerly-bad peer can rehabilitate.
        """
        healthy = self.healthy_peers()
        if not healthy:
            raise NetworkError("no healthy peers remain in this session")
        if len(healthy) == 1:
            return healthy[0]
        if random.random() < EXPLORATION_SHARE:
            return random.choice(healthy)
        weights = [self._weight(url) for url in healthy]
        return random.choices(healthy, weights=weights, k=1)[0]

    def _weight(self, url: str) -> float:
        lo, _hi = SCORE_CLAMP
        return max(0.01, self.scores.get(url, DEFAULT_SCORE) - lo + 1.0)

    def record_success(self, url: str) -> None:
        self.scores[url] = _clamp(self.scores.get(url, DEFAULT_SCORE) + SUCCESS_BONUS)

    def record_transport_error(self, url: str) -> None:
        self.scores[url] = _clamp(self.scores.get(url, DEFAULT_SCORE) + TRANSPORT_PENALTY)

    def record_digest_mismatch(self, url: str) -> None:
        self._blacklist.add(url)
        self.scores[url] = _clamp(self.scores.get(url, DEFAULT_SCORE) + MISMATCH_PENALTY)
        # Persist immediately -- this signal must survive a crash mid-fetch.
        save_scores(self.home, self.scores)
