"""Thin async HTTP client for a single peer, per
02_TECHNICAL_ARCHITECTURE.md section 6.1.

Each instance talks to exactly one base URL; peer attribution for scoring
(`peers.py`) comes from which `OriginClient` (i.e. which URL) a caller used,
not from a parameter threaded through every call. Every method returns
`None` on a 404 (the caller decides what that means for the check in
progress: absence of a root document reads differently than absence of a
requested version) and raises NetworkError for transport failures,
timeouts, oversized responses, or unexpected statuses, so callers never
have to distinguish "peer is down" from "peer said no" via exception type
inspection.

Hardening notes, both directly in scope of the "malicious or compromised
mirror" adversary this project already assumes (T1/T6b):
- Every request carries a hard timeout. Without one, a peer that simply
  never finishes sending a response could hang a fetch indefinitely --
  the security doc's "loud, never silent" failure principle requires this
  to time out and surface as a network error, not hang forever.
- Every response body is read with a hard size cap, enforced while
  streaming (not just via a spoofable Content-Length header). A chunk can
  never legitimately exceed CHUNK_SIZE by protocol; metadata documents are
  small. Without a cap, a peer could send an arbitrarily large response to
  any endpoint and exhaust consumer memory before any digest check ever
  runs.

`get_snapshot` returns raw bytes, never parsed JSON -- see `snapshot.py`'s
docstring on why the wire bytes themselves are the trust-relevant value.
"""

from __future__ import annotations

import asyncio
import json

import aiohttp

from .chunking import CHUNK_SIZE
from .errors import NetworkError

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)

# Chunks are fixed-size by protocol -- no legitimate response can exceed
# CHUNK_SIZE, so the cap is exact, not padded.
MAX_CHUNK_BYTES = CHUNK_SIZE
# Root/timestamp/manifest documents are small signed statements; generous
# headroom over anything realistic.
MAX_METADATA_BYTES = 4 * 1024 * 1024
# Snapshots enumerate every version of every artifact a publisher has ever
# released -- bounded, but larger catalogs need more room than a single
# metadata document.
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024

_READ_CHUNK_SIZE = 65536


class OriginClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "OriginClient":
        self._session = aiohttp.ClientSession(timeout=REQUEST_TIMEOUT)
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def get_root(self, publisher: str, version: int) -> dict | None:
        return await self._get_json(f"/v1/{publisher}/meta/root/{version}", MAX_METADATA_BYTES)

    async def get_timestamp(self, publisher: str) -> dict | None:
        return await self._get_json(f"/v1/{publisher}/meta/timestamp", MAX_METADATA_BYTES)

    async def get_snapshot(self, publisher: str, digest: str) -> bytes | None:
        return await self._get_bytes(f"/v1/{publisher}/meta/snapshot/{digest}", MAX_SNAPSHOT_BYTES)

    async def get_manifest(self, digest: str) -> dict | None:
        return await self._get_json(f"/v1/manifest/{digest}", MAX_METADATA_BYTES)

    async def get_chunk(self, digest: str) -> bytes | None:
        return await self._get_bytes(f"/v1/chunk/{digest}", MAX_CHUNK_BYTES)

    async def get_checkpoint(self, publisher: str) -> dict | None:
        return await self._get_json(f"/v1/{publisher}/log/checkpoint", MAX_METADATA_BYTES)

    async def get_checkpoint_at(self, publisher: str, tree_size: int) -> dict | None:
        return await self._get_json(f"/v1/{publisher}/log/checkpoint/{tree_size}", MAX_METADATA_BYTES)

    async def get_inclusion_proof(self, publisher: str, tree_size: int, leaf_index: int) -> dict | None:
        return await self._get_json(
            f"/v1/{publisher}/log/proof/inclusion/{tree_size}/{leaf_index}", MAX_METADATA_BYTES
        )

    async def get_consistency_proof(self, publisher: str, old_size: int, new_size: int) -> dict | None:
        # A consistency proof scales with the tree, like a snapshot -- same larger cap.
        return await self._get_json(
            f"/v1/{publisher}/log/proof/consistency/{old_size}/{new_size}", MAX_SNAPSHOT_BYTES
        )

    async def get_log_leaves(self, publisher: str) -> list | None:
        # For `mirror sync` only -- raw, untrusted leaves; scales with the
        # tree like a snapshot/consistency proof.
        return await self._get_json(f"/v1/{publisher}/log/leaves", MAX_SNAPSHOT_BYTES)

    async def _read_bounded(self, resp: aiohttp.ClientResponse, path: str, max_bytes: int) -> bytes:
        buf = bytearray()
        async for piece in resp.content.iter_chunked(_READ_CHUNK_SIZE):
            buf.extend(piece)
            if len(buf) > max_bytes:
                raise NetworkError(
                    f"response from {path} exceeded the {max_bytes}-byte limit", peer=self.base_url
                )
        return bytes(buf)

    async def _get_json(self, path: str, max_bytes: int) -> dict | None:
        try:
            async with self._session.get(self.base_url + path) as resp:
                if resp.status == 404:
                    return None
                if resp.status != 200:
                    raise NetworkError(f"unexpected status {resp.status} from {path}", peer=self.base_url)
                body = await self._read_bounded(resp, path, max_bytes)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise NetworkError(f"network error fetching {path}: {e}", peer=self.base_url) from e
        try:
            return json.loads(body)
        except (ValueError, UnicodeDecodeError) as e:
            raise NetworkError(f"malformed JSON from {path}: {e}", peer=self.base_url) from e

    async def _get_bytes(self, path: str, max_bytes: int) -> bytes | None:
        try:
            async with self._session.get(self.base_url + path) as resp:
                if resp.status == 404:
                    return None
                if resp.status != 200:
                    raise NetworkError(f"unexpected status {resp.status} from {path}", peer=self.base_url)
                return await self._read_bounded(resp, path, max_bytes)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise NetworkError(f"network error fetching {path}: {e}", peer=self.base_url) from e
