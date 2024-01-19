"""Origin HTTP server, per 02_TECHNICAL_ARCHITECTURE.md section 6.1.

Every route is either content-addressed (chunk, manifest) or namespaced
under a publisher's own fingerprint (root, current-version bridge); nothing
served here is trusted for being "from" the origin -- the transport carries
zero trust, consumers verify everything locally. This module is also the
in-process fake-peer substrate the T2A/T4A adversarial tests build on
(03_SECURITY_AND_ACCESS.md section 9): tests wrap this same `build_app`
in `aiohttp.test_utils.TestServer` and interpose a tampering proxy in front
of it.

`GET /v1/{publisher}/meta/timestamp` and `GET /v1/{publisher}/meta/snapshot/{digest}`
are the M2 freshness layer (architecture doc section 4.2), superseding
M1's `/current` bridge (removed). The timestamp route serves a DSSE
envelope like the root document; the snapshot route serves RAW bytes via
`web.Response`, never `web.json_response` -- the snapshot's digest is
computed over its exact wire bytes (Decision D6, no signature of its own),
so re-serializing through aiohttp's JSON encoder would silently break
every snapshot fetch.

The M3 transparency-log routes (`log/checkpoint`, `log/checkpoint/{n}`,
`log/proof/inclusion/{n}/{i}`, `log/proof/consistency/{old}/{new}`) serve
PRECOMPUTED proofs, not raw leaves for client-side tree rebuilding (D7:
the client verifies a proof, it doesn't reconstruct the Merkle tree
itself). Inclusion/consistency proof responses carry only `{"proof": [...]}`
-- deliberately not the leaf hash itself, since the client always
recomputes that independently from data it already trusts (the manifest
digest, log_index, and publisher it already has) rather than trusting
anything the server reports about what a leaf "is".

`GET /v1/{publisher}/log/leaves` is the one exception -- it serves the raw
leaf list, untrusted (a leaf's `digest` field is meaningless until it
appears inside a leaf hash a real inclusion proof authenticates). It
exists only for `mirror sync`, which needs its own on-disk copy of
`leaves.json` so its own instance of THIS SAME `handle_log_inclusion_proof`/
`handle_log_consistency_proof` can compute correct proofs for consumers
fetching from that mirror later -- consumers never call this route
themselves.
"""

from __future__ import annotations

from pathlib import Path

from aiohttp import web

from . import cas, originstore
from . import log as log_mod
from .errors import LogFailureError
from .hashing import is_valid_digest

STORE_KEY = web.AppKey("store", Path)


def _validate_digest(digest: str) -> None:
    if not is_valid_digest(digest):
        raise web.HTTPBadRequest(text="invalid digest")


def _validate_component(value: str) -> None:
    if not value or "/" in value or "\\" in value or value in (".", ".."):
        raise web.HTTPBadRequest(text="invalid path component")


def build_app(store: Path) -> web.Application:
    app = web.Application()
    app[STORE_KEY] = store
    app.add_routes(
        [
            web.get("/v1/{publisher}/meta/root/{n}", handle_root),
            web.get("/v1/{publisher}/meta/timestamp", handle_timestamp),
            web.get("/v1/{publisher}/meta/snapshot/{digest}", handle_snapshot),
            web.get("/v1/manifest/{digest}", handle_manifest),
            web.get("/v1/chunk/{digest}", handle_chunk),
            web.get("/v1/{publisher}/log/checkpoint", handle_log_checkpoint),
            web.get("/v1/{publisher}/log/checkpoint/{tree_size}", handle_log_checkpoint_at),
            web.get("/v1/{publisher}/log/proof/inclusion/{tree_size}/{leaf_index}", handle_log_inclusion_proof),
            web.get("/v1/{publisher}/log/proof/consistency/{old_size}/{new_size}", handle_log_consistency_proof),
            web.get("/v1/{publisher}/log/leaves", handle_log_leaves),
        ]
    )
    return app


async def handle_root(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    _validate_component(publisher)
    try:
        version = int(request.match_info["n"])
    except ValueError:
        raise web.HTTPBadRequest(text="invalid root version")

    store: Path = request.app[STORE_KEY]
    envelope = originstore.read_root_doc(store, publisher, version)
    if envelope is None:
        raise web.HTTPNotFound(text="root document not found")
    return web.json_response(envelope)


async def handle_manifest(request: web.Request) -> web.Response:
    digest = request.match_info["digest"]
    _validate_digest(digest)

    store: Path = request.app[STORE_KEY]
    envelope = originstore.read_manifest_envelope(store, digest)
    if envelope is None:
        raise web.HTTPNotFound(text="manifest not found")
    return web.json_response(envelope)


async def handle_chunk(request: web.Request) -> web.Response:
    digest = request.match_info["digest"]
    _validate_digest(digest)

    store: Path = request.app[STORE_KEY]
    if not cas.has_object(store, digest):
        raise web.HTTPNotFound(text="chunk not found")
    data = cas.open_object(store, digest)
    return web.Response(body=data, content_type="application/octet-stream")


async def handle_timestamp(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    _validate_component(publisher)

    store: Path = request.app[STORE_KEY]
    envelope = originstore.read_timestamp(store, publisher)
    if envelope is None:
        raise web.HTTPNotFound(text="timestamp not found")
    return web.json_response(envelope)


async def handle_snapshot(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    digest = request.match_info["digest"]
    _validate_component(publisher)
    _validate_digest(digest)

    store: Path = request.app[STORE_KEY]
    data = originstore.read_snapshot_bytes(store, publisher, digest)
    if data is None:
        raise web.HTTPNotFound(text="snapshot not found")
    # Raw bytes, NOT web.json_response -- see module docstring.
    return web.Response(body=data, content_type="application/json")


async def handle_log_checkpoint(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    _validate_component(publisher)

    store: Path = request.app[STORE_KEY]
    envelope = originstore.read_checkpoint(store, publisher)
    if envelope is None:
        raise web.HTTPNotFound(text="checkpoint not found")
    return web.json_response(envelope)


async def handle_log_checkpoint_at(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    _validate_component(publisher)
    try:
        tree_size = int(request.match_info["tree_size"])
    except ValueError:
        raise web.HTTPBadRequest(text="invalid tree size")

    store: Path = request.app[STORE_KEY]
    envelope = originstore.read_checkpoint_at(store, publisher, tree_size)
    if envelope is None:
        raise web.HTTPNotFound(text="checkpoint not found at that tree size")
    return web.json_response(envelope)


async def handle_log_inclusion_proof(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    _validate_component(publisher)
    try:
        tree_size = int(request.match_info["tree_size"])
        leaf_index = int(request.match_info["leaf_index"])
    except ValueError:
        raise web.HTTPBadRequest(text="invalid tree size or leaf index")

    store: Path = request.app[STORE_KEY]
    leaves = originstore.read_log_leaves(store, publisher)
    if not (0 <= tree_size <= len(leaves)) or not (0 <= leaf_index < tree_size):
        raise web.HTTPNotFound(text="leaf or tree size not found")

    hashes = [log_mod.leaf_hash(leaf) for leaf in leaves[:tree_size]]
    try:
        proof = log_mod.inclusion_proof(hashes, leaf_index)
    except LogFailureError:
        raise web.HTTPBadRequest(text="could not compute inclusion proof")
    return web.json_response({"proof": proof})


async def handle_log_leaves(request: web.Request) -> web.Response:
    """Raw, untrusted leaf list -- for `mirror sync` only, see module
    docstring.
    """
    publisher = request.match_info["publisher"]
    _validate_component(publisher)

    store: Path = request.app[STORE_KEY]
    leaves = originstore.read_log_leaves(store, publisher)
    return web.json_response(leaves)


async def handle_log_consistency_proof(request: web.Request) -> web.Response:
    publisher = request.match_info["publisher"]
    _validate_component(publisher)
    try:
        old_size = int(request.match_info["old_size"])
        new_size = int(request.match_info["new_size"])
    except ValueError:
        raise web.HTTPBadRequest(text="invalid tree sizes")

    store: Path = request.app[STORE_KEY]
    leaves = originstore.read_log_leaves(store, publisher)
    hashes = [log_mod.leaf_hash(leaf) for leaf in leaves]
    try:
        proof = log_mod.consistency_proof(hashes, old_size, new_size)
    except LogFailureError:
        raise web.HTTPBadRequest(text="could not compute consistency proof")
    return web.json_response({"proof": proof})
