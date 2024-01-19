"""Hardening tests for httpclient.py: a malicious or compromised peer must
not be able to hang a fetch indefinitely or exhaust consumer memory by
sending an oversized response -- both are in scope of the "malicious
mirror" adversary the rest of the threat model already assumes (T1/T6b).

These use a synthetic aiohttp app that serves deliberately oversized or
slow responses -- not `httpserver.build_app`, since a real Vouch origin
never legitimately serves an oversized chunk (chunks are fixed-size by
construction). This stands in for a compromised or hostile peer that
doesn't play by the protocol.
"""

from __future__ import annotations

import asyncio

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from vouch import httpclient as httpclient_mod
from vouch.errors import NetworkError
from vouch.httpclient import MAX_CHUNK_BYTES, MAX_METADATA_BYTES, OriginClient

pytestmark = pytest.mark.asyncio


async def _serve(app: web.Application) -> TestServer:
    server = TestServer(app)
    await server.start_server()
    return server


async def test_oversized_chunk_response_is_rejected_not_buffered():
    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(status=200)
        await resp.prepare(request)
        # One byte past the cap is enough to prove the limit is enforced
        # during streaming, not just checked against a (spoofable)
        # Content-Length header afterward.
        remaining = MAX_CHUNK_BYTES + 1
        block = b"x" * 65536
        while remaining > 0:
            piece = block[: min(len(block), remaining)]
            await resp.write(piece)
            remaining -= len(piece)
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_get("/v1/chunk/{digest}", handler)
    server = await _serve(app)
    try:
        async with OriginClient(str(server.make_url(""))) as client:
            with pytest.raises(NetworkError):
                await client.get_chunk("b3:" + "0" * 64)
    finally:
        await server.close()


async def test_chunk_response_at_exactly_the_cap_is_accepted():
    exact_body = b"y" * MAX_CHUNK_BYTES

    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=exact_body, content_type="application/octet-stream")

    app = web.Application()
    app.router.add_get("/v1/chunk/{digest}", handler)
    server = await _serve(app)
    try:
        async with OriginClient(str(server.make_url(""))) as client:
            data = await client.get_chunk("b3:" + "0" * 64)
        assert data == exact_body
    finally:
        await server.close()


async def test_oversized_metadata_response_is_rejected():
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"{" + b'"x":"' + b"a" * MAX_METADATA_BYTES + b'"}', content_type="application/json")

    app = web.Application()
    app.router.add_get("/v1/{publisher}/meta/timestamp", handler)
    server = await _serve(app)
    try:
        async with OriginClient(str(server.make_url(""))) as client:
            with pytest.raises(NetworkError):
                await client.get_timestamp("b3:" + "0" * 64)
    finally:
        await server.close()


async def test_hung_peer_times_out_instead_of_blocking_forever(monkeypatch):
    async def handler(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(status=200)
        await resp.prepare(request)
        await asyncio.sleep(3600)  # never actually reached before the client times out
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_get("/v1/chunk/{digest}", handler)
    server = await _serve(app)
    monkeypatch.setattr(
        httpclient_mod, "REQUEST_TIMEOUT", aiohttp.ClientTimeout(total=0.2, connect=0.2, sock_read=0.2)
    )
    try:
        async with OriginClient(str(server.make_url(""))) as client:
            with pytest.raises(NetworkError):
                await client.get_chunk("b3:" + "0" * 64)
    finally:
        await server.close()
