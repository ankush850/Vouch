"""End-to-end scripted scenario, driven through the real `vouch` CLI
surface (per the M1 plan): keygen -> publisher init -> delegate -> publish
-> origin serve -> trust add -> fetch -> verify, plus a tampering variant.

`origin serve` itself blocks forever (`aiohttp.web.run_app`), so rather than
invoke that specific subcommand we serve the published store directly via
`aiohttp.test_utils.TestServer` wrapping the same `httpserver.build_app` the
command uses -- an explicitly sanctioned substitution for determinism, not a
different code path. Every other step goes through `CliRunner` against the
actual `vouch` command group. CLI invocations run in a worker thread via
`asyncio.to_thread`, because `fetch`/`verify` call `asyncio.run()`
internally and this test itself needs its own event loop alive (for the
TestServer) throughout.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from click.testing import CliRunner

from vouch.chunking import CHUNK_SIZE
from vouch.cli.main import main
from vouch.httpserver import build_app

pytestmark = pytest.mark.asyncio


def _passphrase_fd(passphrase: str) -> int:
    r, w = os.pipe()
    os.write(w, (passphrase + "\n").encode())
    os.close(w)
    return r


async def invoke(runner: CliRunner, args: list[str], passphrase: str | None = None):
    full_args = list(args)
    if passphrase is not None:
        full_args += ["--passphrase-fd", str(_passphrase_fd(passphrase))]
    return await asyncio.to_thread(runner.invoke, main, full_args, catch_exceptions=False)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    home = tmp_path / "home"
    origin = tmp_path / "origin"
    keys_dir = tmp_path / "keys"
    src = tmp_path / "src"
    keys_dir.mkdir()
    src.mkdir()
    monkeypatch.setenv("VOUCH_HOME", str(home))
    return {"home": home, "origin": origin, "keys": keys_dir, "src": src}


async def _publish_fixture_artifact(runner: CliRunner, workspace: dict) -> str:
    """Run keygen -> publisher init -> delegate(release+timestamp) ->
    publish -> origin reissue-timestamp through the real CLI. Returns the
    publisher fingerprint.
    """
    keys_dir = workspace["keys"]
    origin = workspace["origin"]
    src = workspace["src"]

    # One multi-chunk file and one single-chunk file, to exercise both the
    # multi-chunk and single-chunk manifest/assembly paths.
    (src / "big.bin").write_bytes(b"A" * (CHUNK_SIZE + 12345))
    (src / "small.bin").write_bytes(b"small file contents")

    result = await invoke(runner, ["keygen", "--role", "root", "--out", str(keys_dir / "root.key")], passphrase="rootpass")
    assert result.exit_code == 0, result.output

    result = await invoke(runner, ["keygen", "--role", "release", "--out", str(keys_dir / "release.key")], passphrase="releasepass")
    assert result.exit_code == 0, result.output

    result = await invoke(runner, ["keygen", "--role", "timestamp", "--out", str(keys_dir / "ts.key")], passphrase="tspass")
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner,
        ["publisher", "init", "acme-lab", "--root-key", str(keys_dir / "root.key"), "--store", str(origin)],
        passphrase="rootpass",
    )
    assert result.exit_code == 0, result.output
    fingerprint = result.output.split("->")[1].split()[0].strip()

    result = await invoke(
        runner,
        [
            "publisher", "delegate", "--role", "release",
            "--key", str(keys_dir / "release.key.pub"),
            "--root-key", str(keys_dir / "root.key"),
            "--store", str(origin),
        ],
        passphrase="rootpass",
    )
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner,
        [
            "publisher", "delegate", "--role", "timestamp",
            "--key", str(keys_dir / "ts.key.pub"),
            "--root-key", str(keys_dir / "root.key"),
            "--store", str(origin),
        ],
        passphrase="rootpass",
    )
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner,
        [
            "publish", str(src),
            "--name", "bert-tiny", "--version", "1.2.0", "--type", "model",
            "--release-key", str(keys_dir / "release.key"), "--store", str(origin),
        ],
        passphrase="releasepass",
    )
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner,
        ["origin", "reissue-timestamp", "--store", str(origin), "--timestamp-key", str(keys_dir / "ts.key")],
        passphrase="tspass",
    )
    assert result.exit_code == 0, result.output

    return fingerprint


async def test_publish_fetch_verify_end_to_end(runner, workspace):
    fingerprint = await _publish_fixture_artifact(runner, workspace)
    origin = workspace["origin"]
    src = workspace["src"]

    server = TestServer(build_app(origin))
    await server.start_server()
    try:
        base_url = str(server.make_url(""))

        result = await invoke(runner, ["trust", "add", "acme-lab", fingerprint, "--mirror", base_url])
        assert result.exit_code == 0, result.output

        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.2.0"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is True
        assert {c["id"] for c in payload["checks"]} == {"V1", "V2", "V4", "V5", "V6", "V7", "V8", "V9"}
        assert all(c["ok"] for c in payload["checks"])

        materialized = Path(payload["materialized"])
        assert (materialized / "big.bin").read_bytes() == (src / "big.bin").read_bytes()
        assert (materialized / "small.bin").read_bytes() == (src / "small.bin").read_bytes()

        result = await invoke(runner, ["--json", "verify", str(materialized), "--ref", "acme-lab/bert-tiny@1.2.0"])
        assert result.exit_code == 0, result.output
        verify_payload = json.loads(result.output)
        assert verify_payload["ok"] is True
        assert verify_payload["artifact"]["digest"] == payload["artifact"]["digest"]
    finally:
        await server.close()


async def _start_tampering_proxy(upstream_base_url: str, tamper_digest: str) -> TestServer:
    """A minimal in-process on-path attacker in front of `upstream_base_url`,
    corrupting the response body for any request path containing
    `tamper_digest`. Standalone copy of the same pattern used by
    tests/adversarial/conftest.py's TamperingProxy -- kept local here since
    e2e tests don't share fixtures across the tests/adversarial/ directory.
    """

    async def handler(request: web.Request) -> web.Response:
        async with aiohttp.ClientSession() as session:
            async with session.get(upstream_base_url.rstrip("/") + request.path_qs) as resp:
                body = await resp.read()
                status = resp.status
                content_type = resp.content_type
        if status == 200 and tamper_digest in request.path and body:
            mutated = bytearray(body)
            mutated[0] ^= 0xFF
            body = bytes(mutated)
        return web.Response(body=body, status=status, content_type=content_type)

    app = web.Application()
    app.router.add_route("GET", "/{tail:.*}", handler)
    proxy = TestServer(app)
    await proxy.start_server()
    return proxy


async def test_fetch_succeeds_with_one_tampering_mirror_among_several(runner, workspace):
    # T1-shaped resilience through the real CLI: two configured mirrors,
    # one silently corrupting a chunk. `fetch` must still succeed by
    # retrying the honest mirror, unlike single-peer M1 which would have
    # failed the whole fetch.
    fingerprint = await _publish_fixture_artifact(runner, workspace)
    origin = workspace["origin"]
    src = workspace["src"]

    from vouch import cas as cas_mod, originstore

    current = originstore.read_current_pointer(origin, fingerprint, "bert-tiny", "1.2.0")
    envelope = originstore.read_manifest_envelope(origin, current["digest"])
    manifest = json.loads(base64.b64decode(envelope["payload"]))
    chunk_digest = manifest["files"][0]["chunks"][0]

    server = TestServer(build_app(origin))
    await server.start_server()
    proxy = await _start_tampering_proxy(str(server.make_url("")), chunk_digest)
    try:
        honest_url = str(server.make_url(""))
        tampering_url = str(proxy.make_url(""))

        result = await invoke(
            runner,
            ["trust", "add", "acme-lab", fingerprint, "--mirror", tampering_url, "--mirror", honest_url],
        )
        assert result.exit_code == 0, result.output

        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.2.0"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is True

        materialized = Path(payload["materialized"])
        assert (materialized / "big.bin").read_bytes() == (src / "big.bin").read_bytes()

        # Peer scoring is weighted-random (peers.py), so which peer actually
        # served the tampered chunk in any single run isn't deterministic --
        # the honest peer might get picked for every chunk by chance. The
        # deterministic proof that a mismatch is scored/blacklisted lives in
        # tests/adversarial/test_t1_mirror_tamper.py; this e2e test's job is
        # just proving the fetch succeeds end to end through the real CLI
        # with a bad mirror configured, which it does regardless of which
        # peer got selected.
        assert (workspace["home"] / "peers.json").exists()
    finally:
        await server.close()
        await proxy.close()


async def test_publish_fetch_tampered_origin_fails_closed(runner, workspace):
    fingerprint = await _publish_fixture_artifact(runner, workspace)
    origin = workspace["origin"]

    # Corrupt one byte of one chunk directly on the origin's disk, between
    # publish and fetch -- simulating a compromised mirror serving altered
    # bytes for an otherwise legitimately-published release.
    from vouch import cas as cas_mod
    from vouch import originstore

    # Find the manifest that `current` points to, then one of its chunks.
    current = originstore.read_current_pointer(origin, fingerprint, "bert-tiny", "1.2.0")
    envelope = originstore.read_manifest_envelope(origin, current["digest"])
    manifest = json.loads(base64.b64decode(envelope["payload"]))
    chunk_digest = manifest["files"][0]["chunks"][0]
    obj_path = cas_mod.object_path(origin, chunk_digest)
    corrupted = bytearray(obj_path.read_bytes())
    corrupted[0] ^= 0xFF
    obj_path.write_bytes(bytes(corrupted))

    server = TestServer(build_app(origin))
    await server.start_server()
    try:
        base_url = str(server.make_url(""))
        result = await invoke(runner, ["trust", "add", "acme-lab", fingerprint, "--mirror", base_url])
        assert result.exit_code == 0, result.output

        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.2.0"])
        assert result.exit_code == 40, result.output
        payload = json.loads(result.output)
        assert payload["ok"] is False

        fail_check = next(c for c in payload["checks"] if not c["ok"])
        assert fail_check["id"] == "V8"
        assert "evidence" in fail_check

        evidence_dir = Path(fail_check["evidence"])
        assert evidence_dir.is_dir()
        assert (evidence_dir / "report.json").exists()
        assert (evidence_dir / "bytes.bin").exists()

        # Nothing materialized.
        home = workspace["home"]
        assert not (home / "verified" / "acme-lab").exists()
    finally:
        await server.close()
