"""Compromise-playbook drills, per 03_SECURITY_AND_ACCESS.md section 5.6:
scripting the documented incident-response procedures end to end through
the real CLI, not just unit-testing the primitives they're built from.

The release-key playbook (revoke -> rotate -> `publish --resign-all` ->
advisory event in the log) is already fully drilled by
tests/e2e/test_m3_ceremony.py (the ceremony walkthrough) combined with
tests/adversarial/test_t4c_revocation.py (the attacker's-perspective half
-- a still-compromised key rejected post-revocation). Not repeated here.

This file covers the two playbooks that weren't yet drilled end to end:

- **Timestamp key compromise** (section 5.6: "attacker can issue fresh-
  looking timestamps... cannot cause acceptance of any manifest the
  release key did not sign... Response: revoke, rotate, reissue"):
  revoke the compromised timestamp key, delegate a replacement, reissue
  the timestamp with it, confirm the consumer fetches cleanly again --
  and confirm a "fresh-looking" timestamp the attacker still produces
  with the now-revoked key (simulating them continuing to hold it after
  the response) is rejected with KeyRevokedError (exit 42), not silently
  accepted just because its `issued`/`expires` fields look current.
- **Root key compromise** (section 5.6: "full identity compromise...
  Response is out-of-band: publish a new fingerprint through the
  bootstrap channels and ask consumers to re-pin"): the only code-
  testable surface of an inherently manual, out-of-band procedure is
  that re-pinning an EXISTING local alias to a brand-new, unrelated
  fingerprint via `trust add` is a clean, supported operation that
  leaves no residual trust in the old identity -- fetching under the
  old identity's origin fails at the pin/root check once re-pinned,
  fetching the new publisher's content under the same local alias
  succeeds.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from click.testing import CliRunner

from vouch import originstore
from vouch import timestamp as timestamp_mod
from vouch.cli._common import decode_envelope_payload, latest_root_version
from vouch.cli.main import main
from vouch.httpserver import build_app

pytestmark = pytest.mark.asyncio


def _passphrase_fd(passphrase: str) -> int:
    r, w = os.pipe()
    os.write(w, (passphrase + "\n").encode())
    os.close(w)
    return r


async def invoke(runner: CliRunner, args: list[str], passphrase: str | None = None, passphrase2: str | None = None):
    full_args = list(args)
    if passphrase is not None:
        full_args += ["--passphrase-fd", str(_passphrase_fd(passphrase))]
    if passphrase2 is not None:
        full_args += ["--new-root-passphrase-fd", str(_passphrase_fd(passphrase2))]
    return await asyncio.to_thread(runner.invoke, main, full_args, catch_exceptions=False)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    home = tmp_path / "home"
    origin = tmp_path / "origin"
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    monkeypatch.setenv("VOUCH_HOME", str(home))
    return {"home": home, "origin": origin, "keys": keys_dir, "tmp_path": tmp_path}


async def _bootstrap(runner, workspace) -> str:
    """keygen x3 -> publisher init -> delegate release+timestamp ->
    publish v1 -> reissue-timestamp. Returns the publisher fingerprint.
    """
    keys_dir, origin, tmp_path = workspace["keys"], workspace["origin"], workspace["tmp_path"]

    for role, pw in (("root", "rootpass"), ("release", "relpass"), ("timestamp", "tspass")):
        result = await invoke(runner, ["keygen", "--role", role, "--out", str(keys_dir / f"{role}.key")], passphrase=pw)
        assert result.exit_code == 0, result.output

    result = await invoke(
        runner, ["publisher", "init", "acme-lab", "--root-key", str(keys_dir / "root.key"), "--store", str(origin)],
        passphrase="rootpass",
    )
    assert result.exit_code == 0, result.output
    fingerprint = result.output.split("->")[1].split()[0].strip()

    for role, pw in (("release", "relpass"), ("timestamp", "tspass")):
        result = await invoke(
            runner,
            [
                "publisher", "delegate", "--role", role,
                "--key", str(keys_dir / f"{role}.key.pub"),
                "--root-key", str(keys_dir / "root.key"), "--store", str(origin),
            ],
            passphrase="rootpass",
        )
        assert result.exit_code == 0, result.output

    src = tmp_path / "src"
    src.mkdir()
    (src / "model.bin").write_bytes(b"v1 weights" * 20)
    result = await invoke(
        runner,
        [
            "publish", str(src), "--name", "bert-tiny", "--version", "1.0.0", "--type", "model",
            "--release-key", str(keys_dir / "release.key"), "--store", str(origin),
        ],
        passphrase="relpass",
    )
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner, ["origin", "reissue-timestamp", "--store", str(origin), "--timestamp-key", str(keys_dir / "timestamp.key")],
        passphrase="tspass",
    )
    assert result.exit_code == 0, result.output
    return fingerprint


async def test_timestamp_key_compromise_playbook(runner, workspace):
    origin, keys_dir, tmp_path = workspace["origin"], workspace["keys"], workspace["tmp_path"]
    fingerprint = await _bootstrap(runner, workspace)

    server = TestServer(build_app(origin))
    await server.start_server()
    try:
        base_url = str(server.make_url(""))
        result = await invoke(runner, ["trust", "add", "acme-lab", fingerprint, "--mirror", base_url])
        assert result.exit_code == 0, result.output

        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.0.0"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["ok"] is True

        # --- Discover the timestamp key is compromised: revoke it ---
        old_ts_kid = json.loads((keys_dir / "timestamp.key.pub").read_text())["keyid"]
        result = await invoke(
            runner,
            [
                "revoke", old_ts_kid, "--reason", "timestamp key compromised",
                "--store", str(origin), "--root-key", str(keys_dir / "root.key"),
                "--out", str(tmp_path / "revoked_ts.json"),
            ],
            passphrase="rootpass",
        )
        assert result.exit_code == 0, result.output

        result = await invoke(
            runner,
            [
                "publisher", "import-root", str(tmp_path / "revoked_ts.json"),
                "--store", str(origin), "--release-key", str(keys_dir / "release.key"),
            ],
            passphrase="relpass",
        )
        assert result.exit_code == 0, result.output

        # --- Rotate: delegate a replacement timestamp key ---
        result = await invoke(runner, ["keygen", "--role", "timestamp", "--out", str(keys_dir / "timestamp2.key")], passphrase="tspass2")
        assert result.exit_code == 0, result.output

        result = await invoke(
            runner,
            [
                "publisher", "delegate", "--role", "timestamp",
                "--key", str(keys_dir / "timestamp2.key.pub"),
                "--root-key", str(keys_dir / "root.key"), "--store", str(origin),
            ],
            passphrase="rootpass",
        )
        assert result.exit_code == 0, result.output

        # --- Reissue with the new key ---
        result = await invoke(
            runner,
            ["origin", "reissue-timestamp", "--store", str(origin), "--timestamp-key", str(keys_dir / "timestamp2.key")],
            passphrase="tspass2",
        )
        assert result.exit_code == 0, result.output

        # --- Consumer fetches cleanly again, under the new timestamp key ---
        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.0.0"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["ok"] is True

        # --- The attacker, still holding the OLD (now-revoked) key, issues
        # a fresh-looking timestamp anyway. It must be rejected -- not
        # accepted just because `issued`/`expires` look current.
        #
        # `delegate` REPLACES the authorized timestamp key list (D5's
        # single-active-key-per-role model), so after rotation the old key
        # is not merely revoked, it's absent from `keys.timestamp`
        # entirely -- dsse.verify_threshold only checks `revoked_keys` for
        # a key that's still nominally authorized, so this specific
        # sequence surfaces a generic SignatureError(41) rather than
        # KeyRevokedError(42) (T4C's dedicated test proves the 42 case,
        # where `revoke` alone -- no accompanying `delegate` -- leaves the
        # compromised key both listed AND revoked). Either way is fail-
        # closed, which is the property this drill proves. ---
        old_ts_loaded = _load_encrypted_key(keys_dir / "timestamp.key", "tspass")
        current_snapshot_digest = _current_snapshot_digest(origin, fingerprint)
        forged_seq = originstore.next_timestamp_seq(origin, fingerprint)
        forged_stmt = timestamp_mod.build_timestamp_statement(
            publisher=fingerprint, seq=forged_seq, snapshot_digest=current_snapshot_digest
        )
        forged_envelope = timestamp_mod.sign_timestamp(forged_stmt, old_ts_loaded.private_key, old_ts_loaded.key_id)
        originstore.write_timestamp(origin, fingerprint, forged_envelope)

        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.0.0"])
        assert result.exit_code in (41, 42), result.output
        payload = json.loads(result.output)
        assert payload["ok"] is False
        fail_check = next(c for c in payload["checks"] if not c["ok"])
        assert fail_check["id"] == "V4"
    finally:
        await server.close()


async def test_root_key_compromise_playbook_repin_to_new_identity(runner, workspace):
    tmp_path, keys_dir = workspace["tmp_path"], workspace["keys"]
    old_fingerprint = await _bootstrap(runner, workspace)
    old_origin = workspace["origin"]

    old_server = TestServer(build_app(old_origin))
    await old_server.start_server()
    try:
        old_url = str(old_server.make_url(""))
        result = await invoke(runner, ["trust", "add", "acme-lab", old_fingerprint, "--mirror", old_url])
        assert result.exit_code == 0, result.output

        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.0.0"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["ok"] is True

        # --- Root key compromise discovered. There is no automatic
        # recovery (03_SECURITY_AND_ACCESS.md 5.6): the publisher
        # establishes a BRAND NEW identity out-of-band (a fresh root key,
        # a fresh origin store) and distributes the new fingerprint
        # through bootstrap channels. The consumer re-pins. ---
        new_keys_dir = tmp_path / "new_keys"
        new_keys_dir.mkdir()
        new_origin = tmp_path / "new_origin"

        for role, pw in (("root", "newrootpass"), ("release", "newrelpass"), ("timestamp", "newtspass")):
            result = await invoke(
                runner, ["keygen", "--role", role, "--out", str(new_keys_dir / f"{role}.key")], passphrase=pw
            )
            assert result.exit_code == 0, result.output

        result = await invoke(
            runner,
            ["publisher", "init", "acme-lab", "--root-key", str(new_keys_dir / "root.key"), "--store", str(new_origin)],
            passphrase="newrootpass",
        )
        assert result.exit_code == 0, result.output
        new_fingerprint = result.output.split("->")[1].split()[0].strip()
        assert new_fingerprint != old_fingerprint

        for role, pw in (("release", "newrelpass"), ("timestamp", "newtspass")):
            result = await invoke(
                runner,
                [
                    "publisher", "delegate", "--role", role,
                    "--key", str(new_keys_dir / f"{role}.key.pub"),
                    "--root-key", str(new_keys_dir / "root.key"), "--store", str(new_origin),
                ],
                passphrase="newrootpass",
            )
            assert result.exit_code == 0, result.output

        src = tmp_path / "new_src"
        src.mkdir()
        (src / "model.bin").write_bytes(b"post-compromise weights" * 20)
        result = await invoke(
            runner,
            [
                "publish", str(src), "--name", "bert-tiny", "--version", "1.0.0", "--type", "model",
                "--release-key", str(new_keys_dir / "release.key"), "--store", str(new_origin),
            ],
            passphrase="newrelpass",
        )
        assert result.exit_code == 0, result.output
        result = await invoke(
            runner,
            [
                "origin", "reissue-timestamp", "--store", str(new_origin),
                "--timestamp-key", str(new_keys_dir / "timestamp.key"),
            ],
            passphrase="newtspass",
        )
        assert result.exit_code == 0, result.output

        new_server = TestServer(build_app(new_origin))
        await new_server.start_server()
        try:
            new_url = str(new_server.make_url(""))

            # Re-pin the SAME local alias to the NEW fingerprint -- a
            # clean, supported operation (no special "force" flag needed).
            result = await invoke(runner, ["trust", "add", "acme-lab", new_fingerprint, "--mirror", new_url])
            assert result.exit_code == 0, result.output

            # The new identity's content fetches cleanly under the same alias.
            result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.0.0"])
            assert result.exit_code == 0, result.output
            assert json.loads(result.output)["ok"] is True

            # No residual trust in the old identity: the SAME local alias
            # ("acme-lab") now points at the new fingerprint, so pointing
            # `fetch` at the OLD origin instead (--mirror overrides the
            # pinned mirror list, but NOT the pinned fingerprint) must fail
            # -- root routes are namespaced by fingerprint
            # (GET /v1/{publisher}/meta/root/{n}), so the old origin has
            # nothing at all to serve under the new identity (a clean 404/
            # NetworkError), not a mismatched document to compare against.
            # Either way, nothing from the old identity is ever accepted.
            result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-tiny@1.0.0", "--mirror", old_url])
            assert result.exit_code == 20, result.output
            payload = json.loads(result.output)
            assert payload["ok"] is False
            fail_check = next(c for c in payload["checks"] if not c["ok"])
            assert fail_check["id"] == "V2"
        finally:
            await new_server.close()
    finally:
        await old_server.close()


def _load_encrypted_key(path: Path, passphrase: str):
    from vouch import keys as keys_mod

    return keys_mod.load_encrypted_key(path, passphrase)


def _current_snapshot_digest(origin_store: Path, fingerprint: str) -> str:
    envelope = originstore.read_timestamp(origin_store, fingerprint)
    return decode_envelope_payload(envelope)["snapshot"]
