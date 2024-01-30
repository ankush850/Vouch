"""M3 end-to-end scripted scenario, driven through the real `vouch` CLI
surface, per the M3 plan's verification section: keygen -> publisher init
-> delegate -> publish (with --base/--dataset provenance and --records) ->
origin reissue-timestamp -> rotate -> import-root -> revoke -> publish
--resign-all -> fetch (confirms chain-walk + V7/V10) -> vouch status
(confirms revoked-artifact flagging) -> vouch provenance (confirms
lineage renders) -> vouch diff (T3B-PUBLISHER-POISON-AUDIT) -> vouch
log show.

Same conventions as tests/e2e/test_publish_fetch_verify.py: `origin serve`
itself blocks forever, so the published store is served via
`aiohttp.test_utils.TestServer` wrapping the same `httpserver.build_app`
the command uses; every other step goes through `CliRunner` against the
real `vouch` command group, invoked via `asyncio.to_thread` since
`fetch`/`verify`/etc. call `asyncio.run()` internally.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from click.testing import CliRunner

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


async def test_m3_full_ceremony_walkthrough(runner, workspace):
    keys_dir = workspace["keys"]
    origin = workspace["origin"]
    tmp_path = workspace["tmp_path"]

    # --- bootstrap: keys, publisher, delegated roles ---
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

    # --- publish a base model and a dataset (v1, --records line) ---
    src_base = tmp_path / "src_base"
    src_base.mkdir()
    (src_base / "model.bin").write_bytes(b"base model weights" * 10)

    src_ds = tmp_path / "src_ds"
    src_ds.mkdir()
    (src_ds / "data.jsonl").write_bytes(b'{"a":1}\n{"a":2}\n{"a":3}\n')

    result = await invoke(
        runner,
        [
            "publish", str(src_base), "--name", "base-model", "--version", "1.0.0", "--type", "model",
            "--release-key", str(keys_dir / "release.key"), "--store", str(origin),
        ],
        passphrase="relpass",
    )
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner,
        [
            "publish", str(src_ds), "--name", "my-dataset", "--version", "1.0.0", "--type", "dataset",
            "--records", "line", "--release-key", str(keys_dir / "release.key"), "--store", str(origin),
        ],
        passphrase="relpass",
    )
    assert result.exit_code == 0, result.output

    result = await invoke(
        runner, ["origin", "reissue-timestamp", "--store", str(origin), "--timestamp-key", str(keys_dir / "timestamp.key")],
        passphrase="tspass",
    )
    assert result.exit_code == 0, result.output

    server = TestServer(build_app(origin))
    await server.start_server()
    try:
        base_url = str(server.make_url(""))
        result = await invoke(runner, ["trust", "add", "acme-lab", fingerprint, "--mirror", base_url])
        assert result.exit_code == 0, result.output

        # Fetch both, so `publish --base/--dataset` can resolve them from the local cache.
        for ref in ("acme-lab/base-model@1.0.0", "acme-lab/my-dataset@1.0.0"):
            result = await invoke(runner, ["--json", "fetch", ref])
            assert result.exit_code == 0, result.output
            assert json.loads(result.output)["ok"] is True

        # --- publish a fine-tuned model with provenance materials ---
        src_finetuned = tmp_path / "src_finetuned"
        src_finetuned.mkdir()
        (src_finetuned / "model.bin").write_bytes(b"finetuned weights" * 10)

        result = await invoke(
            runner,
            [
                "publish", str(src_finetuned), "--name", "bert-finetuned", "--version", "1.0.0", "--type", "model",
                "--base", "acme-lab/base-model@1.0.0", "--dataset", "acme-lab/my-dataset@1.0.0",
                "--code", "git+https://example.com/train@abc123",
                "--release-key", str(keys_dir / "release.key"), "--store", str(origin),
            ],
            passphrase="relpass",
        )
        assert result.exit_code == 0, result.output
        assert "provenance" in result.output

        # --- publish dataset v2 (T3B-PUBLISHER-POISON-AUDIT): flip a record, add one ---
        (src_ds / "data.jsonl").write_bytes(b'{"a":1}\n{"a":99}\n{"a":3}\n{"a":4}\n')
        result = await invoke(
            runner,
            [
                "publish", str(src_ds), "--name", "my-dataset", "--version", "2.0.0", "--type", "dataset",
                "--records", "line", "--release-key", str(keys_dir / "release.key"), "--store", str(origin),
            ],
            passphrase="relpass",
        )
        assert result.exit_code == 0, result.output

        result = await invoke(
            runner, ["origin", "reissue-timestamp", "--store", str(origin), "--timestamp-key", str(keys_dir / "timestamp.key")],
            passphrase="tspass",
        )
        assert result.exit_code == 0, result.output

        # v1 fetch already checked V1-V9 above; confirm the finetuned model
        # fetches clean with V10 (provenance) verified.
        result = await invoke(runner, ["--json", "fetch", "acme-lab/bert-finetuned@1.0.0"])
        assert result.exit_code == 0, result.output
        finetuned_payload = json.loads(result.output)
        assert finetuned_payload["ok"] is True
        assert {c["id"] for c in finetuned_payload["checks"]} == {
            "V1", "V2", "V4", "V5", "V6", "V7", "V8", "V9", "V10"
        }
        assert all(c["ok"] for c in finetuned_payload["checks"])

        # v2's publish produced a valid inclusion proof and the checkpoint
        # advanced -- confirmed by fetch succeeding through V7 at all.
        result = await invoke(runner, ["--json", "fetch", "acme-lab/my-dataset@2.0.0"])
        assert result.exit_code == 0, result.output
        v2_payload = json.loads(result.output)
        assert v2_payload["ok"] is True
        v7_check = next(c for c in v2_payload["checks"] if c["id"] == "V7")
        assert v7_check["ok"] is True

        # T3B: diff enumerates exactly the injected/modified record.
        result = await invoke(runner, ["--json", "diff", "acme-lab/my-dataset@1.0.0", "acme-lab/my-dataset@2.0.0"])
        assert result.exit_code == 0, result.output
        diff_payload = json.loads(result.output)
        file_diff = diff_payload["files"]["data.jsonl"]
        assert file_diff["added_count"] == 1
        assert file_diff["removed_count"] == 0
        assert file_diff["modified_count"] == 1
        assert file_diff["modified"][0]["index"] == 1

        # provenance: confirm the lineage tree renders with both materials.
        result = await invoke(runner, ["--json", "provenance", "acme-lab/bert-finetuned@1.0.0"])
        assert result.exit_code == 0, result.output
        lineage_payload = json.loads(result.output)
        roles = {m["role"] for m in lineage_payload["root"]["materials"]}
        assert roles == {"base-model", "dataset"}
        assert all(m["node"].get("error") is None for m in lineage_payload["root"]["materials"])

        # log show: confirm the leaves reproduce the verified checkpoint.
        result = await invoke(runner, ["--json", "log", "show", "acme-lab"])
        assert result.exit_code == 0, result.output
        log_payload = json.loads(result.output)
        assert log_payload["checkpoint"]["tree_size"] == len(log_payload["leaves"])
        assert {leaf["event"] for leaf in log_payload["leaves"]} == {"publish"}

        # --- rotate the root key ---
        result = await invoke(
            runner,
            [
                "keygen", "--role", "root", "--out", str(keys_dir / "root2.key"),
            ],
            passphrase="rootpass2",
        )
        assert result.exit_code == 0, result.output

        result = await invoke(
            runner,
            [
                "rotate", "--store", str(origin),
                "--root-key", str(keys_dir / "root.key"), "--new-root-key", str(keys_dir / "root2.key"),
                "--out", str(tmp_path / "rotated.json"),
            ],
            passphrase="rootpass", passphrase2="rootpass2",
        )
        assert result.exit_code == 0, result.output

        result = await invoke(
            runner,
            [
                "publisher", "import-root", str(tmp_path / "rotated.json"),
                "--store", str(origin), "--release-key", str(keys_dir / "release.key"),
            ],
            passphrase="relpass",
        )
        assert result.exit_code == 0, result.output

        # Consumer, still pinned only to the genesis fingerprint, chain-walks
        # to the new head transparently (v4: init, delegate x2, then rotate).
        result = await invoke(runner, ["--json", "fetch", "acme-lab/base-model@1.0.0"])
        assert result.exit_code == 0, result.output
        root_check = next(c for c in json.loads(result.output)["checks"] if c["id"] == "V2")
        assert "root v4" in root_check["detail"]

        # --- revoke the release key (using the NEW root key) ---
        result = await invoke(
            runner,
            [
                "keygen", "--role", "release", "--out", str(keys_dir / "release2.key"),
            ],
            passphrase="relpass2",
        )
        assert result.exit_code == 0, result.output

        # Read the current release key id off the root doc to revoke it precisely.
        from vouch import originstore as originstore_mod
        from vouch.cli._common import decode_envelope_payload, latest_root_version

        current_version = latest_root_version(origin, fingerprint)
        current_doc = decode_envelope_payload(originstore_mod.read_root_doc(origin, fingerprint, current_version))
        old_release_kid = current_doc["keys"]["release"][0]["id"]

        result = await invoke(
            runner,
            [
                "revoke", old_release_kid, "--reason", "smoke-test-compromise",
                "--store", str(origin), "--root-key", str(keys_dir / "root2.key"),
                "--out", str(tmp_path / "revoked.json"),
            ],
            passphrase="rootpass2",
        )
        assert result.exit_code == 0, result.output

        result = await invoke(
            runner,
            [
                "publisher", "import-root", str(tmp_path / "revoked.json"),
                "--store", str(origin), "--release-key", str(keys_dir / "release.key"),
            ],
            passphrase="relpass",
        )
        assert result.exit_code == 0, result.output

        # Delegate the new release key -- revoking the old one doesn't itself
        # authorize a replacement; `resign-all` needs release2 to actually be
        # in the current root's authorized release keys for its re-signed
        # manifests to verify.
        result = await invoke(
            runner,
            [
                "publisher", "delegate", "--role", "release",
                "--key", str(keys_dir / "release2.key.pub"),
                "--root-key", str(keys_dir / "root2.key"), "--store", str(origin),
            ],
            passphrase="rootpass2",
        )
        assert result.exit_code == 0, result.output

        # --- resign-all with the fresh release key, recovering availability ---
        result = await invoke(
            runner,
            ["publish", "--resign-all", "--release-key", str(keys_dir / "release2.key"), "--store", str(origin)],
            passphrase="relpass2",
        )
        assert result.exit_code == 0, result.output
        assert "log checkpoint" in result.output

        # `status`: the pre-revocation-materialized base-model artifact is flagged.
        result = await invoke(runner, ["--json", "status", "acme-lab"])
        status_payload = json.loads(result.output)
        assert result.exit_code != 0  # any_revoked -> SystemExit(1)
        base_model_entries = [
            a for entry in status_payload["publishers"] for a in entry["artifacts"] if a["artifact"] == "base-model"
        ]
        assert base_model_entries and base_model_entries[0]["revoked"] is True

        # Fetching fresh content signed with the NEW release key succeeds cleanly.
        result = await invoke(runner, ["--json", "fetch", "acme-lab/my-dataset@2.0.0"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["ok"] is True
    finally:
        await server.close()
