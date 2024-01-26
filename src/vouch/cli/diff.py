"""`vouch diff REF1 REF2`, per 04_FRONTEND_SPEC.md's diff command and
02_TECHNICAL_ARCHITECTURE.md section 3.4 (T3B's detective mitigation).

Network-optional like `verify`: a reference already fetched/verified once
resolves entirely from the local cache; an uncached reference falls back
to the network only if `--mirror` is given. Emits its own `diff/v1` shape
(records.diff_record_indices' shape, one entry per file common to both
manifests' record indices) rather than `result/v1`, for the same reason
`provenance` does: this is a report, not a pass/fail checklist.
"""

from __future__ import annotations

import asyncio
import json

import click

from .. import freshness
from ..errors import VouchError, UsageError
from ..fetch_flow import parse_ref
from ..httpclient import OriginClient
from ..manifest import verify_manifest_envelope
from ..records import diff_record_indices
from ..root import authorized_keys_for_role, revoked_key_ids, verify_root_doc
from ..store import default_home, ensure_layout
from ..trust_store import (
    cache_manifest,
    cache_root_envelope,
    load_cached_manifest,
    load_cached_root_envelope,
    load_pin,
)


async def _resolve_manifest(home, ref: str, client: OriginClient | None) -> dict:
    publisher_name, artifact, version = parse_ref(ref)
    pin = load_pin(home, publisher_name)
    fingerprint = pin["fingerprint"]

    root_envelope = load_cached_root_envelope(home, publisher_name)
    if root_envelope is not None:
        root_doc = verify_root_doc(root_envelope, pinned_fingerprint=fingerprint)
        revoked_keys = revoked_key_ids(root_doc)
    else:
        if client is None:
            raise UsageError(f"{ref}: no cached root document; pass --mirror to resolve it over the network")
        root_envelope, root_doc, revoked_keys = await freshness.fetch_verified_root_chain(
            home, client, publisher_name, fingerprint
        )
    cache_root_envelope(home, publisher_name, root_envelope)

    authorized_release = authorized_keys_for_role(root_doc, "release")
    cached = load_cached_manifest(home, publisher_name, artifact, version)
    if cached is not None:
        expected_digest, manifest_envelope = cached["digest"], cached["envelope"]
    else:
        if client is None:
            raise UsageError(f"{ref}: no cached manifest; pass --mirror to resolve it over the network")
        authorized_timestamp = authorized_keys_for_role(root_doc, "timestamp")
        timestamp_stmt = await freshness.fetch_verified_timestamp(
            home, client, publisher_name, fingerprint, authorized_timestamp, revoked_keys=revoked_keys
        )
        snapshot_doc = await freshness.fetch_verified_snapshot(client, fingerprint, timestamp_stmt["snapshot"])
        artifact_entry = snapshot_doc.get("artifacts", {}).get(artifact)
        version_entry = artifact_entry.get("versions", {}).get(version) if artifact_entry else None
        if version_entry is None:
            raise UsageError(f"{artifact}@{version} not found in snapshot for {fingerprint}")
        expected_digest = version_entry["manifest_digest"]
        manifest_envelope = await client.get_manifest(expected_digest)
        if manifest_envelope is None:
            raise UsageError(f"manifest {expected_digest} not found at origin")
        cache_manifest(home, publisher_name, artifact, version, expected_digest, manifest_envelope)

    return verify_manifest_envelope(
        manifest_envelope,
        authorized_keys=authorized_release,
        expected_digest=expected_digest,
        publisher=fingerprint,
        name=artifact,
        version=version,
        revoked_keys=revoked_keys,
    )


@click.command("diff")
@click.argument("ref1")
@click.argument("ref2")
@click.option("--mirror", default=None, help="Mirror base URL to resolve an uncached reference")
@click.pass_context
def diff_command(ctx: click.Context, ref1: str, ref2: str, mirror: str | None) -> None:
    """Diff the record indices of two dataset REFs published with --records."""
    home = default_home()
    ensure_layout(home)

    async def run() -> tuple[dict, dict]:
        client = OriginClient(mirror) if mirror else None
        if client is not None:
            async with client:
                m1 = await _resolve_manifest(home, ref1, client)
                m2 = await _resolve_manifest(home, ref2, client)
                return m1, m2
        m1 = await _resolve_manifest(home, ref1, None)
        m2 = await _resolve_manifest(home, ref2, None)
        return m1, m2

    try:
        manifest1, manifest2 = asyncio.run(run())
    except VouchError as e:
        raise click.ClickException(str(e))

    index1 = manifest1.get("record_index") or {}
    index2 = manifest2.get("record_index") or {}
    all_paths = sorted(set(index1) | set(index2))

    files = {}
    for path in all_paths:
        if path in index1 and path in index2:
            files[path] = diff_record_indices(index1[path], index2[path])
        elif path in index1:
            files[path] = {"status": "removed"}
        else:
            files[path] = {"status": "added"}

    result = {"vouch": "diff/v1", "ref1": ref1, "ref2": ref2, "files": files}

    if ctx.obj.get("json"):
        click.echo(json.dumps(result))
        return

    if not files:
        click.echo(f"no record index on either {ref1} or {ref2} (publish with --records to enable this)")
        return
    for path, d in files.items():
        if d.get("status") == "added":
            click.echo(f"{path}: only in {ref2}")
        elif d.get("status") == "removed":
            click.echo(f"{path}: only in {ref1}")
        else:
            click.echo(
                f"{path}: {d['added_count']} added, {d['removed_count']} removed, {d['modified_count']} modified"
                f" ({d['old_count']} -> {d['new_count']} records)"
            )
            if d["duplicates_among_added"]:
                click.echo(f"  {len(d['duplicates_among_added'])} duplicate digest(s) among added records")
