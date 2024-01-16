"""Lineage walk, per 02_TECHNICAL_ARCHITECTURE.md section 5 and
04_FRONTEND_SPEC.md's `provenance` command.

Defaults to metadata-only (Decision 9 in the M3 plan): each node's root,
manifest, and provenance attestation (if any) are verified, but chunk
bytes are never pulled unless that node's artifact is already
materialized in `verified/`, or `--deep` is given (which pulls it via the
real `fetch` pipeline, turning that node into a materialized one). A
max_depth + visited-ref guard protects against cyclic materials graphs --
a valid signature proves who asserted an edge, not that the graph it
describes is acyclic.

A node whose resolution fails (network error, not found, revoked, an
uncached/unpinned publisher) is a leaf carrying an `error` instead of
recursing further -- a broken edge doesn't abort the whole walk, since
lineage is a report for a human to read, not a pass/fail check like
`fetch`/`verify`.
"""

from __future__ import annotations

from pathlib import Path

from . import freshness
from . import fetch_flow as fetch_flow_mod
from .errors import ReferenceNotFoundError, VouchError
from .fetch_flow import parse_ref
from .httpclient import OriginClient
from .manifest import content_digest, verify_manifest_envelope
from .peers import PeerPool
from .provenance import verify_provenance_envelope
from .root import authorized_keys_for_role
from .store import verified_dir
from .trust_store import load_pin


async def _resolve_node(home: Path, client: OriginClient, ref: str) -> dict:
    """V1+V2+V4+V5+V6+V10 for one reference -- metadata only, no chunks."""
    publisher_name, artifact, version = parse_ref(ref)
    pin = load_pin(home, publisher_name)
    fingerprint = pin["fingerprint"]

    _root_envelope, root_doc, revoked_keys = await freshness.fetch_verified_root_chain(
        home, client, publisher_name, fingerprint
    )
    authorized_release = authorized_keys_for_role(root_doc, "release")
    authorized_timestamp = authorized_keys_for_role(root_doc, "timestamp")

    timestamp_stmt = await freshness.fetch_verified_timestamp(
        home, client, publisher_name, fingerprint, authorized_timestamp, revoked_keys=revoked_keys
    )
    snapshot_doc = await freshness.fetch_verified_snapshot(client, fingerprint, timestamp_stmt["snapshot"])

    artifact_entry = snapshot_doc.get("artifacts", {}).get(artifact)
    version_entry = artifact_entry.get("versions", {}).get(version) if artifact_entry else None
    if version_entry is None:
        raise ReferenceNotFoundError(f"{artifact}@{version} not found in snapshot for {fingerprint}")
    expected_digest = version_entry["manifest_digest"]

    manifest_envelope = await client.get_manifest(expected_digest)
    if manifest_envelope is None:
        raise ReferenceNotFoundError(f"manifest {expected_digest} not found at origin")
    manifest = verify_manifest_envelope(
        manifest_envelope,
        authorized_keys=authorized_release,
        expected_digest=expected_digest,
        publisher=fingerprint,
        name=artifact,
        version=version,
        revoked_keys=revoked_keys,
    )

    provenance = None
    if manifest.get("provenance"):
        attestation_digest = manifest["provenance"]
        attestation_envelope = await client.get_manifest(attestation_digest)
        if attestation_envelope is not None:
            provenance = verify_provenance_envelope(
                attestation_envelope,
                authorized_keys=authorized_release,
                expected_digest=attestation_digest,
                subject_manifest_digest=content_digest(manifest),
                revoked_keys=revoked_keys,
            )

    materialized = (verified_dir(home) / publisher_name / artifact / version).is_dir()
    return {
        "ref": ref,
        "digest": expected_digest,
        "type": manifest.get("type"),
        "materialized": materialized,
        "_provenance": provenance,
    }


async def walk_lineage(home: Path, client: OriginClient, ref: str, *, deep: bool = False, max_depth: int = 5) -> dict:
    """Returns a tree: {"ref", "digest", "type", "materialized",
    "materials": [{"role", "node": <tree>}]} -- or {"ref", "error"} /
    {"ref", "cycle": True} / {"ref", "truncated": True} for a node that
    couldn't be resolved, revisits an ancestor, or exceeds max_depth.
    """
    return await _walk(home, client, ref, deep=deep, max_depth=max_depth, visited=frozenset())


async def _walk(home: Path, client: OriginClient, ref: str, *, deep: bool, max_depth: int, visited: frozenset) -> dict:
    if ref in visited:
        return {"ref": ref, "cycle": True}
    if max_depth <= 0:
        return {"ref": ref, "truncated": True}
    visited = visited | {ref}

    try:
        node = await _resolve_node(home, client, ref)
    except VouchError as e:
        return {"ref": ref, "error": str(e)}

    if deep and not node["materialized"]:
        async with PeerPool(home, [client.base_url]) as pool:
            fetch_result = await fetch_flow_mod.fetch(home, pool, ref)
        node["materialized"] = bool(fetch_result.get("ok"))

    materials = []
    provenance = node.pop("_provenance")
    if provenance is not None:
        for material in provenance.get("materials", []):
            child = await _walk(home, client, material["ref"], deep=deep, max_depth=max_depth - 1, visited=visited)
            materials.append({"role": material.get("role"), "node": child})
    node["materials"] = materials
    return node
