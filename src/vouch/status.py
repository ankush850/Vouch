"""Reconciliation for `vouch status`, per 03_SECURITY_AND_ACCESS.md
section 5.5 and the M3 plan's "materialized-but-revoked marking" note.

Read-only: walks a pinned publisher's `verified/` tree, cross-referencing
each artifact's `.vouch-status.json` breadcrumb (written by
`fetch_flow._materialize`) against the CURRENT root's `revoked_key_ids()`
-- fetched fresh over the network via a full chain walk, never from a
stale local cache, since the whole point is to catch a revocation the
consumer hasn't fetched anything new since. Never re-verifies bytes,
never deletes or quarantines anything: refusing to use a flagged artifact
is a policy decision left to the caller (03_SECURITY_AND_ACCESS.md:
"refuses to open... until a re-signed manifest arrives"), not something
this module enforces.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import freshness
from .errors import VouchError
from .fetch_flow import STATUS_BREADCRUMB_NAME
from .httpclient import OriginClient
from .store import verified_dir
from .trust_store import load_pin


async def check_publisher(home: Path, client: OriginClient, publisher_name: str) -> dict:
    """Returns {"publisher", "fingerprint", "artifacts": [...]}, or
    {"publisher", "error", "artifacts": []} if the current root couldn't
    be fetched at all (e.g. offline) -- artifacts default to unreported,
    not flagged, in that case: absence of fresh information is not
    evidence of revocation.
    """
    try:
        pin = load_pin(home, publisher_name)
    except VouchError as e:
        return {"publisher": publisher_name, "error": str(e), "artifacts": []}
    fingerprint = pin["fingerprint"]

    try:
        _envelope, _root_doc, revoked_keys = await freshness.fetch_verified_root_chain(
            home, client, publisher_name, fingerprint
        )
    except VouchError as e:
        return {"publisher": publisher_name, "fingerprint": fingerprint, "error": str(e), "artifacts": []}

    artifacts = []
    base = verified_dir(home) / publisher_name
    if base.is_dir():
        for artifact_dir in sorted(p for p in base.iterdir() if p.is_dir()):
            for version_dir in sorted(p for p in artifact_dir.iterdir() if p.is_dir()):
                breadcrumb_path = version_dir / STATUS_BREADCRUMB_NAME
                if not breadcrumb_path.is_file():
                    continue
                breadcrumb = json.loads(breadcrumb_path.read_text())
                release_key_id = breadcrumb.get("release_key_id")
                revoked = release_key_id is not None and release_key_id in revoked_keys
                artifacts.append(
                    {
                        "artifact": artifact_dir.name,
                        "version": version_dir.name,
                        "manifest_digest": breadcrumb.get("manifest_digest"),
                        "release_key_id": release_key_id,
                        "revoked": revoked,
                    }
                )

    return {"publisher": publisher_name, "fingerprint": fingerprint, "artifacts": artifacts}
