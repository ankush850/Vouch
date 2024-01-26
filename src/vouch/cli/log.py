"""`vouch log show`, per 04_FRONTEND_SPEC.md section 4 and
02_TECHNICAL_ARCHITECTURE.md section 4.3.

Read-only inspection: fetches and verifies the current root chain (for
the release keys that authorize the checkpoint) and the checkpoint itself
(V7's freshness/consistency half), then fetches the raw leaf list
(`GET .../log/leaves`, explicitly untrusted wire data -- see
httpserver.py) and locally recomputes the Merkle root over it to confirm
it reproduces the verified checkpoint's root_hash before printing
anything.
"""

from __future__ import annotations

import asyncio
import json

import click

from .. import freshness, log as log_mod, trust_store
from ..errors import LogFailureError, VouchError
from ..httpclient import OriginClient
from ..root import authorized_keys_for_role
from ..store import default_home, ensure_layout


@click.group("log")
def log_group() -> None:
    """Transparency log inspection."""


@log_group.command("show")
@click.argument("name")
@click.option("--mirror", default=None, help="Mirror base URL to use (defaults to the pinned mirror list)")
@click.pass_context
def log_show(ctx: click.Context, name: str, mirror: str | None) -> None:
    """Show the transparency log checkpoint and leaves for pinned publisher NAME."""
    home = default_home()
    ensure_layout(home)

    try:
        pin = trust_store.load_pin(home, name)
    except VouchError as e:
        raise click.ClickException(str(e))
    fingerprint = pin["fingerprint"]

    base_url = mirror or (pin["mirrors"][0] if pin["mirrors"] else None)
    if base_url is None:
        raise click.ClickException(f"no mirror configured for {name}; pass --mirror")

    async def run() -> tuple[dict, list]:
        async with OriginClient(base_url) as client:
            _envelope, root_doc, revoked_keys = await freshness.fetch_verified_root_chain(
                home, client, name, fingerprint
            )
            authorized_release = authorized_keys_for_role(root_doc, "release")
            checkpoint = await freshness.fetch_verified_checkpoint(
                home, client, name, fingerprint, authorized_release, revoked_keys=revoked_keys
            )
            leaves = await client.get_log_leaves(fingerprint) or []
            hashes = [log_mod.leaf_hash(leaf) for leaf in leaves]
            if log_mod.merkle_root(hashes) != checkpoint["root_hash"]:
                raise LogFailureError("fetched leaves do not reproduce the verified checkpoint's root hash")
            return checkpoint, leaves

    try:
        checkpoint, leaves = asyncio.run(run())
    except VouchError as e:
        raise click.ClickException(str(e))

    if ctx.obj.get("json"):
        click.echo(json.dumps({"vouch": "log/v1", "checkpoint": checkpoint, "leaves": leaves}))
        return

    click.echo(f"checkpoint: tree_size={checkpoint['tree_size']} root_hash={checkpoint['root_hash']}")
    for leaf in leaves:
        click.echo(f"  [{leaf['seq']}] {leaf['event']:<8} {leaf['digest']}")
