"""`vouch status [NAME]`, per 04_FRONTEND_SPEC.md's status command and
03_SECURITY_AND_ACCESS.md section 5.5.

Surfaces materialized artifacts whose signer has since been revoked -- see
`status.py`'s module docstring for exactly what this does and does not do
(read-only reconciliation, never a re-verification or a deletion).
"""

from __future__ import annotations

import asyncio
import json

import click

from .. import status as status_mod, trust_store
from ..httpclient import OriginClient
from ..store import default_home, ensure_layout, trust_dir


@click.command("status")
@click.argument("name", required=False)
@click.option("--mirror", default=None, help="Mirror base URL override (defaults to each pin's mirror list)")
@click.pass_context
def status_command(ctx: click.Context, name: str | None, mirror: str | None) -> None:
    """Reconcile materialized artifacts against current revocations, for NAME or every pinned publisher."""
    home = default_home()
    ensure_layout(home)

    if name is not None:
        names = [name]
    else:
        tdir = trust_dir(home)
        names = sorted(p.name for p in tdir.iterdir() if p.is_dir()) if tdir.is_dir() else []

    async def run() -> list[dict]:
        results = []
        for publisher_name in names:
            base_url = mirror
            if base_url is None:
                try:
                    pin = trust_store.load_pin(home, publisher_name)
                    base_url = pin["mirrors"][0] if pin["mirrors"] else None
                except Exception:
                    base_url = None
            if base_url is None:
                results.append({"publisher": publisher_name, "error": "no mirror configured", "artifacts": []})
                continue
            async with OriginClient(base_url) as client:
                results.append(await status_mod.check_publisher(home, client, publisher_name))
        return results

    results = asyncio.run(run())
    any_revoked = any(a["revoked"] for entry in results for a in entry["artifacts"])

    if ctx.obj.get("json"):
        click.echo(json.dumps({"vouch": "status/v1", "publishers": results}))
    else:
        for entry in results:
            if entry.get("error"):
                click.echo(f"{entry['publisher']}: could not check ({entry['error']})")
                continue
            if not entry["artifacts"]:
                click.echo(f"{entry['publisher']}: no materialized artifacts")
                continue
            for a in entry["artifacts"]:
                flag = "REVOKED" if a["revoked"] else "ok"
                click.echo(f"{entry['publisher']}/{a['artifact']}@{a['version']}  {flag}  ({a['manifest_digest']})")

    if any_revoked:
        raise SystemExit(1)
