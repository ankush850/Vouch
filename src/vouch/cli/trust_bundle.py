"""`vouch trust-bundle`: export publisher trust pin configuration bundles."""

from __future__ import annotations

import json
from pathlib import Path

import click

from .. import trust_store
from ..store import default_home, ensure_layout, trust_dir


@click.command("trust-bundle")
@click.option("--name", default=None, help="Publisher name to export")
@click.pass_context
def trust_bundle_command(ctx: click.Context, name: str | None) -> None:
    """Export trust pins for distribution and bootstrapping."""
    home = default_home()
    ensure_layout(home)
    tdir = trust_dir(home)

    publishers = [name] if name else sorted(p.name for p in tdir.iterdir() if p.is_dir()) if tdir.is_dir() else []
    bundle = []
    for pub in publishers:
        try:
            pin = trust_store.load_pin(home, pub)
            bundle.append({"publisher": pub, "pin": pin})
        except Exception:
            continue

    out = {"vouch": "trust-bundle/v1", "count": len(bundle), "pins": bundle}
    if ctx.obj and ctx.obj.get("json"):
        click.echo(json.dumps(out))
    else:
        click.echo(f"Trust Bundle ({len(bundle)} publishers):")
        click.echo(json.dumps(out, indent=2))
