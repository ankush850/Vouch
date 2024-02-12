"""`vouch key-export`: export public key fingerprints and canonical metadata."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import blake3
import click


@click.command("key-export")
@click.argument("pub_key_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
def keys_export_command(ctx: click.Context, pub_key_path: Path) -> None:
    """Export fingerprint and canonical JSON for an Ed25519 public key."""
    raw = pub_key_path.read_bytes()
    # If raw is base64 or raw 32 bytes
    if len(raw) == 32:
        pub_bytes = raw
    else:
        try:
            pub_bytes = base64.b64decode(raw.strip())
        except Exception:
            pub_bytes = raw

    fingerprint = f"b3:{blake3.blake3(pub_bytes).hexdigest()}"
    res = {
        "key_file": str(pub_key_path),
        "fingerprint": fingerprint,
        "public_base64": base64.b64encode(pub_bytes).decode("ascii"),
    }

    if ctx.obj and ctx.obj.get("json"):
        click.echo(json.dumps(res))
    else:
        click.echo(f"Key File:    {pub_key_path}")
        click.echo(f"Fingerprint: {fingerprint}")
        click.echo(f"Public (b64): {res['public_base64']}")
