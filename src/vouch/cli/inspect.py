"""`vouch inspect FILE`: decode and inspect DSSE envelopes, manifests, and root docs."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import click


@click.command("inspect")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
def inspect_command(ctx: click.Context, file_path: Path) -> None:
    """Inspect and decode a DSSE envelope or JSON document."""
    raw = file_path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except Exception as e:
        raise click.ClickException(f"Failed to parse JSON in {file_path}: {e}")

    # Check if it is a DSSE envelope
    if isinstance(data, dict) and "payloadType" in data and "payload" in data:
        try:
            payload_bytes = base64.b64decode(data["payload"])
            payload_json = json.loads(payload_bytes.decode("utf-8"))
            out = {
                "format": "dsse_envelope",
                "payloadType": data.get("payloadType"),
                "signatures_count": len(data.get("signatures", [])),
                "keyids": [s.get("keyid") for s in data.get("signatures", [])],
                "decoded_payload": payload_json,
            }
        except Exception:
            out = {"format": "dsse_envelope", "raw_envelope": data}
    else:
        out = {"format": "plain_json", "data": data}

    if ctx.obj and ctx.obj.get("json"):
        click.echo(json.dumps(out))
    else:
        click.echo(f"Inspecting {file_path} ({out['format']}):")
        click.echo(json.dumps(out, indent=2))
