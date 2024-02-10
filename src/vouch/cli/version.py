"""`vouch version` command: display version and platform runtime details."""

from __future__ import annotations

import json
import platform
import sys

import click


@click.command("version")
@click.pass_context
def version_command(ctx: click.Context) -> None:
    """Display Vouch version and build environment metadata."""
    meta = {
        "vouch": "0.1.0",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "executable": sys.executable,
    }

    if ctx.obj and ctx.obj.get("json"):
        click.echo(json.dumps(meta))
    else:
        click.echo(f"Vouch v{meta['vouch']} (Python {meta['python']} on {meta['platform']})")
