from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from .. import trust_store, verify_flow
from ..errors import VouchError
from ..httpclient import OriginClient
from ..store import default_home, ensure_layout
from ._output import emit


@click.command("verify")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--ref", required=True, help="NAME/ARTIFACT@VERSION to verify PATH against")
@click.option("--mirror", default=None, help="Mirror base URL to use if the manifest isn't already cached")
@click.pass_context
def verify_command(ctx: click.Context, path: Path, ref: str, mirror: str | None) -> None:
    """Verify PATH is byte-exact against the signed manifest for REF."""
    home = default_home()
    ensure_layout(home)

    publisher_name = ref.split("/", 1)[0]
    base_url = mirror
    if base_url is None:
        try:
            pin = trust_store.load_pin(home, publisher_name)
            base_url = pin["mirrors"][0] if pin["mirrors"] else None
        except VouchError:
            base_url = None

    async def run() -> dict:
        if base_url is not None:
            async with OriginClient(base_url) as client:
                return await verify_flow.verify(home, path, ref, client=client)
        return await verify_flow.verify(home, path, ref, client=None)

    result = asyncio.run(run())
    emit(ctx, result)
    sys.exit(result["exit_code"])
