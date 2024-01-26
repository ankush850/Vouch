from __future__ import annotations

import asyncio
import sys

import click

from .. import fetch_flow, trust_store
from ..errors import VouchError
from ..peers import PeerPool
from ..store import default_home, ensure_layout
from ._output import emit


@click.command("fetch")
@click.argument("ref")
@click.option(
    "--mirror",
    "mirrors",
    multiple=True,
    help="Mirror base URL (repeatable). Overrides the pinned mirror list entirely if given.",
)
@click.pass_context
def fetch_command(ctx: click.Context, ref: str, mirrors: tuple[str, ...]) -> None:
    """Fetch and verify REF (NAME/ARTIFACT@VERSION), materializing it on success."""
    home = default_home()
    ensure_layout(home)

    publisher_name = ref.split("/", 1)[0]
    base_urls = list(mirrors)
    if not base_urls:
        try:
            pin = trust_store.load_pin(home, publisher_name)
            base_urls = list(pin["mirrors"])
        except VouchError:
            base_urls = []
    if not base_urls:
        # No mirror configured (or no pin at all): still run the flow so V1
        # produces the canonical missing-pin result, or (if a pin exists
        # with no mirrors) so V2's network attempt against a clearly
        # unreachable placeholder produces a clean exit-20 result rather
        # than a crash.
        base_urls = ["http://127.0.0.1:1"]

    async def run() -> dict:
        async with PeerPool(home, base_urls) as pool:
            return await fetch_flow.fetch(home, pool, ref)

    result = asyncio.run(run())
    emit(ctx, result)
    sys.exit(result["exit_code"])
