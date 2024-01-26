from __future__ import annotations

import click

from .. import trust_store
from ..errors import VouchError
from ..store import default_home, ensure_layout


@click.group("trust")
def trust_group() -> None:
    """Local trust pin management."""


@trust_group.command("add")
@click.argument("name")
@click.argument("fingerprint")
@click.option("--mirror", "mirrors", multiple=True, required=True, help="Mirror base URL (repeatable)")
def trust_add(name: str, fingerprint: str, mirrors: tuple[str, ...]) -> None:
    """Pin NAME to FINGERPRINT locally, like an SSH known_hosts entry."""
    home = default_home()
    ensure_layout(home)
    trust_store.add_pin(home, name, fingerprint, list(mirrors))
    click.echo(f"pinned {name} -> {fingerprint} ({len(mirrors)} mirror(s))")


@trust_group.command("list")
def trust_list() -> None:
    """List local publisher pins."""
    home = default_home()
    from ..store import trust_dir

    tdir = trust_dir(home)
    if not tdir.is_dir():
        return
    for entry in sorted(tdir.iterdir()):
        if not entry.is_dir():
            continue
        try:
            pin = trust_store.load_pin(home, entry.name)
        except VouchError:
            continue
        click.echo(f"{pin['name']} -> {pin['fingerprint']} ({len(pin['mirrors'])} mirror(s))")
