"""`vouch provenance REF [--deep] [--dot]`, per 04_FRONTEND_SPEC.md's
provenance/lineage command and 02_TECHNICAL_ARCHITECTURE.md section 5.

Emits its own `lineage/v1` JSON shape rather than `result/v1` -- a
documented, deliberate exception (see the M3 plan): this is a report of a
materials graph, not a pass/fail checklist of numbered verification
checks, so forcing it into the `checks` shape would be a worse fit than a
small, separately-documented shape.
"""

from __future__ import annotations

import asyncio
import json

import click

from .. import trust_store
from ..errors import VouchError
from ..httpclient import OriginClient
from ..lineage import walk_lineage
from ..store import default_home, ensure_layout


@click.command("provenance")
@click.argument("ref")
@click.option("--deep", is_flag=True, help="Fetch each node's bytes too (not just metadata)")
@click.option("--dot", is_flag=True, help="Emit Graphviz DOT instead of JSON/text")
@click.option("--max-depth", default=5, help="Maximum materials-graph depth to walk")
@click.option("--mirror", default=None, help="Mirror base URL to use if none is pinned")
@click.pass_context
def provenance_command(ctx: click.Context, ref: str, deep: bool, dot: bool, max_depth: int, mirror: str | None) -> None:
    """Walk and print the materials lineage graph for REF."""
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
    if base_url is None:
        raise click.ClickException(f"no mirror configured for {publisher_name}; pass --mirror")

    async def run() -> dict:
        async with OriginClient(base_url) as client:
            return await walk_lineage(home, client, ref, deep=deep, max_depth=max_depth)

    tree = asyncio.run(run())
    result = {"vouch": "lineage/v1", "ref": ref, "deep": deep, "root": tree}

    if dot:
        click.echo(_render_dot(tree))
    elif ctx.obj.get("json"):
        click.echo(json.dumps(result))
    else:
        click.echo(_render_text(tree))

    if _has_error(tree):
        raise SystemExit(1)


def _render_text(node: dict, prefix: str = "", role: str | None = None) -> str:
    label = node["ref"]
    if role:
        label = f"[{role}] {label}"
    if node.get("error"):
        line = f"{prefix}{label}  ERROR: {node['error']}"
    elif node.get("cycle"):
        line = f"{prefix}{label}  (cycle, stopping)"
    elif node.get("truncated"):
        line = f"{prefix}{label}  (max depth reached)"
    else:
        status = "materialized" if node.get("materialized") else "metadata-only"
        line = f"{prefix}{label}  ({node.get('digest')}, {status})"

    lines = [line]
    for i, child in enumerate(node.get("materials", [])):
        lines.append(_render_text(child["node"], prefix + "  ", role=child.get("role")))
    return "\n".join(lines)


def _render_dot(node: dict, edges: list[str] | None = None) -> str:
    top = edges is None
    edges = edges if edges is not None else []

    def walk(n: dict) -> None:
        for child in n.get("materials", []):
            child_node = child["node"]
            edges.append(f'  "{n["ref"]}" -> "{child_node["ref"]}" [label="{child.get("role", "")}"];')
            walk(child_node)

    walk(node)
    if not top:
        return ""
    return "digraph lineage {\n" + "\n".join(edges) + "\n}"


def _has_error(node: dict) -> bool:
    if node.get("error"):
        return True
    return any(_has_error(child["node"]) for child in node.get("materials", []))
