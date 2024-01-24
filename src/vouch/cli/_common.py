"""Small helpers shared across CLI commands."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import click

from .. import originstore


def find_sole_publisher(store: Path) -> str:
    """M1/M2 support exactly one publisher per origin store; return its
    fingerprint (the name of the sole subdirectory under `publisher/`).
    """
    publisher_dir = store / "publisher"
    if not publisher_dir.is_dir():
        raise click.ClickException(f"{store}: no publisher initialized here; run `publisher init` first")
    candidates = [p.name for p in publisher_dir.iterdir() if p.is_dir()]
    if len(candidates) == 0:
        raise click.ClickException(f"{store}: no publisher initialized here; run `publisher init` first")
    if len(candidates) > 1:
        raise click.ClickException(
            f"{store}: multiple publishers present ({', '.join(candidates)}); one publisher per store is supported"
        )
    candidate = candidates[0]
    if os.name == "nt" and candidate.startswith("b3_"):
        return "b3:" + candidate[3:]
    return candidate


def latest_root_version(store: Path, fingerprint: str) -> int:
    root_dir = originstore.publisher_dir(store, fingerprint) / "root"
    if not root_dir.is_dir():
        raise click.ClickException(f"{store}: no root document found for {fingerprint}")
    versions = [int(p.stem) for p in root_dir.iterdir() if p.is_file() and p.suffix == ".json" and p.stem.isdigit()]
    if not versions:
        raise click.ClickException(f"{store}: no root document found for {fingerprint}")
    return max(versions)


def decode_envelope_payload(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"], validate=True))


def decode_key_entries(entries: list[dict]) -> list[tuple[str, bytes]]:
    return [(e["id"], base64.b64decode(e["pub"], validate=True)) for e in entries]
