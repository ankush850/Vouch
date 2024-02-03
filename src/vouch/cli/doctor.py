"""`vouch doctor` command: diagnose local installation, cryptographic primitives, and environment layout."""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path

import click

from ..store import cas_dir, default_home, ensure_layout, trust_dir


@click.command("doctor")
@click.pass_context
def doctor_command(ctx: click.Context) -> None:
    """Diagnose local environment, cryptographic dependencies, and store integrity."""
    checks = []
    all_ok = True

    # 1. Python version check
    py_ver = sys.version_info
    py_ok = (py_ver.major == 3 and py_ver.minor >= 11) or py_ver.major > 3
    checks.append({
        "check": "python_version",
        "status": "ok" if py_ok else "warn",
        "message": f"Python {platform.python_version()} (>= 3.11 recommended)",
    })
    if not py_ok:
        all_ok = False

    # 2. Cryptographic backend check: blake3
    try:
        import blake3

        hasher = blake3.blake3(b"vouch-health-check")
        digest = hasher.hexdigest()
        checks.append({
            "check": "crypto_blake3",
            "status": "ok",
            "message": "BLAKE3 hashing engine functional",
        })
    except Exception as e:
        checks.append({
            "check": "crypto_blake3",
            "status": "error",
            "message": f"BLAKE3 unavailable: {e}",
        })
        all_ok = False

    # 3. Cryptographic backend check: cryptography (Ed25519)
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        sig = priv.sign(b"test")
        pub.verify(sig, b"test")
        checks.append({
            "check": "crypto_ed25519",
            "status": "ok",
            "message": "Ed25519 signature engine functional",
        })
    except Exception as e:
        checks.append({
            "check": "crypto_ed25519",
            "status": "error",
            "message": f"Ed25519 signature engine failed: {e}",
        })
        all_ok = False

    # 4. Canonical JSON serializer: rfc8785
    try:
        import rfc8785

        serialized = rfc8785.dumps({"test": 1, "a": True})
        checks.append({
            "check": "canonical_json",
            "status": "ok",
            "message": "RFC 8785 canonical JSON serializer functional",
        })
    except Exception as e:
        checks.append({
            "check": "canonical_json",
            "status": "error",
            "message": f"RFC 8785 serializer failed: {e}",
        })
        all_ok = False

    # 5. Local store directory integrity
    home = default_home()
    try:
        ensure_layout(home)
        tdir = trust_dir(home)
        cdir = cas_dir(home)
        pin_count = len([p for p in tdir.iterdir() if p.is_dir()]) if tdir.is_dir() else 0
        cas_entries = len(list(cdir.iterdir())) if cdir.is_dir() else 0

        checks.append({
            "check": "store_layout",
            "status": "ok",
            "message": f"Vouch home layout valid at {home} (pins: {pin_count}, cas items: {cas_entries})",
        })
    except Exception as e:
        checks.append({
            "check": "store_layout",
            "status": "error",
            "message": f"Failed to initialize Vouch store layout: {e}",
        })
        all_ok = False

    if ctx.obj and ctx.obj.get("json"):
        click.echo(json.dumps({"vouch": "doctor/v1", "healthy": all_ok, "checks": checks}))
    else:
        click.echo("Vouch Doctor Diagnostics:")
        for c in checks:
            badge = " [OK] " if c["status"] == "ok" else f"[{c['status'].upper()}]"
            click.echo(f"{badge} {c['check']}: {c['message']}")
        if not all_ok:
            click.echo("\nDoctor check completed with warnings/errors.")

    if not all_ok:
        raise SystemExit(1)
