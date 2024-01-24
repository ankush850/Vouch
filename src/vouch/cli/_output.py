"""Human/JSON rendering of the shared result/v1 object, per
04_FRONTEND_SPEC.md sections 2 and 8: human output is a view of the same
object `--json` emits, and every failure prints the failing check, the
evidence location, and a remedy if one exists.
"""

from __future__ import annotations

import json

import click

_LABELS = {
    "V1": "pin",
    "V2": "root",
    "V4": "timestamp",
    "V5": "snapshot",
    "V6": "manifest",
    "V7": "log",
    "V8": "chunks",
    "V9": "assembly",
    "V10": "provenance",
}

_REMEDIES = {
    2: "check command usage (vouch COMMAND --help)",
    20: "check network connectivity / mirror availability, or add another mirror",
    21: "check the artifact name/version; nothing published under that reference",
    30: "add an independent mirror; the publisher may have stopped reissuing timestamps, or peers are withholding",
    31: "none on the consumer side; this is a legitimate rollback rejection -- report the offending mirror",
    40: "add an honest mirror (vouch trust add ... --mirror URL) or retry later",
    41: "none on the consumer side; the publisher must re-sign or investigate",
    42: "the signing key was revoked; wait for the publisher to re-sign with a new key (vouch publish --resign-all)",
    43: 'obtain the fingerprint from an out-of-band channel, then\n           vouch trust add NAME <fingerprint>',
    44: "equivocation or a broken transparency-log proof detected; do not trust either statement, report the offending mirror",
    45: "the provenance attestation is invalid or doesn't match this manifest; report the offending mirror or publisher",
    70: "internal error; please file a bug report",
}


def render_human(result: dict) -> str:
    checks = result.get("checks", [])
    label_width = max((len(_LABELS.get(c["id"], c["id"])) for c in checks), default=4)

    lines = []
    for c in checks:
        label = _LABELS.get(c["id"], c["id"])
        status = "ok" if c["ok"] else "FAIL"
        line = f"{label:<{label_width}}  {status}"
        if c.get("detail"):
            line += f"  {c['detail']}"
        line += f"  [{c['id']}]"
        lines.append(line)
        if not c["ok"]:
            if c.get("evidence"):
                lines.append(f"evidence:  {c['evidence']}")
            remedy = _REMEDIES.get(result["exit_code"])
            if remedy:
                lines.append(f"remedy:    {remedy}")

    if result["ok"]:
        if result.get("materialized"):
            lines.append(f"materialized {result['materialized']}")
        elif result.get("op") == "verify":
            lines.append(f"result: the signed artifact for {result['ref']}")
    else:
        lines.append(f"result: {result['op']} FAILED for {result['ref']} (exit {result['exit_code']})")

    return "\n".join(lines)


def emit(ctx: click.Context, result: dict) -> None:
    if ctx.obj.get("json"):
        click.echo(json.dumps(result))
    else:
        click.echo(render_human(result))
