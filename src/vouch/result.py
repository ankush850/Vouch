"""Shared result/v1 object construction, per 04_FRONTEND_SPEC.md section 8.

Human-readable CLI output and `--json` output are both views of the same
result object; this module is where that object gets built, shared by
`fetch_flow.py` and `verify_flow.py` so both commands produce checks in
the same shape.
"""

from __future__ import annotations

from .errors import VouchError


def check_ok(checks: list[dict], check_id: str, detail: str | None = None) -> None:
    entry = {"id": check_id, "ok": True}
    if detail:
        entry["detail"] = detail
    checks.append(entry)


def check_fail(checks: list[dict], check_id: str, err: VouchError) -> None:
    entry = {"id": check_id, "ok": False, "detail": err.message}
    for key in ("peer", "expected", "actual"):
        value = err.detail.get(key)
        if value is not None:
            entry[key] = value
    if err.evidence is not None:
        entry["evidence"] = str(err.evidence)
    checks.append(entry)


def build_result(op: str, ref: str, ok: bool, exit_code: int, checks: list[dict], **extra) -> dict:
    result = {
        "vouch": "result/v1",
        "op": op,
        "ref": ref,
        "ok": ok,
        "exit_code": int(exit_code),
        "checks": checks,
    }
    result.update(extra)
    return result
