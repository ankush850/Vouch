from vouch.cli._output import render_human


def test_render_human_success_with_materialization():
    result = {
        "op": "fetch",
        "ref": "acme-lab/bert-tiny@1.2.0",
        "ok": True,
        "exit_code": 0,
        "checks": [
            {"id": "V1", "ok": True, "detail": "acme-lab -> b3:aaaa"},
            {"id": "V4", "ok": True, "detail": "timestamp seq 1"},
            {"id": "V5", "ok": True, "detail": "b3:snap"},
        ],
        "materialized": "/home/user/.vouch/verified/acme-lab/bert-tiny/1.2.0",
    }
    output = render_human(result)
    assert "timestamp" in output  # V4's friendly label
    assert "snapshot" in output  # V5's friendly label
    assert "[V4]" in output
    assert "materialized /home/user/.vouch/verified/acme-lab/bert-tiny/1.2.0" in output


def test_render_human_rollback_failure_has_remedy():
    result = {
        "op": "fetch",
        "ref": "acme-lab/bert-tiny@1.2.0",
        "ok": False,
        "exit_code": 31,
        "checks": [
            {"id": "V1", "ok": True, "detail": "acme-lab -> b3:aaaa"},
            {"id": "V4", "ok": False, "detail": "timestamp seq 1 is older than the previously seen seq 3"},
        ],
    }
    output = render_human(result)
    assert "FAIL" in output
    assert "remedy:" in output
    assert "rollback" in output.lower() or "report the offending mirror" in output


def test_render_human_equivocation_failure_has_remedy():
    result = {
        "op": "fetch",
        "ref": "acme-lab/bert-tiny@1.2.0",
        "ok": False,
        "exit_code": 44,
        "checks": [{"id": "V4", "ok": False, "detail": "equivocation: two different timestamp statements"}],
    }
    output = render_human(result)
    assert "equivocation" in output.lower()


def test_render_human_unknown_check_id_falls_back_to_raw_id():
    result = {"op": "fetch", "ref": "r", "ok": True, "exit_code": 0, "checks": [{"id": "V99", "ok": True}]}
    output = render_human(result)
    assert "V99" in output
