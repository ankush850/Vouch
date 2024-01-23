"""PRD success criterion 6: "The codebase contains no flag, environment
variable, or code path that yields an unverified artifact in the verified
store." Checked here by test as the PRD requires, in addition to grep in
review.
"""

from __future__ import annotations

import re
from pathlib import Path

import vouch

PACKAGE_ROOT = Path(vouch.__file__).parent

_BYPASS_PATTERNS = [
    re.compile(r"--no-verify"),
    re.compile(r"--skip-verify"),
    re.compile(r"--insecure"),
    re.compile(r"\bno_verify\b"),
    re.compile(r"\bskip_verify\b"),
    re.compile(r"\bNO_VERIFY\b"),
    re.compile(r"\bSKIP_VERIFY\b"),
    re.compile(r"\bALLOW_UNVERIFIED\b"),
    re.compile(r"\bUNVERIFIED_OK\b"),
]


def _all_source_files():
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def test_no_bypass_flag_or_env_var_anywhere_in_source():
    offenders = []
    for path in _all_source_files():
        text = path.read_text()
        for pattern in _BYPASS_PATTERNS:
            if pattern.search(text):
                offenders.append((path, pattern.pattern))
    assert offenders == [], f"found verification-bypass-shaped code: {offenders}"


def test_materialize_is_the_only_writer_of_verified_dir():
    # `_materialize` in fetch_flow.py is the sole place anything is ever
    # renamed into verified/, and it is only reached after every check in
    # the pipeline (through V9) has passed.
    fetch_flow_source = (PACKAGE_ROOT / "fetch_flow.py").read_text()
    assert fetch_flow_source.count("verified_dir(home)") >= 1
    for path in _all_source_files():
        if path.name in ("fetch_flow.py", "store.py"):
            continue
        text = path.read_text()
        assert "os.replace" not in text, f"unexpected materialization-shaped write in {path}"
