"""Shared clock/skew/ISO-8601 helpers.

Extracted from `root.py` (which originally defined `CLOCK_SKEW` and its own
expiry parsing) so `timestamp.py` can reuse the same 10-minute skew
allowance (03_SECURITY_AND_ACCESS.md section 6: "Clock policy") without
importing `root.py` for unrelated reasons.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

CLOCK_SKEW = timedelta(minutes=10)
_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime(_FORMAT)


def format_iso8601(dt: datetime) -> str:
    return dt.strftime(_FORMAT)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso8601(value: str) -> datetime:
    return datetime.strptime(value, _FORMAT).replace(tzinfo=timezone.utc)


def is_expired(expires: str, *, skew: timedelta = CLOCK_SKEW) -> bool:
    """True if `expires` (an ISO-8601 UTC timestamp) is in the past, allowing
    for clock skew.
    """
    return utc_now() - skew > parse_iso8601(expires)


def is_issued_too_far_in_future(issued: str, *, skew: timedelta = CLOCK_SKEW) -> bool:
    """True if `issued` claims a time further ahead than the skew allowance --
    the clock-policy rule from the security doc's V4 checklist: a statement
    issued in the future beyond the allowance is rejected as invalid, not
    accepted.
    """
    return parse_iso8601(issued) - skew > utc_now()
