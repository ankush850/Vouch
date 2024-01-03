from datetime import timedelta

from vouch.timeutil import (
    CLOCK_SKEW,
    format_iso8601,
    is_expired,
    is_issued_too_far_in_future,
    parse_iso8601,
    utc_now,
    utc_now_iso,
)


def test_utc_now_iso_round_trips_through_parse():
    now = utc_now_iso()
    parsed = parse_iso8601(now)
    assert format_iso8601(parsed) == now


def test_is_expired_false_for_future_expiry():
    future = format_iso8601(utc_now() + timedelta(days=1))
    assert not is_expired(future)


def test_is_expired_true_for_past_expiry_beyond_skew():
    past = format_iso8601(utc_now() - CLOCK_SKEW - timedelta(minutes=1))
    assert is_expired(past)


def test_is_expired_tolerates_skew_window():
    just_past = format_iso8601(utc_now() - timedelta(minutes=1))
    assert not is_expired(just_past)


def test_is_issued_too_far_in_future_true_beyond_skew():
    far_future = format_iso8601(utc_now() + CLOCK_SKEW + timedelta(minutes=1))
    assert is_issued_too_far_in_future(far_future)


def test_is_issued_too_far_in_future_false_within_skew():
    near_future = format_iso8601(utc_now() + timedelta(minutes=1))
    assert not is_issued_too_far_in_future(near_future)


def test_is_issued_too_far_in_future_false_for_past():
    past = format_iso8601(utc_now() - timedelta(days=1))
    assert not is_issued_too_far_in_future(past)
