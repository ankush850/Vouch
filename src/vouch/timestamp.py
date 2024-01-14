"""Timestamp statement, per 02_TECHNICAL_ARCHITECTURE.md section 4.2.

Tiny, short-lived, and reissued independently of `publish` (03's role
separation: the timestamp key is meant to live on a different, more
frequently-online host than the release key). Signed the same way as the
root document -- a DSSE envelope over canonical JSON -- so the trust-
relevant bytes live inside the envelope's base64 `payload` field, immune to
outer-JSON reformatting. Contrast with `snapshot.py`, which is NOT signed
this way (see that module's docstring).

This module implements only the crypto+expiry half of V4
(03_SECURITY_AND_ACCESS.md section 6): signature validity and freshness.
The high-water-mark/equivocation half of V4 is `trust_store.py`'s job,
orchestrated together by `freshness.py`.
"""

from __future__ import annotations

import json
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import dsse
from .canonical import canonicalize, is_canonical
from .errors import SignatureError, StaleError
from .timeutil import format_iso8601, is_expired, is_issued_too_far_in_future, parse_iso8601, utc_now_iso

TIMESTAMP_TYPE = "timestamp/v1"
DEFAULT_TTL = timedelta(hours=24)


def build_timestamp_statement(
    *,
    publisher: str,
    seq: int,
    snapshot_digest: str,
    issued: str | None = None,
    ttl: timedelta = DEFAULT_TTL,
) -> dict:
    issued_at = issued or utc_now_iso()
    expires_at = format_iso8601(parse_iso8601(issued_at) + ttl)
    return {
        "vouch": TIMESTAMP_TYPE,
        "publisher": publisher,
        "seq": seq,
        "snapshot": snapshot_digest,
        "issued": issued_at,
        "expires": expires_at,
    }


def sign_timestamp(statement: dict, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    return dsse.sign(canonicalize(statement), private_key, key_id)


def verify_timestamp_envelope(
    envelope: dict,
    *,
    authorized_keys: dict[str, bytes],
    publisher: str,
    revoked_keys: frozenset[str] = frozenset(),
) -> dict:
    """Crypto + expiry only (V4's non-hwm half). Returns the verified statement.

    Fail: SignatureError(41) for a bad/unauthorized signature, non-canonical
    payload, publisher mismatch, or `issued` too far in the future (the
    clock-policy rule from section 6). StaleError(30) if `expires` has
    lapsed beyond the skew allowance. KeyRevokedError(42, M3) if the only
    otherwise-valid signature was from a revoked timestamp key.
    """
    payload = dsse.verify(envelope, authorized_keys, revoked_keys=revoked_keys)

    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as e:
        raise SignatureError("timestamp payload is not valid JSON") from e
    if not isinstance(parsed, dict):
        raise SignatureError("timestamp payload is not a JSON object")

    if not is_canonical(parsed, payload):
        raise SignatureError("timestamp payload is not canonical JSON")

    if parsed.get("vouch") != TIMESTAMP_TYPE:
        raise SignatureError(f"unexpected document type: {parsed.get('vouch')!r}")

    if parsed.get("publisher") != publisher:
        raise SignatureError("timestamp publisher field does not match the requested publisher")

    issued = parsed.get("issued")
    try:
        issued_too_future = is_issued_too_far_in_future(issued)
    except Exception as e:
        raise SignatureError(f"timestamp has an unparseable issued time: {issued!r}") from e
    if issued_too_future:
        raise SignatureError(f"timestamp issued in the future: {issued}")

    expires = parsed.get("expires")
    try:
        expired = is_expired(expires)
    except Exception as e:
        raise SignatureError(f"timestamp has an unparseable expiry: {expires!r}") from e
    if expired:
        raise StaleError(f"timestamp expired at {expires}")

    return parsed
