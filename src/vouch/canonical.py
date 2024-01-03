"""JSON canonicalization, per 02_TECHNICAL_ARCHITECTURE.md section 3.5 (Decision D4).

All signed payloads are canonicalized per RFC 8785 (JCS) before signing or
digesting. This removes an entire class of signature-bypass bugs where two
semantically-equal but byte-different JSON encodings would produce different
signatures/digests.
"""

from __future__ import annotations

import rfc8785


def canonicalize(obj) -> bytes:
    """Return the RFC 8785 canonical JSON encoding of `obj` as bytes."""
    return rfc8785.dumps(obj)


def is_canonical(obj, payload: bytes) -> bool:
    """True if `payload` is the RFC 8785 canonical encoding of `obj`.

    Every `verify_*_envelope` caller uses this (instead of calling
    `canonicalize` directly) on attacker-controlled, already-signature-
    verified payloads: `rfc8785.dumps` raises its own `ValueError`
    subclasses (e.g. `IntegerDomainError`) for values outside JCS's safe
    integer/float domain, found by M4's parser fuzzing to otherwise
    escape as an unhandled exception past every one of these callers'
    existing `except (ValueError, ...)` blocks, none of which wrapped the
    canonicalize call itself. Such a value can never legitimately BE the
    canonical encoding of anything, so "not canonical" (False, not an
    exception) is the correct, uniform answer.
    """
    try:
        return canonicalize(obj) == payload
    except ValueError:
        return False
