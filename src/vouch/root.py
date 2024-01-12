"""Root trust document, per 02_TECHNICAL_ARCHITECTURE.md section 4.1.

A publisher's identity IS the fingerprint of its ORIGINAL (genesis) root
public key -- this becomes the permanent `publisher` field, fixed forever
even as `keys.root` changes across rotations (M3). Three verification
entry points exist, each anchored to a different trust boundary; using the
wrong one for a given caller is a real security bug, not just a style
choice, so read the docstrings before reaching for one:

- `verify_root_genesis` -- the trust bootstrap. Requires the served
  document to be signed SPECIFICALLY by the pinned fingerprint's own key
  (not merely by "a key the untrusted document happens to declare in its
  own `keys.root` list" -- that would let a lookalike publisher vouch for
  itself by inventing a bogus root key entry, exactly threat T4A). Only
  valid for verifying root version 1 against a fresh network response.
- `verify_root_link` -- one hop of a chain walk between two ALREADY-
  established trust points: proves `next` is a legitimate rotation of
  `prev` via TUF-style cross-signing (satisfies both prev's threshold
  under prev's keys AND next's own threshold under next's own keys).
- `verify_root_chain` -- orchestrates genesis + every subsequent link for
  a full envelope list from an UNTRUSTED network source. This is what
  `freshness.fetch_verified_root_chain` calls.
- `verify_root_doc` -- NOT safe against untrusted network input. Verifies
  a single document is self-consistent (satisfies its own declared
  threshold under its own declared root keys) and its permanent
  `publisher` field matches the pin. Trust for *why this version is
  legitimate* was already established once, when `fetch_flow.py` walked
  the full chain and cached this exact envelope; this function is a
  defense-in-depth re-check against LOCAL cache tampering, used only by
  `verify_flow.py`'s fully-offline path. Never call this on a fresh
  network response.

Every check that examines signatures also takes an optional `revoked_keys`
set (D13, security doc section 5.5): a cryptographically valid signature
from a revoked key is still rejected, with no time-based carve-out for
signatures made before the revocation.
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import dsse
from .canonical import canonicalize, is_canonical
from .errors import PinMismatchError, RollbackError, SignatureError
from .hashing import b3_hex
from .timeutil import format_iso8601, is_expired, utc_now

ROOT_TYPE = "root/v1"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def _key_entry(key_id: str, pub: bytes) -> dict:
    return {"id": key_id, "pub": _b64(pub)}


def _decode_key_map(entries) -> dict[str, bytes]:
    """Decode a `keys.<role>` list into keyid -> raw pubkey bytes, dropping
    any entry whose declared `id` does NOT equal `b3:` + hex(pub) -- a key
    id is defined as the fingerprint of its own public key (hashing.py),
    so an entry claiming an id that doesn't match its own pub is either
    corrupt or an attempt to mislabel a key under someone else's
    fingerprint (exactly the T4A trick: "invent an entry claiming to BE
    the pinned fingerprint, but supply a public key we actually hold").
    Silently dropping it (rather than raising) means every caller's
    existing "id not found" handling naturally covers this too.
    """
    keys: dict[str, bytes] = {}
    if not isinstance(entries, list):
        return keys
    for entry in entries:
        if not isinstance(entry, dict) or "id" not in entry or "pub" not in entry:
            continue
        try:
            pub = _b64d(entry["pub"])
        except Exception:
            continue
        if b3_hex(pub) != entry["id"]:
            continue
        keys[entry["id"]] = pub
    return keys


def _decode_envelope_payload(envelope: dict) -> dict:
    if not isinstance(envelope, dict) or "payload" not in envelope:
        raise SignatureError("malformed root document envelope")
    try:
        raw_payload = _b64d(envelope["payload"])
        claimed = json.loads(raw_payload)
    except Exception as e:
        raise SignatureError("malformed root document payload") from e
    if not isinstance(claimed, dict):
        raise SignatureError("malformed root document payload")
    return claimed


def _finish_verified(parsed: dict, payload: bytes) -> dict:
    if not is_canonical(parsed, payload):
        raise SignatureError("root document payload is not canonical JSON")
    _check_not_expired(parsed)
    return parsed


def _check_not_expired(parsed: dict) -> None:
    expires = parsed.get("expires")
    try:
        expired = is_expired(expires)
    except Exception as e:
        raise SignatureError(f"root document has an unparseable expiry: {expires!r}") from e
    if expired:
        raise SignatureError(f"root document expired at {expires}")


def default_root_expires(*, days: int = 365) -> str:
    return format_iso8601(utc_now() + timedelta(days=days))


def build_root_doc(
    *,
    publisher: str,
    root_keys: list[tuple[str, bytes]],
    release_keys: list[tuple[str, bytes]] = (),
    timestamp_keys: list[tuple[str, bytes]] = (),
    root_version: int = 1,
    threshold_root: int = 1,
    revoked: list[dict] = (),
    expires: str | None = None,
) -> dict:
    """`publisher` is the permanent identity fingerprint -- callers building
    the genesis document (root_version=1) pass the genesis root key's own
    id as `publisher`; callers building a rotation pass the SAME value
    forward unchanged, even though `root_keys` may now list different keys.
    """
    return {
        "vouch": ROOT_TYPE,
        "publisher": publisher,
        "root_version": root_version,
        "keys": {
            "root": [_key_entry(kid, pub) for kid, pub in root_keys],
            "release": [_key_entry(kid, pub) for kid, pub in release_keys],
            "timestamp": [_key_entry(kid, pub) for kid, pub in timestamp_keys],
        },
        "threshold": {"root": threshold_root},
        "revoked": list(revoked),
        "expires": expires or default_root_expires(),
    }


def sign_root_doc(doc: dict, root_private_key: Ed25519PrivateKey, root_key_id: str) -> dict:
    """Sign (or, via `dsse.add_signature` on the result, co-sign) a root
    document. Rotation ceremonies call this once for the new root key's
    self-signature and `dsse.add_signature` once more for the old root
    key's cross-signature (or vice versa; order doesn't matter to
    `verify_root_link`, which checks both independently).
    """
    return dsse.sign(canonicalize(doc), root_private_key, root_key_id)


def verify_root_genesis(envelope: dict, *, pinned_fingerprint: str) -> dict:
    """The trust bootstrap (T4A): the served document must be signed
    SPECIFICALLY by the pinned fingerprint's own key. Returns the verified
    root document (expected to be root_version 1, though this function
    does not itself enforce that -- `verify_root_chain` only ever calls it
    on the first element of an envelope list, by construction).
    """
    claimed = _decode_envelope_payload(envelope)

    root_keys = _decode_key_map(claimed.get("keys", {}).get("root", []))
    pinned_pub = root_keys.get(pinned_fingerprint)
    if pinned_pub is None:
        raise PinMismatchError(
            f"served root document does not list the pinned fingerprint {pinned_fingerprint} as a root key",
            pinned=pinned_fingerprint,
        )

    payload = dsse.verify(envelope, {pinned_fingerprint: pinned_pub})
    parsed = json.loads(payload)

    if parsed.get("publisher") != pinned_fingerprint:
        raise PinMismatchError("root document publisher field does not match pinned fingerprint")

    return _finish_verified(parsed, payload)


def verify_root_link(prev_doc: dict, next_envelope: dict, *, revoked_keys: frozenset[str] = frozenset()) -> dict:
    """One hop of a chain walk: `next_envelope` must be a legitimate
    rotation of `prev_doc` (TUF-style cross-signing). `revoked_keys` is the
    set accumulated BEFORE this hop (a revoked root key can't authorize a
    rotation); `next_doc`'s own `revoked` entries are not yet in effect for
    this same hop -- see module docstring and DECISIONS.md on revocation
    propagation semantics.
    """
    next_claimed = _decode_envelope_payload(next_envelope)

    if next_claimed.get("publisher") != prev_doc.get("publisher"):
        raise PinMismatchError("root rotation changed the publisher identity")

    expected_version = prev_doc.get("root_version", 0) + 1
    next_version = next_claimed.get("root_version", 0)
    if next_version != expected_version:
        raise RollbackError(
            f"root version {next_version} is not the next version after {prev_doc.get('root_version')} "
            f"(expected {expected_version})",
            seen=prev_doc.get("root_version"),
            offered=next_version,
        )

    prev_root_keys = _decode_key_map(prev_doc.get("keys", {}).get("root", []))
    prev_threshold = prev_doc.get("threshold", {}).get("root", 1)
    next_root_keys = _decode_key_map(next_claimed.get("keys", {}).get("root", []))
    next_threshold = next_claimed.get("threshold", {}).get("root", 1)

    # Cross-signing: satisfies the PREVIOUS root's threshold...
    dsse.verify_threshold(next_envelope, prev_root_keys, prev_threshold, revoked_keys=revoked_keys)
    # ...AND the NEW root's own declared threshold (self-consistency).
    payload = dsse.verify_threshold(next_envelope, next_root_keys, next_threshold, revoked_keys=revoked_keys)

    parsed = json.loads(payload)
    return _finish_verified(parsed, payload)


def verify_root_chain(
    envelopes: list[dict], *, pinned_fingerprint: str, min_version: int = 0
) -> tuple[dict, frozenset[str]]:
    """Walk a full root envelope list, starting from genesis (`envelopes[0]`
    must be root_version 1). Returns (current root document, accumulated
    revoked-key-id set). Raises on the first invalid hop.
    """
    if not envelopes:
        raise SignatureError("no root documents to verify")

    current = verify_root_genesis(envelopes[0], pinned_fingerprint=pinned_fingerprint)
    revoked = revoked_key_ids(current)

    for next_envelope in envelopes[1:]:
        current = verify_root_link(current, next_envelope, revoked_keys=revoked)
        revoked = revoked | revoked_key_ids(current)

    current_version = current.get("root_version", 0)
    if current_version < min_version:
        raise RollbackError(
            f"root chain ends at version {current_version}, older than the previously seen version {min_version}",
            seen=min_version,
            offered=current_version,
        )

    return current, revoked


def verify_root_doc(envelope: dict, *, pinned_fingerprint: str, min_version: int = 0) -> dict:
    """Re-verify a LOCALLY CACHED root document for self-consistency. NOT
    safe against untrusted network input -- see module docstring. Used by
    `verify_flow.py`'s fully-offline path only.
    """
    claimed = _decode_envelope_payload(envelope)

    if claimed.get("publisher") != pinned_fingerprint:
        raise PinMismatchError(
            f"root document publisher does not match pinned fingerprint {pinned_fingerprint}",
            pinned=pinned_fingerprint,
        )

    root_keys = _decode_key_map(claimed.get("keys", {}).get("root", []))
    threshold = claimed.get("threshold", {}).get("root", 1)
    payload = dsse.verify_threshold(envelope, root_keys, threshold)

    parsed = json.loads(payload)
    verified = _finish_verified(parsed, payload)

    root_version = verified.get("root_version", 0)
    if root_version < min_version:
        raise RollbackError(
            f"root version {root_version} is older than the previously seen version {min_version}",
            seen=min_version,
            offered=root_version,
        )
    return verified


def revoked_key_ids(doc: dict) -> frozenset[str]:
    return frozenset(
        entry["id"] for entry in doc.get("revoked", []) if isinstance(entry, dict) and "id" in entry
    )


def authorized_keys_for_role(root_doc: dict, role: str) -> dict[str, bytes]:
    """Extract keyid -> raw public key bytes for every key of `role` listed
    in a verified root document (used to authorize manifest/attestation
    signatures).
    """
    entries = root_doc.get("keys", {}).get(role, [])
    return _decode_key_map(entries)
