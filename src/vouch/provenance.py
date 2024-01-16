"""Provenance attestation, per 02_TECHNICAL_ARCHITECTURE.md section 5.

In-toto flavored, DSSE-signed by the release key (no new role), bound to
the manifest digest in BOTH directions: the manifest's `provenance` field
names the attestation's own digest, and the attestation's `subject.digest`
names the manifest's digest. Forging a lineage edge (a `materials` entry)
therefore requires either a hash preimage or the release key -- this is
T5A's entire mitigation, and is why this module deliberately mirrors
`manifest.py`'s verification shape closely.

Storage and serving reuse manifest.py's existing machinery UNCHANGED
(`originstore.write_manifest_envelope`/`read_manifest_envelope`,
`GET /v1/manifest/{digest}`): an attestation is just another digest-
addressed signed JSON blob, content-addressed exactly like a manifest, so
no new storage or route code exists for it.
"""

from __future__ import annotations

import json

from . import dsse
from .canonical import canonicalize, is_canonical
from .errors import ProvenanceInvalidError
from .hashing import b3_hex
from .timeutil import utc_now_iso

PROVENANCE_TYPE = "provenance/v1"


def build_provenance(
    *,
    name: str,
    version: str,
    manifest_digest: str,
    materials: list[dict],
    build: dict,
    created: str | None = None,
) -> dict:
    return {
        "vouch": PROVENANCE_TYPE,
        "subject": {"name": name, "version": version, "digest": manifest_digest},
        "materials": list(materials),
        "build": dict(build),
        "created": created or utc_now_iso(),
    }


def provenance_digest(doc: dict) -> str:
    return b3_hex(canonicalize(doc))


def sign_provenance(doc: dict, private_key, key_id: str) -> dict:
    return dsse.sign(canonicalize(doc), private_key, key_id)


def verify_provenance_envelope(
    envelope: dict,
    *,
    authorized_keys: dict[str, bytes],
    expected_digest: str,
    subject_manifest_digest: str,
    revoked_keys: frozenset[str] = frozenset(),
) -> dict:
    """Implements V10. Signature-level failures (bad/unauthorized/revoked
    signer) surface from the underlying `dsse.verify` as SignatureError(41)
    or KeyRevokedError(42); every structural failure specific to provenance
    itself (malformed payload, digest mismatch, subject binding mismatch)
    is ProvenanceInvalidError(45), per the security doc's V10 entry.
    """
    payload = dsse.verify(envelope, authorized_keys, revoked_keys=revoked_keys)

    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as e:
        raise ProvenanceInvalidError("provenance payload is not valid JSON") from e
    if not isinstance(parsed, dict):
        raise ProvenanceInvalidError("provenance payload is not a JSON object")

    if not is_canonical(parsed, payload):
        raise ProvenanceInvalidError("provenance payload is not canonical JSON")

    digest = b3_hex(payload)
    if digest != expected_digest:
        raise ProvenanceInvalidError(
            f"provenance digest mismatch: expected {expected_digest}, got {digest}",
            expected=expected_digest,
            actual=digest,
        )

    subject_digest = parsed.get("subject", {}).get("digest") if isinstance(parsed.get("subject"), dict) else None
    if subject_digest != subject_manifest_digest:
        raise ProvenanceInvalidError(
            "provenance subject digest does not match the manifest that names it",
            expected=subject_manifest_digest,
            actual=subject_digest,
        )

    return parsed
