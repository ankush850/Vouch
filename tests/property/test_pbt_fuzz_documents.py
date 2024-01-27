"""M4 parser fuzzing (see test_pbt_fuzz_envelope.py's docstring for the
overall property and its relationship to the existing PBT-*-MUTATE tests).

Target: `verify_manifest_envelope`, `verify_timestamp_envelope`,
`verify_checkpoint_envelope`, `verify_provenance_envelope`, and (lighter
coverage, see module note below) `root.verify_root_doc` -- the five
document-shape parsers named in the milestone's list ("manifest, root,
timestamp, snapshot, envelope... inputs"; snapshot has its own dedicated
file since `verify_snapshot`'s call shape and guarantee are different).

Each is fed a DSSE envelope wrapping ARBITRARY bytes, signed by a REAL
test keypair the caller also lists as authorized -- so the signature
itself always verifies, forcing every input all the way into the
payload-parsing code beneath `dsse.verify`, which is the actual target
(dsse.py's own robustness is test_pbt_fuzz_envelope.py's job). Half the
generated corpus is `json.dumps` of a Hypothesis-generated JSON-like
value (valid JSON, arbitrary/wrong shape); half is raw arbitrary bytes
(not even valid JSON). This directly exercises the `isinstance(parsed,
dict)` guard fix (D... see DECISIONS.md M4 section) added to all four of
these modules ahead of writing this file.

`root.verify_root_genesis`/`verify_root_link` need a payload whose OWN
`keys.root` list already names the pinned fingerprint before signature
verification is even reached (T4A's trust-bootstrap design), so
structurally-arbitrary payloads mostly short-circuit at PinMismatchError
before ever reaching deeper parsing -- fuzzing them meaningfully would
need a generator aware of that shape, out of proportion for what M4
needs here since `root.py::_decode_envelope_payload` is the ALREADY-
correct reference implementation the other four modules were missing
(see the M4 D-decision) and needs no fix. `verify_root_doc` (the
simpler, already-established, local-cache re-check entry point) gets a
direct pass instead, for coverage parity with the others.
"""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, strategies as st

from vouch import dsse
from vouch.errors import (
    KeyRevokedError,
    PinMismatchError,
    ProvenanceInvalidError,
    RollbackError,
    SignatureError,
    StaleError,
)
from vouch.hashing import b3_hex
from vouch.keys import key_id, public_bytes
from vouch.log import verify_checkpoint_envelope
from vouch.manifest import verify_manifest_envelope
from vouch.provenance import verify_provenance_envelope
from vouch.root import verify_root_doc
from vouch.timestamp import verify_timestamp_envelope

_json_scalar = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=20))
_json_value = st.recursive(
    _json_scalar,
    lambda children: st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=10), children, max_size=3),
    max_leaves=6,
)

_payload_bytes_strategy = st.one_of(
    _json_value.map(lambda v: json.dumps(v).encode("utf-8")),
    st.binary(max_size=200),
)


def _keypair():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return sk, key_id(pub), pub


@given(payload_bytes=_payload_bytes_strategy)
def test_verify_manifest_envelope_never_crashes(payload_bytes):
    sk, kid, pub = _keypair()
    envelope = dsse.sign(payload_bytes, sk, kid)
    try:
        verify_manifest_envelope(
            envelope,
            authorized_keys={kid: pub},
            expected_digest=b3_hex(payload_bytes),
            publisher="acme-lab",
            name="bert-tiny",
            version="1.0.0",
        )
    except (SignatureError, KeyRevokedError, RollbackError):
        pass


@given(payload_bytes=_payload_bytes_strategy)
def test_verify_timestamp_envelope_never_crashes(payload_bytes):
    sk, kid, pub = _keypair()
    envelope = dsse.sign(payload_bytes, sk, kid)
    try:
        verify_timestamp_envelope(envelope, authorized_keys={kid: pub}, publisher="acme-lab")
    except (SignatureError, KeyRevokedError, StaleError):
        pass


@given(payload_bytes=_payload_bytes_strategy)
def test_verify_checkpoint_envelope_never_crashes(payload_bytes):
    sk, kid, pub = _keypair()
    envelope = dsse.sign(payload_bytes, sk, kid)
    try:
        verify_checkpoint_envelope(envelope, authorized_keys={kid: pub}, publisher="acme-lab")
    except (SignatureError, KeyRevokedError):
        pass


@given(payload_bytes=_payload_bytes_strategy)
def test_verify_provenance_envelope_never_crashes(payload_bytes):
    sk, kid, pub = _keypair()
    envelope = dsse.sign(payload_bytes, sk, kid)
    try:
        verify_provenance_envelope(
            envelope,
            authorized_keys={kid: pub},
            expected_digest=b3_hex(payload_bytes),
            subject_manifest_digest="b3:" + "0" * 64,
        )
    except (SignatureError, KeyRevokedError, ProvenanceInvalidError):
        pass


@given(payload_bytes=_payload_bytes_strategy)
def test_verify_root_doc_never_crashes(payload_bytes):
    sk, kid, pub = _keypair()
    envelope = dsse.sign(payload_bytes, sk, kid)
    try:
        verify_root_doc(envelope, pinned_fingerprint=kid)
    except (SignatureError, KeyRevokedError, PinMismatchError, RollbackError):
        pass
