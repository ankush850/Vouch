"""M4 parser fuzzing, per 03_SECURITY_AND_ACCESS.md section 9: "M4 adds
parser fuzzing (manifest, root, timestamp, snapshot, envelope, proof
inputs are attacker-controlled bytes and are treated as such)."

Target: dsse.py's `verify`/`verify_threshold`, the DSSE envelope parser
every other document type's `verify_*_envelope` sits on top of. Unlike
the existing PBT-MANIFEST-MUTATE-style tests (which mutate ONE byte of an
otherwise-valid, real signed envelope), this generates structurally
arbitrary envelope shapes -- wrong field types, missing fields, garbage
nested inside `signatures` -- since there's no single "valid structure"
to mutate from when the property under test is "never crash on malformed
input," not "a specific known-good document gets rejected."

The property: for ANY input, `verify`/`verify_threshold` either returns
verified payload bytes or raises a `VouchError` subclass (SignatureError
or KeyRevokedError) -- never an unhandled exception (AttributeError,
TypeError, KeyError, etc.).
"""

from __future__ import annotations

from hypothesis import given, strategies as st
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import dsse
from vouch.errors import KeyRevokedError, SignatureError
from vouch.keys import key_id, public_bytes

_json_scalar = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=20))
_json_value = st.recursive(
    _json_scalar,
    lambda children: st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=10), children, max_size=3),
    max_leaves=6,
)

_signature_entry = st.dictionaries(
    st.sampled_from(["keyid", "sig", "other"]),
    st.one_of(st.text(max_size=30), _json_value),
    max_size=3,
)

_envelope_strategy = st.fixed_dictionaries(
    {},
    optional={
        "payloadType": st.one_of(st.text(max_size=30), _json_value),
        "payload": st.one_of(st.text(max_size=200), _json_value),
        "signatures": st.one_of(_json_value, st.lists(_signature_entry, max_size=4)),
    },
)


def _authorized_keys():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return {key_id(pub): pub}


@given(envelope=_envelope_strategy)
def test_verify_never_crashes_on_structurally_arbitrary_envelope(envelope):
    try:
        dsse.verify(envelope, _authorized_keys())
    except (SignatureError, KeyRevokedError):
        pass


@given(envelope=st.one_of(_json_value, st.none(), st.text(), st.integers(), st.lists(_json_value, max_size=3)))
def test_verify_never_crashes_on_non_dict_top_level(envelope):
    try:
        dsse.verify(envelope, _authorized_keys())
    except (SignatureError, KeyRevokedError):
        pass


@given(threshold=st.integers(min_value=-5, max_value=10), envelope=_envelope_strategy)
def test_verify_threshold_never_crashes_on_arbitrary_threshold_and_envelope(threshold, envelope):
    try:
        dsse.verify_threshold(envelope, _authorized_keys(), threshold)
    except (SignatureError, KeyRevokedError):
        pass


@given(
    keyid_matches=st.booleans(),
    sig=st.one_of(st.text(max_size=50), st.binary(max_size=50), st.none(), st.integers()),
)
def test_verify_never_crashes_on_garbage_signature_bytes_for_a_real_keyid(keyid_matches, sig):
    authorized = _authorized_keys()
    real_kid = next(iter(authorized))
    keyid = real_kid if keyid_matches else "b3:" + "0" * 64
    envelope = {
        "payloadType": "application/vnd.vouch.v1+json",
        "payload": "e30=",  # base64 of "{}"
        "signatures": [{"keyid": keyid, "sig": sig}],
    }
    try:
        dsse.verify(envelope, authorized)
    except (SignatureError, KeyRevokedError):
        pass
