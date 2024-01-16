"""M4 parser fuzzing (see test_pbt_fuzz_envelope.py's docstring for the
overall property).

Target: `snapshot.verify_snapshot`, the one entry point named in the
milestone's list ("...snapshot...") that isn't DSSE-envelope-shaped --
snapshot bytes are the raw wire bytes themselves, digest-bound rather
than signed (Decision D6). Fed arbitrary bytes with `expected_digest`
computed by the test itself (`b3_hex` of the fuzzed bytes), so the digest
gate always passes and the JSON/canonical/type-check code underneath is
what's actually exercised.

Per `snapshot.py`'s own docstring, this entry point has an unusually
strong property to prove: "every failure path here, including malformed
or non-canonical bytes that still happen to match the requested digest,
raises DigestMismatchError(40)" -- so unlike the envelope-shaped
document parsers (which can raise one of several VouchError
subclasses), NOTHING but DigestMismatchError should ever escape here.
"""

from __future__ import annotations

from hypothesis import given, strategies as st

from vouch.errors import DigestMismatchError
from vouch.hashing import b3_hex
from vouch.snapshot import verify_snapshot


@given(data=st.binary(max_size=500))
def test_verify_snapshot_never_raises_anything_but_digest_mismatch(data):
    digest = b3_hex(data)
    try:
        verify_snapshot(data, expected_digest=digest)
    except DigestMismatchError:
        pass


@given(data=st.binary(max_size=500), wrong_digest=st.text(max_size=80))
def test_verify_snapshot_never_crashes_on_a_mismatched_digest_either(data, wrong_digest):
    try:
        verify_snapshot(data, expected_digest=wrong_digest)
    except DigestMismatchError:
        pass
