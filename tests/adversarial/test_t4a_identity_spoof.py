"""T4A-IDENTITY-SPOOF, per 03_SECURITY_AND_ACCESS.md section 4:

"Spoofed publisher identity: lookalike key distributes 'acme-lab'
artifacts. Primary mitigation: identity is the root-key fingerprint; the
local pin fails against any other key; no name resolution exists outside
pins."

Three sub-cases: no pin at all, a lookalike key claiming to be the pinned
publisher, and a corrupted self-signature on an otherwise fingerprint-
matching document.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import fetch_flow, originstore, store as store_mod, trust_store
from vouch.keys import key_id, public_bytes
from vouch.peers import PeerPool
from vouch.root import build_root_doc, sign_root_doc

pytestmark = pytest.mark.asyncio


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


async def test_t4a_no_pin_at_all(consumer_home, published_artifact, fake_origin):
    # No `trust add` was ever run for "acme-lab".
    async with PeerPool(consumer_home, [str(fake_origin.make_url(""))]) as pool:
        result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")

    assert result["ok"] is False
    assert result["exit_code"] == 43
    assert result["checks"] == [{"id": "V1", "ok": False, "detail": 'no pin for "acme-lab"'}]


async def test_t4a_lookalike_key_rejected_by_pin_before_signature_check(
    consumer_home, published_artifact, origin_store, fake_origin
):
    # The consumer is pinned to the REAL publisher's fingerprint...
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])

    # ...but an attacker (a compromised origin, or a malicious mirror
    # claiming to be able to answer for that fingerprint) overwrites the
    # served root document at that same route with one for a totally
    # different key -- the "lookalike" from the threat description.
    impostor_sk = Ed25519PrivateKey.generate()
    impostor_pub = public_bytes(impostor_sk.public_key())
    impostor_kid = key_id(impostor_pub)
    impostor_doc = build_root_doc(publisher=impostor_kid, root_keys=[(impostor_kid, impostor_pub)])
    impostor_envelope = sign_root_doc(impostor_doc, impostor_sk, impostor_kid)
    originstore.write_root_doc(origin_store, published_artifact["fingerprint"], 1, impostor_envelope)

    async with PeerPool(consumer_home, [str(fake_origin.make_url(""))]) as pool:
        result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")

    assert result["ok"] is False
    assert result["exit_code"] == 43
    fail_check = next(c for c in result["checks"] if not c["ok"])
    assert fail_check["id"] == "V2"

    # Nothing was ever fetched or materialized for a pin that was never
    # validated -- the attack is caught before any chunk fetch is attempted.
    assert not (consumer_home / "verified").exists() or not list((consumer_home / "verified").iterdir())


async def test_t4a_corrupted_self_signature_rejected(consumer_home, published_artifact, origin_store, fake_origin):
    trust_store.add_pin(consumer_home, "acme-lab", published_artifact["fingerprint"])

    envelope = originstore.read_root_doc(origin_store, published_artifact["fingerprint"], 1)
    import base64

    bad_sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    bad_sig[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(bad_sig)).decode()
    originstore.write_root_doc(origin_store, published_artifact["fingerprint"], 1, envelope)

    async with PeerPool(consumer_home, [str(fake_origin.make_url(""))]) as pool:
        result = await fetch_flow.fetch(consumer_home, pool, "acme-lab/bert-tiny@1.2.0")

    assert result["ok"] is False
    assert result["exit_code"] == 41
    fail_check = next(c for c in result["checks"] if not c["ok"])
    assert fail_check["id"] == "V2"
