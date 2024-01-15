import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import log as log_mod
from vouch import originstore, store as store_mod
from vouch.dsse import add_signature
from vouch.errors import LogFailureError, NetworkError, RollbackError, StaleError
from vouch.freshness import (
    cross_check_checkpoints,
    cross_check_timestamps,
    fetch_verified_checkpoint,
    fetch_verified_inclusion,
    fetch_verified_root_chain,
    fetch_verified_snapshot,
    fetch_verified_timestamp,
)
from vouch.httpclient import OriginClient
from vouch.httpserver import build_app
from vouch.keys import key_id, public_bytes
from vouch.peers import PeerPool
from vouch.root import build_root_doc, sign_root_doc
from vouch.snapshot import build_and_digest_snapshot
from vouch.timestamp import build_timestamp_statement, sign_timestamp

pytestmark = pytest.mark.asyncio


@pytest.fixture
def origin_store(tmp_path):
    store_mod.ensure_layout(tmp_path)
    return tmp_path


@pytest.fixture
def consumer_home(tmp_path):
    home = tmp_path / "consumer"
    store_mod.ensure_layout(home)
    return home


def _publish_timestamp(origin_store, fingerprint, ts_sk, ts_kid, *, seq):
    _doc, canonical, digest = build_and_digest_snapshot(publisher=fingerprint, artifacts={})
    originstore.write_snapshot(origin_store, fingerprint, digest, canonical)
    stmt = build_timestamp_statement(publisher=fingerprint, seq=seq, snapshot_digest=digest)
    envelope = sign_timestamp(stmt, ts_sk, ts_kid)
    originstore.write_timestamp(origin_store, fingerprint, envelope)
    return digest


@pytest.fixture
def timestamp_key():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return sk, pub, key_id(pub)


@pytest.fixture
async def server(origin_store):
    s = TestServer(build_app(origin_store))
    await s.start_server()
    try:
        yield s
    finally:
        await s.close()


FP = "b3:" + "9" * 64


async def test_fetch_verified_timestamp_success(consumer_home, origin_store, server, timestamp_key):
    ts_sk, ts_pub, ts_kid = timestamp_key
    _publish_timestamp(origin_store, FP, ts_sk, ts_kid, seq=1)

    async with OriginClient(str(server.make_url(""))) as client:
        statement = await fetch_verified_timestamp(consumer_home, client, "acme-lab", FP, {ts_kid: ts_pub})
    assert statement["seq"] == 1
    assert statement["publisher"] == FP


async def test_fetch_verified_timestamp_missing_is_stale(consumer_home, origin_store, server, timestamp_key):
    ts_sk, ts_pub, ts_kid = timestamp_key
    async with OriginClient(str(server.make_url(""))) as client:
        with pytest.raises(StaleError):
            await fetch_verified_timestamp(consumer_home, client, "acme-lab", FP, {ts_kid: ts_pub})


async def test_fetch_verified_timestamp_rollback_rejected(consumer_home, origin_store, server, timestamp_key):
    ts_sk, ts_pub, ts_kid = timestamp_key
    _publish_timestamp(origin_store, FP, ts_sk, ts_kid, seq=3)

    async with OriginClient(str(server.make_url(""))) as client:
        await fetch_verified_timestamp(consumer_home, client, "acme-lab", FP, {ts_kid: ts_pub})

    # Origin regresses to an older, individually-valid statement (T2b).
    _publish_timestamp(origin_store, FP, ts_sk, ts_kid, seq=1)

    async with OriginClient(str(server.make_url(""))) as client:
        with pytest.raises(RollbackError):
            await fetch_verified_timestamp(consumer_home, client, "acme-lab", FP, {ts_kid: ts_pub})


async def test_fetch_verified_snapshot_success(server, origin_store):
    doc, canonical, digest = build_and_digest_snapshot(publisher=FP, artifacts={"bert-tiny": {"current_version": "1.0.0", "versions": {}}})
    originstore.write_snapshot(origin_store, FP, digest, canonical)

    async with OriginClient(str(server.make_url(""))) as client:
        verified = await fetch_verified_snapshot(client, FP, digest)
    assert verified == doc


async def test_fetch_verified_snapshot_missing_is_network_error(server, origin_store):
    async with OriginClient(str(server.make_url(""))) as client:
        with pytest.raises(NetworkError):
            await fetch_verified_snapshot(client, FP, "b3:" + "0" * 64)


# --- fetch_verified_root_chain ---------------------------------------------


def _publish_genesis_root(origin_store):
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    kid = key_id(pub)
    doc = build_root_doc(publisher=kid, root_keys=[(kid, pub)])
    envelope = sign_root_doc(doc, sk, kid)
    originstore.write_root_doc(origin_store, kid, 1, envelope)
    return doc, sk, kid


async def test_fetch_verified_root_chain_single_version(consumer_home, origin_store, server):
    doc, sk, kid = _publish_genesis_root(origin_store)
    async with OriginClient(str(server.make_url(""))) as client:
        result_envelope, result_doc, revoked = await fetch_verified_root_chain(consumer_home, client, "acme-lab", kid)
    assert result_doc == doc
    assert result_envelope is not None
    assert revoked == frozenset()


async def test_fetch_verified_root_chain_walks_a_rotation(consumer_home, origin_store, server):
    doc1, sk1, kid1 = _publish_genesis_root(origin_store)

    sk2 = Ed25519PrivateKey.generate()
    pub2 = public_bytes(sk2.public_key())
    kid2 = key_id(pub2)
    doc2 = build_root_doc(publisher=kid1, root_keys=[(kid2, pub2)], root_version=2)
    envelope2 = sign_root_doc(doc2, sk2, kid2)
    envelope2 = add_signature(envelope2, sk1, kid1)
    originstore.write_root_doc(origin_store, kid1, 2, envelope2)

    async with OriginClient(str(server.make_url(""))) as client:
        result_envelope, result_doc, revoked = await fetch_verified_root_chain(consumer_home, client, "acme-lab", kid1)
    assert result_doc == doc2
    assert result_envelope == envelope2


async def test_fetch_verified_root_chain_missing_is_network_error(consumer_home, origin_store, server):
    async with OriginClient(str(server.make_url(""))) as client:
        with pytest.raises(NetworkError):
            await fetch_verified_root_chain(consumer_home, client, "acme-lab", "b3:" + "0" * 64)


# --- fetch_verified_checkpoint / fetch_verified_inclusion / cross_check ----


def _release_key():
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk.public_key())
    return sk, key_id(pub)


async def test_fetch_verified_checkpoint_first_time_has_nothing_to_compare(consumer_home, origin_store, server):
    sk, kid = _release_key()
    originstore.append_log_leaf(origin_store, FP, event="publish", digest="b3:" + "a" * 64, release_private_key=sk, release_key_id=kid)

    async with OriginClient(str(server.make_url(""))) as client:
        checkpoint = await fetch_verified_checkpoint(consumer_home, client, "acme-lab", FP, {kid: public_bytes(sk.public_key())})
    assert checkpoint["tree_size"] == 1


async def test_fetch_verified_checkpoint_consistency_across_sessions(consumer_home, origin_store, server):
    sk, kid = _release_key()
    authorized = {kid: public_bytes(sk.public_key())}
    originstore.append_log_leaf(origin_store, FP, event="publish", digest="b3:" + "a" * 64, release_private_key=sk, release_key_id=kid)

    async with OriginClient(str(server.make_url(""))) as client:
        await fetch_verified_checkpoint(consumer_home, client, "acme-lab", FP, authorized)

    originstore.append_log_leaf(origin_store, FP, event="publish", digest="b3:" + "b" * 64, release_private_key=sk, release_key_id=kid)

    async with OriginClient(str(server.make_url(""))) as client:
        checkpoint2 = await fetch_verified_checkpoint(consumer_home, client, "acme-lab", FP, authorized)
    assert checkpoint2["tree_size"] == 2


async def test_fetch_verified_inclusion_success(origin_store, server):
    sk, kid = _release_key()
    originstore.append_log_leaf(origin_store, FP, event="publish", digest="b3:" + "a" * 64, release_private_key=sk, release_key_id=kid)
    originstore.append_log_leaf(origin_store, FP, event="publish", digest="b3:" + "b" * 64, release_private_key=sk, release_key_id=kid)

    leaves = originstore.read_log_leaves(origin_store, FP)
    hashes = [log_mod.leaf_hash(leaf) for leaf in leaves]
    root_hash = log_mod.merkle_root(hashes)

    async with OriginClient(str(server.make_url(""))) as client:
        await fetch_verified_inclusion(client, FP, 2, 0, hashes[0], root_hash)  # must not raise


async def test_fetch_verified_inclusion_missing_proof_is_log_failure(origin_store, server):
    sk, kid = _release_key()
    originstore.append_log_leaf(origin_store, FP, event="publish", digest="b3:" + "a" * 64, release_private_key=sk, release_key_id=kid)
    async with OriginClient(str(server.make_url(""))) as client:
        with pytest.raises(LogFailureError):
            await fetch_verified_inclusion(client, FP, 99, 50, "b3:" + "0" * 64, "b3:" + "0" * 64)


async def test_cross_check_checkpoints_detects_equivocation():
    # Two independent in-process origins, seeded with DIFFERENT trees at
    # the SAME tree size for the same publisher -- exactly T5B.
    import tempfile
    from pathlib import Path as P

    sk, kid = _release_key()
    authorized = {kid: public_bytes(sk.public_key())}

    with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
        store_a, store_b = P(tmp_a), P(tmp_b)
        store_mod.ensure_layout(store_a)
        store_mod.ensure_layout(store_b)

        originstore.append_log_leaf(store_a, FP, event="publish", digest="b3:" + "a" * 64, release_private_key=sk, release_key_id=kid)
        originstore.append_log_leaf(store_b, FP, event="publish", digest="b3:" + "f" * 64, release_private_key=sk, release_key_id=kid)

        server_a = TestServer(build_app(store_a))
        server_b = TestServer(build_app(store_b))
        await server_a.start_server()
        await server_b.start_server()
        try:
            home = P(tmp_a) / "consumer-home"
            store_mod.ensure_layout(home)
            async with PeerPool(home, [str(server_a.make_url("")), str(server_b.make_url(""))]) as pool:
                primary_client = pool.clients_by_score()[0]
                primary_envelope = await primary_client.get_checkpoint(FP)
                primary_checkpoint = log_mod.verify_checkpoint_envelope(
                    primary_envelope, authorized_keys=authorized, publisher=FP
                )
                with pytest.raises(LogFailureError):
                    await cross_check_checkpoints(pool, FP, primary_checkpoint, authorized_keys=authorized)
        finally:
            await server_a.close()
            await server_b.close()


async def test_cross_check_checkpoints_accepts_consistent_larger_tree():
    import tempfile
    from pathlib import Path as P

    sk, kid = _release_key()
    authorized = {kid: public_bytes(sk.public_key())}

    with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
        store_a, store_b = P(tmp_a), P(tmp_b)
        store_mod.ensure_layout(store_a)
        store_mod.ensure_layout(store_b)

        # store_b has everything store_a has, plus one more (honest growth).
        originstore.append_log_leaf(store_a, FP, event="publish", digest="b3:" + "a" * 64, release_private_key=sk, release_key_id=kid)
        originstore.append_log_leaf(store_b, FP, event="publish", digest="b3:" + "a" * 64, release_private_key=sk, release_key_id=kid)
        originstore.append_log_leaf(store_b, FP, event="publish", digest="b3:" + "b" * 64, release_private_key=sk, release_key_id=kid)

        server_a = TestServer(build_app(store_a))
        server_b = TestServer(build_app(store_b))
        await server_a.start_server()
        await server_b.start_server()
        try:
            home = P(tmp_a) / "consumer-home"
            store_mod.ensure_layout(home)
            async with PeerPool(home, [str(server_a.make_url("")), str(server_b.make_url(""))]) as pool:
                client_a = pool.client_for(str(server_a.make_url("")))
                primary_envelope = await client_a.get_checkpoint(FP)
                primary_checkpoint = log_mod.verify_checkpoint_envelope(
                    primary_envelope, authorized_keys=authorized, publisher=FP
                )
                await cross_check_checkpoints(pool, FP, primary_checkpoint, authorized_keys=authorized)  # must not raise
        finally:
            await server_a.close()
            await server_b.close()


async def test_cross_check_timestamps_detects_equivocation():
    # Two independent in-process origins, both signing a DIFFERENT
    # statement at the SAME seq for the same publisher -- the timestamp
    # analogue of T5B, per 02_TECHNICAL_ARCHITECTURE.md section 6.2.
    import tempfile
    from pathlib import Path as P

    from vouch.timestamp import verify_timestamp_envelope

    sk, kid = _release_key()
    authorized = {kid: public_bytes(sk.public_key())}

    with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
        store_a, store_b = P(tmp_a), P(tmp_b)
        store_mod.ensure_layout(store_a)
        store_mod.ensure_layout(store_b)

        _publish_timestamp(store_a, FP, sk, kid, seq=1)
        # store_b's snapshot has a different (empty vs. non-empty is not
        # distinguishable here, so vary via a differently-keyed artifact
        # dict) content at the SAME seq -- two honestly-impossible, only
        # equivocation-possible, statements.
        _doc, canonical, digest = build_and_digest_snapshot(publisher=FP, artifacts={"x": {}})
        originstore.write_snapshot(store_b, FP, digest, canonical)
        stmt_b = build_timestamp_statement(publisher=FP, seq=1, snapshot_digest=digest)
        originstore.write_timestamp(store_b, FP, sign_timestamp(stmt_b, sk, kid))

        server_a = TestServer(build_app(store_a))
        server_b = TestServer(build_app(store_b))
        await server_a.start_server()
        await server_b.start_server()
        try:
            home = P(tmp_a) / "consumer-home"
            store_mod.ensure_layout(home)
            async with PeerPool(home, [str(server_a.make_url("")), str(server_b.make_url(""))]) as pool:
                primary_client = pool.clients_by_score()[0]
                primary_envelope = await primary_client.get_timestamp(FP)
                primary_statement = verify_timestamp_envelope(primary_envelope, authorized_keys=authorized, publisher=FP)
                with pytest.raises(LogFailureError):
                    await cross_check_timestamps(pool, FP, primary_statement, authorized_keys=authorized)
        finally:
            await server_a.close()
            await server_b.close()


async def test_cross_check_timestamps_accepts_a_peer_that_is_simply_ahead():
    import tempfile
    from pathlib import Path as P

    from vouch.timestamp import verify_timestamp_envelope

    sk, kid = _release_key()
    authorized = {kid: public_bytes(sk.public_key())}

    with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
        store_a, store_b = P(tmp_a), P(tmp_b)
        store_mod.ensure_layout(store_a)
        store_mod.ensure_layout(store_b)

        _publish_timestamp(store_a, FP, sk, kid, seq=1)
        _publish_timestamp(store_b, FP, sk, kid, seq=1)
        _publish_timestamp(store_b, FP, sk, kid, seq=2)  # store_b is honestly ahead

        server_a = TestServer(build_app(store_a))
        server_b = TestServer(build_app(store_b))
        await server_a.start_server()
        await server_b.start_server()
        try:
            home = P(tmp_a) / "consumer-home"
            store_mod.ensure_layout(home)
            async with PeerPool(home, [str(server_a.make_url("")), str(server_b.make_url(""))]) as pool:
                client_a = pool.client_for(str(server_a.make_url("")))
                primary_envelope = await client_a.get_timestamp(FP)
                primary_statement = verify_timestamp_envelope(primary_envelope, authorized_keys=authorized, publisher=FP)
                await cross_check_timestamps(pool, FP, primary_statement, authorized_keys=authorized)  # must not raise
        finally:
            await server_a.close()
            await server_b.close()
