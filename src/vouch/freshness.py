"""V4, V5, and (M3) V7 orchestration, shared by `fetch_flow.py` and
`verify_flow.py`.

`fetch_verified_timestamp` is V4 end to end: fetch the timestamp envelope,
verify its signature/expiry (`timestamp.verify_timestamp_envelope`), then
check it against the consumer's persisted rollback/equivocation state
(`trust_store.check_and_advance_timestamp_seq`). `fetch_verified_snapshot`
is V5: fetch the snapshot's raw bytes by digest and confirm they hash to
it (`snapshot.verify_snapshot`).

`fetch_verified_root_chain` always re-fetches and re-walks the FULL root
chain from genesis (version 1) through whatever version the origin
currently serves, rather than resuming from a cached head -- simpler, and
at the modest root-version counts a real deployment accumulates (each
document is small; rotations are rare events), not a meaningful cost.

V7 (transparency log) is two independent checks, both implemented here:
`fetch_verified_checkpoint` verifies a consistency proof from the
consumer's OWN previously-stored checkpoint to the current one (detects a
single source going backwards or rewriting its own history over time);
`cross_check_checkpoints` compares the primary checkpoint against every
OTHER configured peer's checkpoint IN THE SAME SESSION, sequentially over
`pool.clients_by_score()` (same precedent as M2 Open Decision 6, not
concurrent) -- this is what actually catches a publisher/attacker showing
different victims different "latest" states at the same moment (T5B),
which the single-source-over-time check alone cannot.
`fetch_verified_inclusion` verifies the specific manifest being fetched is
really a leaf in the checkpointed tree.

`cross_check_timestamps` (M4) is V4's multi-source half, the timestamp
analogue of `cross_check_checkpoints`: 02_TECHNICAL_ARCHITECTURE.md
section 6.2 states timestamps are "fetched from at least two independent
sources when two or more are configured... two valid statements with the
same seq but different contents [is] equivocation evidence." Root gets no
such cross-source check: `verify_root_chain`'s TUF-style cross-signing,
anchored at the pinned genesis key, already makes two divergent-but-both-
valid root histories require actual root key compromise -- an event
03_SECURITY_AND_ACCESS.md section 5.6 documents as unrecoverable by any
automatic mechanism, so a same-session cross-source root check would be
new code defending against a scenario the threat model already says code
cannot fix.
"""

from __future__ import annotations

from pathlib import Path

from . import log as log_mod
from . import trust_store
from .errors import LogFailureError, NetworkError, StaleError, VouchError
from .httpclient import OriginClient
from .peers import PeerPool
from .root import verify_root_chain
from .snapshot import verify_snapshot
from .timestamp import verify_timestamp_envelope


async def fetch_verified_timestamp(
    home: Path,
    client: OriginClient,
    publisher_name: str,
    fingerprint: str,
    authorized_timestamp_keys: dict[str, bytes],
    revoked_keys: frozenset[str] = frozenset(),
) -> dict:
    """Implements V4. Returns the verified timestamp statement."""
    envelope = await client.get_timestamp(fingerprint)
    if envelope is None:
        raise StaleError(f"no timestamp obtainable for {fingerprint}", peer=client.base_url)

    statement = verify_timestamp_envelope(
        envelope, authorized_keys=authorized_timestamp_keys, publisher=fingerprint, revoked_keys=revoked_keys
    )
    trust_store.check_and_advance_timestamp_seq(home, publisher_name, statement["seq"], envelope)
    return statement


async def fetch_verified_snapshot(client: OriginClient, fingerprint: str, snapshot_digest: str) -> dict:
    """Implements V5. Returns the verified snapshot document."""
    data = await client.get_snapshot(fingerprint, snapshot_digest)
    if data is None:
        raise NetworkError(f"snapshot {snapshot_digest} not found at origin", peer=client.base_url)
    return verify_snapshot(data, expected_digest=snapshot_digest)


async def fetch_verified_root_chain(
    home: Path, client: OriginClient, publisher_name: str, fingerprint: str
) -> tuple[dict, dict, frozenset[str]]:
    """Implements the M3 chain-walk form of V2. Fetches every root version
    from 1 up to the first 404, verifies the whole chain, checks the result
    against the consumer's persisted rollback high-water mark, and advances
    it. Returns (current root envelope, current root document, accumulated
    revoked-key-id set) -- the envelope is returned alongside the document
    so callers can cache the exact bytes for `verify_flow.py`'s offline
    re-check path, without a second round trip to re-fetch the head.
    """
    envelopes = []
    version = 1
    while True:
        envelope = await client.get_root(fingerprint, version)
        if envelope is None:
            break
        envelopes.append(envelope)
        version += 1

    if not envelopes:
        raise NetworkError(f"no root document obtainable for {fingerprint}", peer=client.base_url)

    hwm = trust_store.get_root_version_hwm(home, publisher_name)
    doc, revoked = verify_root_chain(envelopes, pinned_fingerprint=fingerprint, min_version=hwm)
    trust_store.check_and_advance_root_version(home, publisher_name, doc["root_version"])
    return envelopes[-1], doc, revoked


async def fetch_verified_checkpoint(
    home: Path,
    client: OriginClient,
    publisher_name: str,
    fingerprint: str,
    authorized_keys: dict[str, bytes],
    revoked_keys: frozenset[str] = frozenset(),
) -> dict:
    """V7, single-source-over-time half: fetch+verify the checkpoint
    envelope, then check it against the consumer's own previously-stored
    checkpoint via a consistency proof (skipped the first time -- nothing
    stored yet) and advance the stored state on success.
    """
    envelope = await client.get_checkpoint(fingerprint)
    if envelope is None:
        raise LogFailureError(f"no checkpoint obtainable for {fingerprint}", peer=client.base_url)
    checkpoint = log_mod.verify_checkpoint_envelope(
        envelope, authorized_keys=authorized_keys, publisher=fingerprint, revoked_keys=revoked_keys
    )

    stored = trust_store.get_log_checkpoint_hwm(home, publisher_name)
    if stored is not None:
        if checkpoint["tree_size"] < stored["tree_size"]:
            raise LogFailureError(
                f"checkpoint tree size {checkpoint['tree_size']} is older than the previously seen size "
                f"{stored['tree_size']}",
                peer=client.base_url,
            )
        if checkpoint["tree_size"] == stored["tree_size"]:
            if checkpoint["root_hash"] != stored["root_hash"]:
                raise LogFailureError(
                    "equivocation: checkpoint root hash changed at the same tree size", peer=client.base_url
                )
        else:
            proof_response = await client.get_consistency_proof(
                fingerprint, stored["tree_size"], checkpoint["tree_size"]
            )
            if proof_response is None:
                raise LogFailureError(
                    f"no consistency proof obtainable from {stored['tree_size']} to {checkpoint['tree_size']}",
                    peer=client.base_url,
                )
            log_mod.verify_consistency(
                stored["tree_size"], stored["root_hash"], checkpoint["tree_size"], checkpoint["root_hash"],
                proof_response["proof"],
            )

    trust_store.advance_log_checkpoint(home, publisher_name, checkpoint["tree_size"], checkpoint["root_hash"])
    return checkpoint


async def fetch_verified_inclusion(
    client: OriginClient, fingerprint: str, tree_size: int, leaf_index: int, expected_leaf_hash: str, root_hash: str
) -> None:
    """V7, per-manifest half: verify the specific leaf this fetch cares
    about is really included in the checkpointed tree.
    """
    proof_response = await client.get_inclusion_proof(fingerprint, tree_size, leaf_index)
    if proof_response is None:
        raise LogFailureError(
            f"no inclusion proof obtainable for leaf {leaf_index} at tree size {tree_size}", peer=client.base_url
        )
    log_mod.verify_inclusion(expected_leaf_hash, leaf_index, tree_size, root_hash, proof_response["proof"])


async def cross_check_checkpoints(
    pool: PeerPool,
    fingerprint: str,
    primary_checkpoint: dict,
    *,
    authorized_keys: dict[str, bytes],
    revoked_keys: frozenset[str] = frozenset(),
) -> None:
    """V7, multi-source half (T5B): compare the primary checkpoint against
    every OTHER configured peer's checkpoint, sequentially. Same tree_size
    with a different root_hash is equivocation across sources (caught here,
    not by `fetch_verified_checkpoint`, since that only compares a single
    source against itself over time). A peer reporting a LARGER tree_size
    is verified via a consistency proof from the primary's size to theirs;
    a smaller or equal (and matching) tree_size needs no further action --
    being behind is an availability fact, not evidence of a split view. A
    peer that fails to answer or whose checkpoint doesn't verify is simply
    skipped (deprioritizing/blacklisting that peer is `fetch_flow.py`'s
    job via the normal V2/V4/V5/V6 checks against it, not this function's).
    """
    primary_size = primary_checkpoint["tree_size"]
    primary_root = primary_checkpoint["root_hash"]

    for client in pool.clients_by_score():
        try:
            other_envelope = await client.get_checkpoint(fingerprint)
            if other_envelope is None:
                continue
            other_checkpoint = log_mod.verify_checkpoint_envelope(
                other_envelope, authorized_keys=authorized_keys, publisher=fingerprint, revoked_keys=revoked_keys
            )
        except VouchError:
            continue

        other_size = other_checkpoint["tree_size"]
        other_root = other_checkpoint["root_hash"]

        if other_size == primary_size:
            if other_root != primary_root:
                raise LogFailureError(
                    f"equivocation: two sources report different root hashes at tree size {primary_size}",
                    peer=client.base_url,
                )
            continue

        if other_size > primary_size:
            proof_response = await client.get_consistency_proof(fingerprint, primary_size, other_size)
            if proof_response is None:
                continue
            log_mod.verify_consistency(
                primary_size, primary_root, other_size, other_root, proof_response["proof"]
            )
        # other_size < primary_size: that peer is just behind; nothing to check.


async def cross_check_timestamps(
    pool: PeerPool,
    fingerprint: str,
    primary_statement: dict,
    *,
    authorized_keys: dict[str, bytes],
    revoked_keys: frozenset[str] = frozenset(),
) -> None:
    """V4, multi-source half (M4, per 02_TECHNICAL_ARCHITECTURE.md section
    6.2): compare the primary timestamp statement against every OTHER
    configured peer's timestamp, sequentially. Same seq with a DIFFERENT
    statement is equivocation across sources (caught here, not by
    `fetch_verified_timestamp`, since that only compares a single source
    against itself over time via the consumer's persisted hwm). A
    different seq either direction is not flagged -- an older seq is just
    an availability fact (that peer is behind), and a newer seq is simply
    ahead, which `_try_each_peer`'s normal score-ordered fallback already
    handles. A peer that fails to answer or whose statement doesn't verify
    is simply skipped (deprioritizing/blacklisting that peer is
    `fetch_flow.py`'s job via the normal V1-V6 checks against it, not this
    function's).
    """
    primary_seq = primary_statement["seq"]

    for client in pool.clients_by_score():
        try:
            other_envelope = await client.get_timestamp(fingerprint)
            if other_envelope is None:
                continue
            other_statement = verify_timestamp_envelope(
                other_envelope, authorized_keys=authorized_keys, publisher=fingerprint, revoked_keys=revoked_keys
            )
        except VouchError:
            continue

        if other_statement["seq"] == primary_seq and other_statement != primary_statement:
            raise LogFailureError(
                f"equivocation: two sources report different timestamp statements at seq {primary_seq}",
                peer=client.base_url,
            )
