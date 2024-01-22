"""The flagship consumer flow: `fetch`, per 02_TECHNICAL_ARCHITECTURE.md
section 7 and 03_SECURITY_AND_ACCESS.md section 6.

Implements the full V1-V10 pipeline: V1 (pin), V2 (root chain walk from
genesis through every rotation, M3, with the rollback high-water mark and
accumulated key revocations), V4 (timestamp, revocation-aware), V5
(snapshot), V6 (manifest, revocation-aware, per-artifact rollback
high-water mark), V7 (M3: transparency log -- checkpoint freshness, this
release's inclusion proof, cross-source equivocation check), V8 (per-chunk
hash-before-write across a `PeerPool` with retry-elsewhere on a bad or
unavailable peer), V9 (assembly), and V10 (M3: provenance attestation,
only when the manifest names one -- provenance is optional per D3).

Metadata resolution (V2/V4/V5/V6/V7) falls back across every configured
peer in score order (`_try_each_peer`): each document is independently
verified regardless of which peer served it, so a bad or unavailable peer
there is just an availability/scoring event, not a reason to fail the
whole fetch while an honest peer is still available (Open Decision 6 in
the M2 plan). Chunk fetching (V8, `_fetch_and_verify_chunks`) is scheduled
with real concurrency across the pool, retrying a mismatched or failed
chunk against a different peer -- a digest mismatch there is the harsher
signal (T1): the offending peer is blacklisted for the rest of the session
and takes a large persistent score penalty, saved immediately. The
materialization gate is unchanged: nothing is renamed into `verified/`
until every file's V9 check has passed.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Awaitable, Callable, TypeVar

from . import cas, freshness, log as log_mod, trust_store
from .chunking import compute_file_digest, iter_chunks
from .errors import (
    DigestMismatchError,
    ExitCode,
    LogFailureError,
    NetworkError,
    ReferenceNotFoundError,
    VouchError,
    UsageError,
)
from .httpclient import OriginClient
from .manifest import content_digest, verify_manifest_envelope
from .peers import PeerPool
from .provenance import verify_provenance_envelope
from .quarantine import quarantine_file
from .result import build_result, check_fail, check_ok
from .root import authorized_keys_for_role
from .store import verified_dir
from .trust_store import cache_manifest, cache_root_envelope, load_pin

REF_RE = re.compile(r"^(?P<publisher>[^/@]+)/(?P<artifact>[^/@]+)@(?P<version>[^/@]+)$")

T = TypeVar("T")


def parse_ref(ref: str) -> tuple[str, str, str]:
    m = REF_RE.match(ref)
    if not m:
        raise UsageError(f"malformed reference {ref!r}, expected NAME/ARTIFACT@VERSION")
    return m["publisher"], m["artifact"], m["version"]


def _reset_staging_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


STATUS_BREADCRUMB_NAME = ".vouch-status.json"


def _signer_key_id(envelope: dict, authorized_keys: dict[str, bytes]) -> str | None:
    """Best-effort: the first signature entry whose keyid is in
    `authorized_keys`. The envelope already verified by this point, so this
    is just picking a representative signer to remember for `status.py`'s
    later reconciliation, not itself a trust decision.
    """
    for entry in envelope.get("signatures", []):
        keyid = entry.get("keyid") if isinstance(entry, dict) else None
        if keyid in authorized_keys:
            return keyid
    return None


def _materialize(staging_root: Path, final_path: Path, *, manifest_digest: str, release_key_id: str | None) -> None:
    breadcrumb_path = staging_root / STATUS_BREADCRUMB_NAME
    breadcrumb_path.write_text(json.dumps({"manifest_digest": manifest_digest, "release_key_id": release_key_id}))

    final_path.parent.mkdir(parents=True, exist_ok=True)
    if final_path.exists():
        shutil.rmtree(final_path)
    os.replace(staging_root, final_path)


async def _try_each_peer(pool: PeerPool, attempt: Callable[[OriginClient], Awaitable[T]]) -> T:
    """Try an async `attempt(client)` across `pool.clients_by_score()` in
    score order, returning the first peer's successful result. Any
    VouchError from a peer (network failure, bad signature, rollback,
    equivocation -- all peer-specific) deprioritizes that peer and moves on
    to the next; the document itself is independently verified inside
    `attempt`, so a dishonest or unlucky peer here can only cost
    availability, never cause an accepted bad result. Raises the last error
    if every peer fails.
    """
    last_error: VouchError | None = None
    for client in pool.clients_by_score():
        try:
            result = await attempt(client)
        except VouchError as e:
            pool.record_transport_error(client.base_url)
            last_error = e
            continue
        pool.record_success(client.base_url)
        return result
    raise last_error or NetworkError("no peers available")


async def _fetch_and_verify_chunks(home: Path, pool: PeerPool, digests: list[str], *, concurrency: int = 8) -> None:
    """V8: fetch and hash-verify every chunk before it touches the CAS
    (`cas.write_verified` is the unchanged choke point), scheduled across
    the peer pool. A digest mismatch blacklists that peer for the session
    and retries the chunk elsewhere; a transport error just deprioritizes.
    Raises the last error only if every retry across every peer is
    exhausted for some chunk.
    """
    unique_digests = [d for d in dict.fromkeys(digests) if not cas.has_object(home, d)]
    if not unique_digests:
        return

    semaphore = asyncio.Semaphore(concurrency)
    max_attempts = max(2 * len(pool.base_urls), 2)

    async def fetch_one(digest: str) -> None:
        last_error: VouchError | None = None
        async with semaphore:
            for _attempt in range(max_attempts):
                try:
                    peer_url = pool.select_peer()
                except NetworkError as e:
                    # Running out of peers to retry against isn't new
                    # information -- keep whatever more specific error (e.g.
                    # a DigestMismatchError, with its evidence/expected/
                    # actual/peer detail) we already have, if any.
                    if last_error is None:
                        last_error = e
                    break
                client = pool.client_for(peer_url)
                try:
                    data = await client.get_chunk(digest)
                    if data is None:
                        raise NetworkError(f"chunk {digest} not found at origin", peer=peer_url)
                    cas.write_verified(home, digest, data, peer=peer_url)
                    pool.record_success(peer_url)
                    return
                except DigestMismatchError as e:
                    pool.record_digest_mismatch(peer_url)
                    last_error = e
                except NetworkError as e:
                    pool.record_transport_error(peer_url)
                    last_error = e
        raise last_error or NetworkError(f"chunk {digest} could not be fetched from any peer")

    results = await asyncio.gather(*(fetch_one(d) for d in unique_digests), return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException):
            raise result


def _assemble_file(home: Path, staging_path: Path, chunk_digests: list[str]) -> None:
    """No network or verification here -- pure reassembly of chunks already
    verified and sitting in the CAS.
    """
    staging_path.parent.mkdir(parents=True, exist_ok=True)
    with open(staging_path, "wb") as out:
        for digest in chunk_digests:
            out.write(cas.open_object(home, digest))


async def fetch(home: Path, pool: PeerPool, ref: str) -> dict:
    """Run the full M2 fetch pipeline across a peer pool. Always returns a
    result/v1 dict (never raises) -- failures are recorded as a failing
    check entry with the appropriate exit code.
    """
    started = time.monotonic()
    checks: list[dict] = []

    try:
        publisher_name, artifact, version = parse_ref(ref)
    except VouchError as e:
        check_fail(checks, "V1", e)
        return build_result("fetch", ref, False, e.exit_code, checks)

    # V1: pin lookup
    try:
        pin = load_pin(home, publisher_name)
    except VouchError as e:
        check_fail(checks, "V1", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    fingerprint = pin["fingerprint"]
    check_ok(checks, "V1", f"{publisher_name} -> {fingerprint}")

    # V2: root chain walk from genesis through the current rotation (M3),
    # rollback-checked against the hwm; accumulates every revoked key id.
    try:
        async def _get_root_chain(client: OriginClient):
            return await freshness.fetch_verified_root_chain(home, client, publisher_name, fingerprint)

        root_envelope, root_doc, revoked_keys = await _try_each_peer(pool, _get_root_chain)
    except VouchError as e:
        check_fail(checks, "V2", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    cache_root_envelope(home, publisher_name, root_envelope)
    check_ok(checks, "V2", f"root v{root_doc['root_version']}, {len(revoked_keys)} revocation(s) apply")

    # V4: timestamp freshness (signature, expiry, rollback, equivocation, revocation)
    try:
        authorized_timestamp = authorized_keys_for_role(root_doc, "timestamp")

        async def _get_timestamp(client: OriginClient):
            return await freshness.fetch_verified_timestamp(
                home, client, publisher_name, fingerprint, authorized_timestamp, revoked_keys=revoked_keys
            )

        timestamp_stmt = await _try_each_peer(pool, _get_timestamp)
        await freshness.cross_check_timestamps(
            pool, fingerprint, timestamp_stmt, authorized_keys=authorized_timestamp, revoked_keys=revoked_keys
        )
    except VouchError as e:
        check_fail(checks, "V4", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    check_ok(checks, "V4", f"timestamp seq {timestamp_stmt['seq']}, expires {timestamp_stmt['expires']}")

    # V5: snapshot (digest-bound to the timestamp)
    try:
        async def _get_snapshot(client: OriginClient):
            return await freshness.fetch_verified_snapshot(client, fingerprint, timestamp_stmt["snapshot"])

        snapshot_doc = await _try_each_peer(pool, _get_snapshot)
    except VouchError as e:
        check_fail(checks, "V5", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    check_ok(checks, "V5", timestamp_stmt["snapshot"])

    # V6: resolve name@version via the verified snapshot, then fetch+verify the manifest
    try:
        artifact_entry = snapshot_doc.get("artifacts", {}).get(artifact)
        version_entry = artifact_entry.get("versions", {}).get(version) if artifact_entry else None
        if version_entry is None:
            raise ReferenceNotFoundError(f"{artifact}@{version} not found in snapshot for {fingerprint}")
        expected_digest = version_entry["manifest_digest"]

        authorized_release = authorized_keys_for_role(root_doc, "release")
        artifact_seq_hwm = trust_store.get_manifest_seq_hwm(home, publisher_name, artifact)

        async def _get_manifest(client: OriginClient):
            envelope = await client.get_manifest(expected_digest)
            if envelope is None:
                raise NetworkError(f"manifest {expected_digest} not found at origin", peer=client.base_url)
            manifest = verify_manifest_envelope(
                envelope,
                authorized_keys=authorized_release,
                expected_digest=expected_digest,
                publisher=fingerprint,
                name=artifact,
                version=version,
                min_seq=artifact_seq_hwm,
                revoked_keys=revoked_keys,
            )
            return envelope, manifest

        manifest_envelope, manifest = await _try_each_peer(pool, _get_manifest)
        trust_store.check_and_advance_manifest_seq(home, publisher_name, artifact, manifest["seq"])
    except VouchError as e:
        check_fail(checks, "V6", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    cache_manifest(home, publisher_name, artifact, version, expected_digest, manifest_envelope)
    check_ok(checks, "V6", f"{expected_digest} sig ok, name/version match")

    # V7: transparency log -- checkpoint freshness/consistency, this release's
    # inclusion proof, and cross-source equivocation (T5B). The log is
    # mandatory (Decision 2): a release with no recorded log index fails
    # closed rather than silently skipping the check.
    try:
        log_index = version_entry.get("log_index")
        if log_index is None:
            raise LogFailureError(
                f"no transparency log index recorded for {artifact}@{version}; the log is mandatory"
            )

        async def _get_checkpoint(client: OriginClient):
            checkpoint = await freshness.fetch_verified_checkpoint(
                home, client, publisher_name, fingerprint, authorized_release, revoked_keys=revoked_keys
            )
            return client, checkpoint

        checkpoint_client, checkpoint = await _try_each_peer(pool, _get_checkpoint)

        expected_leaf_hash = log_mod.leaf_hash(
            log_mod.build_leaf(seq=log_index, event="publish", digest=expected_digest, publisher=fingerprint)
        )
        await freshness.fetch_verified_inclusion(
            checkpoint_client, fingerprint, checkpoint["tree_size"], log_index, expected_leaf_hash,
            checkpoint["root_hash"],
        )
        await freshness.cross_check_checkpoints(
            pool, fingerprint, checkpoint, authorized_keys=authorized_release, revoked_keys=revoked_keys
        )
    except VouchError as e:
        check_fail(checks, "V7", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    check_ok(checks, "V7", f"checkpoint tree_size {checkpoint['tree_size']}, leaf {log_index} included")

    # V8: fetch + verify every chunk across the peer pool before it ever touches the CAS
    staging_root = verified_dir(home) / ".staging" / publisher_name / artifact / version
    all_chunk_digests = [d for f in manifest["files"] for d in f["chunks"]]
    try:
        _reset_staging_dir(staging_root)
        await _fetch_and_verify_chunks(home, pool, all_chunk_digests)
        for file_entry in manifest["files"]:
            _assemble_file(home, staging_root / file_entry["path"], file_entry["chunks"])
    except VouchError as e:
        check_fail(checks, "V8", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    check_ok(checks, "V8", f"{len(all_chunk_digests)} chunks verified across {len(pool.base_urls)} peer(s)")

    # V9: assembly -- re-read what actually landed on disk and confirm every
    # file digest independently of the in-memory bytes checked at V8.
    try:
        for file_entry in manifest["files"]:
            file_path = staging_root / file_entry["path"]
            on_disk_chunk_digests = [c.digest for c in iter_chunks(file_path)]
            recomputed_digest = compute_file_digest(on_disk_chunk_digests)
            if recomputed_digest != file_entry["digest"] or on_disk_chunk_digests != file_entry["chunks"]:
                qdir = quarantine_file(
                    home,
                    code=ExitCode.DIGEST_MISMATCH,
                    path=file_path,
                    expected=file_entry["digest"],
                    actual=recomputed_digest,
                    reason="assembled file digest mismatch",
                )
                raise DigestMismatchError(
                    f"assembled file digest mismatch for {file_entry['path']}",
                    evidence=qdir,
                    expected=file_entry["digest"],
                    actual=recomputed_digest,
                )
    except VouchError as e:
        check_fail(checks, "V9", e)
        return build_result("fetch", ref, False, e.exit_code, checks)
    check_ok(checks, "V9", f"{len(manifest['files'])} files, artifact digest {expected_digest}")

    # V10: provenance attestation, only when this manifest names one (D3:
    # provenance is optional -- an artifact with no lineage to attest to
    # simply has `provenance: null` and this check is skipped entirely).
    if manifest.get("provenance"):
        attestation_digest = manifest["provenance"]
        try:
            subject_digest = content_digest(manifest)

            async def _get_provenance(client: OriginClient):
                envelope = await client.get_manifest(attestation_digest)
                if envelope is None:
                    raise NetworkError(f"provenance {attestation_digest} not found at origin", peer=client.base_url)
                return verify_provenance_envelope(
                    envelope,
                    authorized_keys=authorized_release,
                    expected_digest=attestation_digest,
                    subject_manifest_digest=subject_digest,
                    revoked_keys=revoked_keys,
                )

            await _try_each_peer(pool, _get_provenance)
        except VouchError as e:
            check_fail(checks, "V10", e)
            return build_result("fetch", ref, False, e.exit_code, checks)
        check_ok(checks, "V10", f"provenance {attestation_digest} verified")

    final_path = verified_dir(home) / publisher_name / artifact / version
    release_key_id = _signer_key_id(manifest_envelope, authorized_release)
    _materialize(staging_root, final_path, manifest_digest=expected_digest, release_key_id=release_key_id)

    elapsed = time.monotonic() - started
    total_bytes = sum(f["size"] for f in manifest["files"])
    return build_result(
        "fetch",
        ref,
        True,
        ExitCode.OK,
        checks,
        artifact={"digest": expected_digest, "seq": manifest.get("seq")},
        materialized=str(final_path),
        timing={"wall_s": round(elapsed, 3), "bytes": total_bytes},
    )
