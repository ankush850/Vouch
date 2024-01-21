"""Transparency log primitives, per 02_TECHNICAL_ARCHITECTURE.md section 4.3
and 03_SECURITY_AND_ACCESS.md section 6 (V7).

RFC 6962-style append-only Merkle tree: every publish, rotation, and
revocation appends a leaf; the publisher signs checkpoints (tree size +
root hash) with the release key (no new role -- D5's three roles stay
fixed). This module is pure Merkle math and DSSE checkpoint shape, with NO
I/O -- `originstore.py` owns persistence, `freshness.py` owns the
network-fetch-then-verify orchestration.

Two proof types:
- Inclusion proof: "this leaf is really in the tree at this size" --
  implemented as the standard RFC 6962 O(log n) audit path.
- Consistency proof: "this newer tree is a genuine append-only extension
  of a tree I've already checkpointed" -- implemented here as the full
  ordered list of leaf hashes up to the new size (O(n), not RFC 6962's
  O(log n) SUBPROOF construction). This is a deliberate simplification:
  it gives the identical security property (any inconsistency between an
  old and a claimed-newer checkpoint is detected) with much simpler, more
  obviously-correct code, and at the modest per-publisher leaf counts
  this system handles the size difference isn't practically significant.
  D7 commits to "client-side proofs" and equivocation detection, not
  byte-for-byte RFC 6962 conformance.

Domain-separated hashing (leaf vs. internal node) follows RFC 6962 exactly
(0x00 / 0x01 prefixes) even though the consistency-proof simplification
above doesn't, since domain separation is what prevents a leaf being
mistaken for an internal node hash (a second-preimage class of attack on
naive Merkle trees) and costs nothing to keep.
"""

from __future__ import annotations

import json

from . import dsse
from .canonical import canonicalize, is_canonical
from .errors import LogFailureError, SignatureError
from .hashing import b3_hex, is_valid_digest, parse_b3

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_TREE_HASH = b3_hex(b"")

LEAF_TYPE = "log-leaf/v1"
CHECKPOINT_TYPE = "checkpoint/v1"
LEAF_EVENTS = ("publish", "rotate", "revoke")


def build_leaf(*, seq: int, event: str, digest: str, publisher: str) -> dict:
    if event not in LEAF_EVENTS:
        raise ValueError(f"unknown log event type: {event!r}")
    return {"vouch": LEAF_TYPE, "seq": seq, "event": event, "digest": digest, "publisher": publisher}


def leaf_hash(leaf: dict) -> str:
    """RFC 6962 leaf hash: H(0x00 || canonical(leaf))."""
    return b3_hex(LEAF_PREFIX + canonicalize(leaf))


def _node_hash(left: str, right: str) -> str:
    return b3_hex(NODE_PREFIX + parse_b3(left) + parse_b3(right))


def _largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(hashes: list[str]) -> str:
    """RFC 6962 MTH: the root hash of a tree whose leaves already carry
    `leaf_hash` values (or, recursively, subtree roots).
    """
    n = len(hashes)
    if n == 0:
        return EMPTY_TREE_HASH
    if n == 1:
        return hashes[0]
    k = _largest_power_of_two_less_than(n)
    return _node_hash(merkle_root(hashes[:k]), merkle_root(hashes[k:]))


def inclusion_proof(hashes: list[str], leaf_index: int) -> list[str]:
    """RFC 6962 audit path for `hashes[leaf_index]` in `merkle_root(hashes)`.
    Ordered from the deepest sibling (closest to the leaf) to the topmost.
    """
    n = len(hashes)
    if not (0 <= leaf_index < n):
        raise LogFailureError(f"leaf index {leaf_index} out of range for a tree of size {n}")
    return _path(leaf_index, hashes)


def _path(m: int, hashes: list[str]) -> list[str]:
    n = len(hashes)
    if n <= 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if m < k:
        return _path(m, hashes[:k]) + [merkle_root(hashes[k:])]
    return _path(m - k, hashes[k:]) + [merkle_root(hashes[:k])]


def verify_inclusion(leaf_hash_value: str, leaf_index: int, tree_size: int, root_hash: str, proof: list[str]) -> None:
    """Recompute the root from `leaf_hash_value` + `proof` and confirm it
    equals `root_hash`. Raises LogFailureError on any mismatch or malformed
    proof.
    """
    if not (0 <= leaf_index < tree_size):
        raise LogFailureError(f"leaf index {leaf_index} out of range for a tree of size {tree_size}")
    _validate_proof_elements(proof)
    computed = _root_from_inclusion_proof(leaf_index, tree_size, leaf_hash_value, proof)
    if computed != root_hash:
        raise LogFailureError("inclusion proof does not reproduce the expected root hash")


def _validate_proof_elements(proof: list[str]) -> None:
    """Both proof types are ultimately lists of digest strings that get
    hex-decoded (`parse_b3`, which raises a bare `ValueError`, not a
    `VouchError`) -- a malformed element from an untrusted peer must
    fail closed with `LogFailureError` here, before any decoding is
    attempted, rather than crash the caller with an unhandled exception.
    """
    if not isinstance(proof, list):
        raise LogFailureError("proof is not a list")
    for element in proof:
        if not isinstance(element, str) or not is_valid_digest(element):
            raise LogFailureError("proof contains a malformed digest")


def _root_from_inclusion_proof(m: int, n: int, leaf: str, proof: list[str]) -> str:
    if n <= 1:
        if proof:
            raise LogFailureError("inclusion proof has extra elements for a single-leaf (sub)tree")
        return leaf
    if not proof:
        raise LogFailureError("inclusion proof is too short")
    k = _largest_power_of_two_less_than(n)
    if m < k:
        subtree_root = _root_from_inclusion_proof(m, k, leaf, proof[:-1])
        return _node_hash(subtree_root, proof[-1])
    subtree_root = _root_from_inclusion_proof(m - k, n - k, leaf, proof[:-1])
    return _node_hash(proof[-1], subtree_root)


def consistency_proof(hashes: list[str], old_size: int, new_size: int) -> list[str]:
    """See module docstring: the simplified (O(n)) consistency proof is the
    full ordered slice of leaf hashes up to `new_size`.
    """
    if not (0 <= old_size <= new_size <= len(hashes)):
        raise LogFailureError(
            f"invalid consistency proof range old={old_size} new={new_size} for {len(hashes)} leaves"
        )
    return list(hashes[:new_size])


def verify_consistency(old_size: int, old_root: str, new_size: int, new_root: str, proof: list[str]) -> None:
    if old_size > new_size:
        raise LogFailureError(f"old tree size {old_size} is larger than new tree size {new_size}")
    _validate_proof_elements(proof)
    if len(proof) != new_size:
        raise LogFailureError(f"consistency proof has {len(proof)} leaf hashes, expected {new_size}")
    if merkle_root(proof[:old_size]) != old_root:
        raise LogFailureError("consistency proof does not reproduce the old checkpoint's root hash")
    if merkle_root(proof) != new_root:
        raise LogFailureError("consistency proof does not reproduce the new checkpoint's root hash")


def build_checkpoint(*, publisher: str, tree_size: int, root_hash: str) -> dict:
    return {"vouch": CHECKPOINT_TYPE, "publisher": publisher, "tree_size": tree_size, "root_hash": root_hash}


def sign_checkpoint(checkpoint: dict, private_key, key_id: str) -> dict:
    """Signed with the release key -- no new role (architecture doc section
    4.3: "the publisher signs checkpoints... with the release key").
    """
    return dsse.sign(canonicalize(checkpoint), private_key, key_id)


def verify_checkpoint_envelope(
    envelope: dict,
    *,
    authorized_keys: dict[str, bytes],
    publisher: str,
    revoked_keys: frozenset[str] = frozenset(),
) -> dict:
    payload = dsse.verify(envelope, authorized_keys, revoked_keys=revoked_keys)
    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as e:
        raise SignatureError("checkpoint payload is not valid JSON") from e
    if not isinstance(parsed, dict):
        raise SignatureError("checkpoint payload is not a JSON object")

    if not is_canonical(parsed, payload):
        raise SignatureError("checkpoint payload is not canonical JSON")
    if parsed.get("vouch") != CHECKPOINT_TYPE:
        raise SignatureError(f"unexpected document type: {parsed.get('vouch')!r}")
    if parsed.get("publisher") != publisher:
        raise SignatureError("checkpoint publisher field does not match the requested publisher")

    return parsed
