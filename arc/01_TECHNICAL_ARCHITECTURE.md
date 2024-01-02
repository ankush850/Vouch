# Vouch: Technical Architecture

Status: v1 (M1-M4) implemented; this document reflects the design as built. Companion to the PRD; the security document owns the threat-by-threat analysis, this document owns the mechanisms.
Date: 2026-07-13

## 1. Overview

Vouch has four runtime roles. A publisher signs artifacts and metadata, with the root key offline. An origin node (run by the publisher) is the first source of bytes. Mirrors are untrusted replicas that copy and serve bytes. Consumers fetch from anywhere and verify everything locally against a pinned publisher identity.

```
 +---------------------------+
 |  Publisher                |    publish: chunks, signed manifests,
 |  offline root key         |    metadata, log entries
 |  online release/timestamp |------------------------------+
 +---------------------------+                              v
                                                   +------------------+
                                                   |  Origin node     |
                                                   |  (publisher-run) |
                                                   +---+----------+---+
                                        untrusted pull |          | untrusted pull
                                                       v          v
                                              +-----------+   +-----------+
                                              | Mirror A   |   | Mirror B  |
                                              | untrusted  |   | untrusted |
                                              +-----+-----+   +-----+-----+
                                                     \             /
                                       chunks + metadata (verified locally)
                                                      \           /
                                              +--------v---------v--------+
                                              | Consumer (vouch CLI)    |
                                              | pinned roots, CAS store,  |
                                              | verifier, quarantine      |
                                              +---------------------------+
```

Every byte a consumer accepts is justified in exactly one of two ways: it is content-addressed (its hash is named by something already trusted), or it is signed (by a key already trusted via the pinned root). The transport therefore carries zero trust. TLS between nodes is optional and provides privacy only, never integrity.

## 2. Identities and naming

A publisher's identity is the fingerprint of its root public key: `b3:<hex>` over the canonical root public key encoding. There is no global naming authority; a human-friendly name like `acme-lab` is a local alias created when the consumer pins the fingerprint, exactly like an SSH `known_hosts` entry. Decision, with reasoning: a global registry would reintroduce a central trust root, which is what the system exists to remove; local pinning keeps the trust bootstrap explicit and auditable.

An artifact reference is `NAME/ARTIFACT@VERSION`, for example `acme-lab/bert-tiny@1.2.0`. The reference resolves through signed metadata (Section 4) to a manifest digest. The artifact's true identity is that manifest digest, since the manifest transitively names every byte.

## 3. Content addressing and artifact model

### 3.1 Hashing

All digests are BLAKE3, 256-bit, rendered as `b3:<hex>`. The prefix gives algorithm agility: manifests carry the algorithm in the digest string, so a future migration (or a secondary SHA-256 digest for interop) does not break the format. Decision D1: BLAKE3 over SHA-256. Reasoning: hashing multi-gigabyte checkpoints is the hot path of verification; BLAKE3 is SIMD-optimized and parallelizes across cores, giving well over 1 GB/s on commodity hardware, which is what makes "verify every byte, always" affordable; it is a modern construction with a healthy margin, and the Python binding is a thin wrapper over the reference Rust implementation. The cost is that SHA-256 is more universal; the prefix keeps the door open.

### 3.2 Chunking

Files are split into fixed 4 MiB chunks; each chunk is stored and requested by its own digest. Decision D2: fixed-size chunks, not content-defined chunking (CDC). Reasoning: fixed chunks make offsets trivially computable, keep the fetch scheduler simple, and are enough for the primary goal (streaming verification with bounded memory and fail-fast on the first bad chunk). CDC would improve cross-version deduplication for append-heavy datasets, but fine-tuned weights change almost everywhere anyway, and CDC adds a subtle algorithm to the trusted computing base. Recorded as deferred, revisit after M4 with real dataset traffic. Decision D3: a manifest carries the flat, ordered list of chunk digests rather than a deep Merkle tree with per-chunk proofs. Reasoning: manifests are small enough to fetch whole (a 10 GiB file is about 2,560 digests, roughly 80 KiB of manifest), so proofs buy nothing, and a flat list is harder to get wrong.

### 3.3 Manifest

The manifest is the signed statement "this artifact is exactly these bytes". Canonical shape (canonicalization in 3.5):

```json
{
  "vouch": "manifest/v1",
  "publisher": "b3:9f2a...",
  "name": "bert-tiny",
  "version": "1.2.0",
  "seq": 14,
  "type": "model",
  "created": "2026-07-13T09:00:00Z",
  "files": [
    {
      "path": "model.safetensors",
      "size": 5477632000,
      "chunk_size": 4194304,
      "chunks": ["b3:aa01...", "b3:aa02...", "..."],
      "digest": "b3:77e1..."
    }
  ],
  "total_size": 5477632000,
  "record_index": null,
  "provenance": "b3:03bd..."
}
```

`seq` is a per-artifact monotonic release counter used for rollback protection; `version` is the human semantic version. A file's `digest` is BLAKE3 over the concatenated raw chunk digests, and the artifact digest is BLAKE3 over the canonical manifest bytes. The manifest embeds its own `name` and `version` so that a compromised freshness key cannot remap references to a different legitimately signed manifest (see the security document, timestamp-key blast radius).

### 3.4 Dataset record index

For datasets, the manifest may carry a `record_index`: a per-file index of record digests at configurable granularity. v1 supports JSONL (digest per record or per block of N records) and treats other formats as opaque; Parquet row groups and tar shard members are natural extensions, deferred. The index serves two purposes: partial verification of a slice, and `vouch diff`, which compares two versions' indices and reports added, removed, and modified records by digest. This diff is the lightweight provenance-based mitigation for publisher-signed poisoning: injected or duplicated samples and label flips between versions become enumerable facts tied to a signed release, rather than something hidden inside a multi-gigabyte blob. The index inflates the manifest, so granularity is a publish-time choice (`--records line|block:N|none`).

### 3.5 Canonicalization and signing envelope

All signed payloads are JSON canonicalized per RFC 8785 (JCS), and signatures live in a DSSE envelope (payloadType `application/vnd.vouch.v1+json`, base64 payload, signatures with key IDs), signed over DSSE's pre-authentication encoding. Decision D4: JCS plus DSSE rather than an ad hoc "sign the bytes we happened to serialize" scheme. Reasoning: deterministic canonicalization removes an entire class of signature-bypass bugs (semantically equal, byte-different payloads), and DSSE is the small, well-reviewed envelope used by in-toto and sigstore, so the design leans on prior art instead of inventing an envelope. Key IDs are `b3:` fingerprints of the raw public key.

## 4. Trust metadata layer

The layer is shaped like TUF with the role set collapsed to what the threat model needs. Decision D5: three keys, not four. Roles:

| Role | Key location | Signs | Compromise blast radius (summary) |
|---|---|---|---|
| root | offline | root documents: role keys, revocations, rotations | full identity compromise; recovery is out-of-band re-pin |
| release | online, publish host | manifests, provenance attestations, log checkpoints | attacker can sign malicious releases until revoked; detectable in the log |
| timestamp | online, freshness signer | timestamp statements | freshness lies within TTL: freeze or garbage-pointer DoS, never valid content forgery |

### 4.1 Root document

```json
{
  "vouch": "root/v1",
  "publisher": "b3:9f2a...",
  "root_version": 3,
  "keys": {
    "root": [{"id": "b3:9f2a...", "pub": "..."}],
    "release": [{"id": "b3:5cc0...", "pub": "..."}],
    "timestamp": [{"id": "b3:11d4...", "pub": "..."}]
  },
  "threshold": {"root": 1},
  "revoked": [{"id": "b3:old1...", "at": "2026-06-30T00:00:00Z", "reason": "compromise"}],
  "expires": "2027-07-13T00:00:00Z"
}
```

Root documents form a chain: version N+1 must carry signatures satisfying the threshold of version N's root keys and of version N+1's root keys (the TUF cross-signing rule), so a consumer holding only the original pin can walk forward to the current root. Thresholds default to 1-of-1 but the format supports m-of-n from day one because retrofitting thresholds into signatures is painful.

### 4.2 Timestamp and snapshot

The timestamp statement is tiny, short-lived, and reissued automatically:

```json
{
  "vouch": "timestamp/v1",
  "publisher": "b3:9f2a...",
  "seq": 141,
  "snapshot": "b3:e0ff...",
  "issued": "2026-07-13T09:00:00Z",
  "expires": "2026-07-14T09:00:00Z"
}
```

The snapshot it names maps every artifact to its current version, seq, and manifest digest. Decision D6: the snapshot is digest-bound to the timestamp rather than separately signed. Reasoning: one fewer online key; integrity of the snapshot comes from its digest, freshness from the timestamp's TTL and monotonic `seq`, and mix-and-match across artifacts is impossible because a single snapshot pins them all at once. Default TTL is 24 hours with a 10-minute clock-skew allowance; both are publisher-configurable. Consumers persist the highest `seq` per publisher and per artifact as rollback high-water marks.

### 4.3 Transparency log

Every publish, rotation, and revocation appends a leaf (event type, digest, seq) to a per-publisher append-only Merkle log in the RFC 6962 style. The publisher signs checkpoints (tree size plus root hash) with the release key. Consumers verify an inclusion proof for any manifest they consume and a consistency proof from the last checkpoint they stored to the current one, and they compare checkpoints obtained from different sources. Decision D7: a single publisher-operated log with client-side proofs and cross-source checkpoint comparison, rather than third-party witnesses or a ledger. Reasoning: this already makes fake version history and targeted equivocation (serving one victim a different "latest" than everyone else) cryptographically detectable, which is what threat 5 requires; witness co-signing strengthens it later without format changes. Log leaves and checkpoints are themselves content-addressed files, so mirrors replicate the log like any other content.

## 5. Provenance and lineage

Each release carries a provenance attestation, in-toto flavored, signed by the release key in a DSSE envelope, and bound to the manifest by digest in both directions (manifest names attestation digest; attestation names manifest digest as subject):

```json
{
  "vouch": "provenance/v1",
  "subject": {"name": "bert-tiny", "version": "1.2.0", "digest": "b3:77e1..."},
  "materials": [
    {"role": "base-model", "ref": "acme-lab/bert-base@2.1.0", "digest": "b3:5aa9..."},
    {"role": "dataset", "ref": "acme-lab/sst5@1.4.2", "digest": "b3:03ab..."}
  ],
  "build": {"kind": "finetune", "code": "git+https://github.com/acme/train@ab12cd3", "params": "b3:cd44..."},
  "created": "2026-07-13T08:40:00Z"
}
```

Lineage edges are digests, so forging a parent relationship requires either a hash preimage or the publisher's signing key; there is no unsigned lineage. The lineage of an artifact forms a DAG that the CLI can walk and render, labeling each node with the consumer's local knowledge level: `verified` (bytes present and verified), `manifest` (signed manifest seen, bytes not fetched), or `recorded` (digest known only from the attestation, e.g. an external code reference). Fake version history is separately prevented by the log: a version that does not appear in the log with a valid inclusion proof does not verify.

## 6. Distribution layer

### 6.1 Protocol

Peers speak plain HTTP. Every response is either content-addressed or signed, so no endpoint is trusted:

```
GET /v1/{publisher}/meta/root/{n}          root chain documents
GET /v1/{publisher}/meta/timestamp         latest timestamp (only mutable endpoint)
GET /v1/{publisher}/meta/snapshot/{digest}
GET /v1/manifest/{digest}
GET /v1/chunk/{digest}
GET /v1/{publisher}/log/checkpoint
GET /v1/{publisher}/log/leaf/{index}
GET /v1/{publisher}/log/proof/inclusion?leaf=...&size=...
GET /v1/{publisher}/log/proof/consistency?old=...&new=...
```

Digest-addressed endpoints are immutable and infinitely cacheable, which makes dumb HTTP caches and CDNs into mirrors for free. Decision D8: a thin custom HTTP layer rather than libtorrent, IPFS, or libp2p. Reasoning: BitTorrent v1 hashes with SHA-1 and neither v1 nor v2 provides the freshness, identity, revocation, or log semantics, so the trust layer would be custom regardless; IPFS brings a large dependency, a DHT with studied eclipse issues, and immature Python bindings, while its CAS overlaps what forty lines of hashing code provide; a custom layer keeps every verification decision in auditable project code and lets the entire adversarial test suite run in-process with fake peers. The cost is writing our own fetch scheduler, which is the intended scope.

### 6.2 Discovery and peer selection

The consumer's mirror list per publisher comes from three sources: mirrors pinned in local config, an optional signed mirror-hint list the publisher ships (best effort, not trust-bearing), and manual additions. There is no DHT in v1. Because content is verified at the endpoint, discovery integrity is availability-critical only: the worst a poisoned peer list yields is failed fetches and a loud staleness error, never accepted bad bytes.

The fetch scheduler fans chunk requests across peers with a default of 8 parallel streams, verifies each chunk digest before the bytes touch the CAS, and maintains per-peer scores. A digest mismatch immediately blacklists the peer for the session, decrements its persistent score, and re-queues the chunk elsewhere; transport errors merely deprioritize. Selection is weighted random over healthy peers with a small exploration share so a formerly bad mirror can rehabilitate. Freshness metadata (`timestamp`, `log/checkpoint`) is fetched from at least two independent sources when two or more are configured; the consumer accepts the freshest valid statement and treats two valid statements with the same `seq` but different contents as equivocation evidence (hard fail, evidence saved). Sybil peers therefore reduce to a bandwidth-waste and availability problem, handled by scoring and by the hard staleness failure; the design intentionally does not attempt Sybil-proof membership (no proof of work or stake), because endpoint verification removes the need.

## 7. Verification pipeline

The consumer-side pipeline, in order, with the exact check semantics specified in the security document as V1 through V10:

```
resolve pin (V1)
  -> update root chain (V2), load revocations (V3)
  -> fetch timestamp from >=2 sources, validate TTL/seq/equivocation (V4)
  -> fetch snapshot by digest (V5)
  -> resolve name@version -> manifest digest; fetch, hash-check, verify
     signature, verify embedded name/version match (V6)
  -> verify log inclusion + consistency (V7)
  -> schedule chunks across peers; per chunk: hash-check then write to
     CAS temp, else blacklist peer and refetch (V8)
  -> assemble files; confirm file digests and artifact digest (V9)
  -> verify provenance binding and signature (V10)
  -> atomically materialize into verified store; update high-water
     marks, checkpoint, peer scores
any failure -> abort, quarantine evidence, specific exit code
```

Verification streams: memory use is O(chunk size), a bad chunk is caught within one chunk of arrival, and nothing unverified is ever written under the verified path. Partial state lives in a temp area inside the CAS; failed material moves to quarantine with evidence attached.

## 8. Local storage layout

```
~/.vouch/
  config.toml
  trust/<publisher>/            pinned fingerprint, root chain, high-water marks,
                                stored log checkpoint
  objects/<aa>/<digest>         content-addressed store (chunks, manifests,
                                snapshots, attestations, log leaves)
  verified/<publisher>/<artifact>/<version>/   materialized artifacts (hardlinks
                                               into objects where possible)
  quarantine/<timestamp>-<reason>/             evidence from failed verification
  peers.json                    persistent peer scores
```

Decision D9: no database; small JSON state files written with atomic rename. Reasoning: every state file is human-inspectable during adversarial debugging, atomic rename gives the needed crash consistency, and the trusted computing base stays small. Revisit only if peer-score or index volume demands it.

## 9. Stack recommendation

Recommendation: Python 3.11+, asyncio-based. The origin repo is Python, and this is a recommendation against the threat model and performance needs, not an assumption of continuity:

| Dependency | Why |
|---|---|
| `blake3` | Rust-backed hashing; the performance-critical path runs at native speed |
| `cryptography` | Ed25519 signing and verification; maintained, widely audited |
| `rfc8785` | JCS canonicalization (Trail of Bits), avoids hand-rolling canonical JSON |
| `aiohttp` | async HTTP client and server for consumer, origin, and mirror |
| `click` | CLI framework; stable, minimal |
| `pytest` + `hypothesis` | test runner plus property-based testing |

Reasoning. The performance-sensitive work is hashing and network I/O; both run in native code or the kernel, so Python's interpreter overhead is off the hot path, and the 1 GB/s hashing target is met by the BLAKE3 binding rather than by the host language. What Python buys that matters to this project specifically: Hypothesis, which is the strongest property-based testing tool in any mainstream ecosystem, and the working requirements make adversarial property tests a first-class deliverable; rapid iteration across four review-gated milestones; and direct reuse of any origin-repo pieces worth keeping. Honest alternatives: Rust would give memory safety and the best mirror-daemon throughput, at the cost of iteration speed across M1 to M4 and with `proptest` being a step down from Hypothesis for this style of testing; Go suits long-running daemons but has a weaker property-testing story and zero reuse. Decision D10: Python for all of M1 through M4; the one component worth revisiting in Rust afterward is the standalone mirror daemon, and nothing in the wire format or storage layout would need to change.

## 10. Reuse from P2P-File-Sharing-System

Reviewed at HEAD (about 850 lines of Python). What is there: a socket tracker mapping `info_hash` to peer lists, a peer that serves file pieces by filename, a client that downloads pieces in parallel threads, a SHA-1 hash-of-piece-hashes utility (BitTorrent v1 style, 16 KiB pieces), and a separate multi-threaded raw-socket HTTP server with its own test client.

What carries over as concepts: the role separation (tracker, serving peer, fetching client maps onto directory hints, mirror, consumer), the piece-parallel download pattern, and the hash-of-pieces idea, upgraded into the signed manifest.

What must be replaced, with the security reasons: the client writes downloaded pieces without ever verifying them against the info hash, which is precisely the poisoning hole this product exists to close; pieces are requested by filename rather than digest, and the serving peer joins that filename onto its shared path unsanitized (a path traversal); SHA-1 is collision-broken and cannot anchor a content-addressed design; there is no identity, signing, freshness, revocation, or provenance anywhere; and the length-unframed socket protocol is fragile. The standalone HTTP server is dropped in favor of aiohttp. Net assessment: the repo is treated as a design sketch that demonstrated the transport shape; effectively all trust-relevant code is new, consistent with treating the poisoning-resistance reframe as the actual product, not the transport plumbing.

## 11. Milestone mapping

| Milestone | Components | Proving tests (IDs in security doc) |
|---|---|---|
| M1 | CAS, chunker, manifest, JCS+DSSE sign/verify, origin server, single-peer fetch, materialize/quarantine, core exit codes | T2A, T4A, PBT-MANIFEST-MUTATE, PBT-CHUNK-MUTATE |
| M2 | mirror sync/serve, fetch scheduler, peer scoring/blacklist, timestamp+snapshot, rollback high-water marks, multi-source metadata | T1, T2B, T3A, PBT-HISTORY-MONOTONE |
| M3 | provenance attestations, lineage walk, record index + diff, root chain rotation, revocation, transparency log with proofs | T3B, T4B, T4C, T5A, T5B |
| M4 | eclipse/freeze hardening, equivocation cross-checks, chaos scenario, fuzzing of parsers, compromise-playbook drills | T6A, T6B, full-suite adversarial demo |

## 12. Decision log (seed)

Carried into the repo as `DECISIONS.md` at M1; entries above are summarized here for one-glance review. D1 BLAKE3 over SHA-256 (verification hot path; agility via prefix). D2 fixed 4 MiB chunks over CDC (simplicity; dedup deferred). D3 flat chunk list over Merkle proofs (manifests are small; less to get wrong). D4 JCS canonical JSON in DSSE envelopes (kills canonicalization bugs; prior art). D5 three roles: offline root, online release, online timestamp (minimum that satisfies the threat model). D6 snapshot digest-bound to timestamp, not separately signed (one fewer online key, same guarantees). D7 single publisher log, client-side inclusion/consistency proofs, cross-source checkpoint comparison (equivocation detection without a ledger). D8 thin custom HTTP over libtorrent/IPFS/libp2p (trust layer is custom anyway; auditable; in-process adversarial testing). D9 JSON state files with atomic rename, no database (inspectable, small TCB). D10 Python 3.11+ for M1 to M4 (native-speed hot paths, Hypothesis, reuse), Rust noted only as a post-M4 option for the mirror daemon. D11 no unverified fetch path exists anywhere in the design (invariant, tested). D12 publisher naming is local pinning, no global registry (no reintroduced central trust root).
