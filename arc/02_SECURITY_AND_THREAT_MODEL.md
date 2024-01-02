# Vouch: Security and Access

Status: v1 (M1-M4) implemented; this document reflects the design as built. This document owns the threat model, trust boundaries, key lifecycle, the exact consumer verification semantics, and failure behavior. Mechanisms are specified in the architecture document.
Date: 2026-07-13

## 1. Security objective and non-objectives

Objective: a consumer either obtains bytes that are exactly what the pinned publisher signed, with valid freshness, an unbroken identity chain, and hash-linked provenance, or the operation fails closed with attributable evidence.

Non-objectives, stated as assumptions per the product scope: (a) a fully compromised consumer machine is out of scope; the verifier and the pinned trust store live on that machine, so no protocol can survive its compromise; (b) quality auditing of artifacts the legitimate publisher signed is out of scope; integrity verification passes on publisher-signed poison by definition. For (b) Vouch ships a detective, provenance-based mitigation described under threat T3B: it makes such poisoning attributable and auditable, not impossible.

## 2. Access model

There are no accounts. Capability is key possession. Publishing requires the release key; changing the key set requires the root key threshold; issuing freshness requires the timestamp key. Mirroring and consuming require no credentials at all: mirrors serve public content, consumers hold only public pins. This is deliberate: any mirror credential would imply mirrors are trusted, and the design's core claim is that they are not.

## 3. Trust boundaries

```
TRUSTED                          SEMI-TRUSTED                    UNTRUSTED
consumer host,                   publisher online infra:         mirrors, trackers/
~/.vouch store,                release-key host, timestamp     directories, CDNs,
vouch binary                   signer, log server, origin      DNS, network path,
                                                                 other consumers
publisher offline
root environment
```

Trusted: the consumer host and store (assumption A above), and the publisher's offline root environment; compromise of either defeats the system for that party. Semi-trusted: the publisher's online infrastructure; its compromise is contained (bounded blast radius per key, Section 5.6) and recoverable (rotation and revocation). Untrusted: everything between publisher and consumer. Every boundary crossing from the untrusted zone is protected by exactly one of two mechanisms: content addressing (bytes must hash to a digest named by already-trusted data) or signature verification (statements must verify against keys chained from the pinned root). No data crosses inward on any other basis.

## 4. Threat model with mitigations, one to one

The six threats are those from the product brief; two are split into sub-cases where the mechanism differs. Each row lists the proving adversarial test; a mitigation is not considered done until its test demonstrates fail-closed behavior.

| ID | Threat | Example attack | Primary mitigation | Residual risk | Proving test | Milestone |
|---|---|---|---|---|---|---|
| T1 | Malicious or compromised mirror serves altered weights or datasets | mirror flips bytes in a chunk of `model.safetensors` | every chunk hash-verified against the signed manifest before write; peer blacklisted on mismatch | availability only | T1-MIRROR-TAMPER | M2 |
| T2a | Tampering in transit | on-path attacker rewrites bytes or swaps responses | same end-to-end content addressing; nothing is trusted for being "from" anyone | none for integrity | T2A-TRANSIT-TAMPER | M1 |
| T2b | Replay of stale artifacts | mirror serves last month's valid-but-superseded metadata to freeze a victim on a withdrawn release | timestamp role: signed, TTL-bounded, monotonic `seq`; consumer-persisted high-water marks; snapshot digest-bound to timestamp | freeze within one TTL window (loud after) | T2B-REPLAY-ROLLBACK | M2 |
| T3a | Byte-valid poisoned artifact introduced by a non-publisher | attacker injects duplicated samples into a shard, flips labels in JSONL records, or patches a tensor; file still loads | any byte change breaks chunk and file digests, so this is caught identically to T1; "loads fine" never bypasses hashing | none | T3A-POISON-BYTES | M2 |
| T3b | Byte-valid poison signed by the legitimate publisher | publisher (or attacker holding the release key pre-revocation) signs a backdoored release | out of scope for prevention (integrity, not quality). Detective mitigation: mandatory signed provenance, record-index `diff` between versions, and transparency-log publication making every release public, ordered, and attributable | poison present from v1.0 with plausible provenance is not detectable here | T3B-PUBLISHER-POISON-AUDIT | M3 |
| T4a | Spoofed publisher identity | lookalike key distributes "acme-lab" artifacts | identity is the root-key fingerprint; the local pin fails against any other key; no name resolution exists outside pins | first-pin bootstrap is out-of-band (Section 8) | T4A-IDENTITY-SPOOF | M1 |
| T4b | Key rotation abused or broken | attacker offers a "new root" the victim should adopt | root chain requires cross-signing: root N+1 must satisfy the threshold of root N's keys and its own; anything else is rejected | root-key compromise (see playbook) | T4B-ROTATION | M3 |
| T4c | Compromised signing key keeps working | stolen release key signs malware after the publisher noticed | signed revocation in the root document; consumers reject all signatures by a revoked key, past and future; publisher re-signs known-good releases | window between compromise and revocation; log monitoring shortens it | T4C-REVOCATION | M3 |
| T5a | Provenance or lineage forgery | attacker fabricates "fine-tuned from trusted-base@2.0" | lineage edges are digests inside release-key-signed attestations, digest-bound to the manifest in both directions; forging an edge needs a preimage or the key | publisher can lie about its own lineage (collapses to T3b) | T5A-LINEAGE-FORGE | M3 |
| T5b | Fake version history, equivocation | victim is shown a different "latest" than the rest of the world, or history is rewritten | append-only Merkle log: inclusion proof required for every consumed manifest, consistency proof against the consumer's stored checkpoint, checkpoints compared across independent sources | equivocation across consumers who never compare checkpoints and share no source | T5B-SPLIT-VIEW | M3 |
| T6a | Eclipse of a consumer | attacker controls all of a victim's peers and withholds fresh metadata | freshness hard-fails when the TTL lapses (exit 30), so an eclipse converts to a loud availability failure, never silent stale data; metadata fetched from >=2 sources when configured; pinned mirrors recommended | availability loss under total eclipse; freeze within TTL | T6A-ECLIPSE-FREEZE | M4 |
| T6b | Sybil flooding of the distribution layer | attacker spins up many fake mirrors serving garbage or nothing | endpoint verification makes Sybils unable to poison; per-peer scoring, session blacklists on digest mismatch, and bounded retries cap wasted bandwidth; no open DHT exists to capture | wasted bandwidth, degraded availability | T6B-SYBIL-EXHAUST | M4 |

Property-based tests back the table at the mechanism level: PBT-MANIFEST-MUTATE (for any valid signed manifest and any single-byte mutation of payload or signature, verification fails), PBT-CHUNK-MUTATE (for any chunk and any mutation, including truncation and extension, the chunk is rejected before write), PBT-HISTORY-MONOTONE (for any valid metadata history and any replayed prefix or reordering, the consumer rejects with a rollback or staleness error).

Why the two-mechanism rule holds against this table: T1, T2a, and T3a are the same attack at different points and fall to content addressing alone; T2b, T4a-c, T5a-b are attacks on statements rather than bytes and fall to the signed-metadata chain (root pin, cross-signed rotation, revocation, TTL and monotonic freshness, log proofs); T6a-b cannot touch integrity at all and are reduced to availability, which the design makes loud rather than silent.

## 5. Key lifecycle

### 5.1 Algorithms and identifiers
Ed25519 for all roles. Key ID is `b3:` over the raw public key. Private keys at rest are encrypted with a passphrase-derived key (scrypt parameters pinned in the key file header); no plaintext private key ever touches disk.

### 5.2 Generation and storage
Root: generated on an offline machine via `vouch keygen --role root`; the private key never resides on any network-connected host. The public fingerprint is what publishers distribute out-of-band. Release and timestamp: generated on the publish host, encrypted at rest, decrypted into process memory by the publishing tool and the freshness signer respectively. Passphrases arrive via prompt or file descriptor, never argv or environment.

### 5.3 Issuance and delegation
The root document lists authorized keys per role. Adding a release or timestamp key is a root-signed root-document update (root version increments) plus a log entry. Nothing is authorized implicitly.

### 5.4 Rotation
Release or timestamp rotation (routine): generate the new key, publish root version N+1 listing it (and usually removing the old one), signed by the root threshold; append a rotation event to the log; re-point the signer. Recommended cadence: release every 90 days or on personnel change, timestamp every 30 days, root annually or on suspicion. Root rotation: new root document signed by both the old root threshold and the new one (cross-signing), so every consumer can walk from their original pin to the current root without re-pinning. A consumer that encounters a root version older than one it has already validated treats it as rollback (exit 31).

### 5.5 Revocation
Revocation is a root-signed root-document update placing the key ID in `revoked` with a time and reason, plus a log event. Semantics, decision D13 (fail closed): a revoked key's signatures are invalid everywhere, including on artifacts that verified before the revocation. Reasoning: without trusted timestamping there is no sound way to distinguish signatures made before compromise from backdated ones made after, so the safe rule is total; availability is restored by the publisher re-signing known-good manifests with the new key, which is cheap (manifests, not artifacts, are re-signed; the bytes and digests do not change). Consumers holding a now-revoked-key artifact in the verified store mark it `revoked` on the next metadata refresh and refuse to open or re-verify it until a re-signed manifest arrives.

### 5.6 Compromise playbooks and blast radius
Timestamp key: attacker can issue fresh-looking timestamps, so it can freeze consumers on the current state or point at garbage (DoS); it cannot cause acceptance of any manifest the release key did not sign, and it cannot remap names because manifests embed name and version (check V6). Response: revoke, rotate, reissue. Release key: attacker can sign malicious releases and log checkpoints until revocation; every such release necessarily lands in a log that monitors can watch, which is the detection channel. Response: revoke, rotate, re-sign known-good manifests, publish an advisory event in the log. Root key: full identity compromise; the attacker can rotate the publisher out of their own identity. Response is out-of-band: publish a new fingerprint through the bootstrap channels and ask consumers to re-pin. Stated honestly: cryptography does not recover from root loss, which is why the root stays offline and thresholds are supported.

## 6. What a consumer verifies, and when

The authoritative checklist. Order matters; each step consumes only data validated by earlier steps.

- V1 Pin: a local pin exists for the publisher; the requested name maps to a fingerprint. Fail: exit 43.
- V2 Root chain: every root document from the pinned version to the newest validates its signature threshold, cross-signatures on rotation, strictly increasing versions, and unexpired current root. Fail: 41 (signature), 31 (older root than already seen).
- V3 Revocations: the revoked-key set from the current root is loaded; any signature by a revoked key encountered at any later step is invalid. Fail at point of use: 42.
- V4 Timestamp: signed by an authorized timestamp key; `expires` in the future within the 10-minute skew allowance; `seq` >= the stored high-water mark; if `seq` equals a previously seen value, the statement bytes must match what was seen (equivocation check). Fail: 41, 30 (expired or none fresh available), 31 (lower seq), 44 (equivocation). On success the high-water mark advances.
- V5 Snapshot: fetched by the digest named in the timestamp; bytes hash to that digest. Fail: 40.
- V6 Manifest: the snapshot maps name@version to a manifest digest; fetched bytes hash to it; the DSSE signature verifies under an authorized, unrevoked release key; the manifest's embedded publisher, name, and version equal the requested reference; per-artifact `seq` >= that artifact's high-water mark. Fail: 40, 41, 42, 31, or 21 (reference absent from a valid snapshot).
- V7 Log: an inclusion proof places the manifest's log leaf under the current signed checkpoint; a consistency proof connects the consumer's stored checkpoint to the current one; when two or more sources are configured, their checkpoints are cross-compared. Fail: 44. On success the stored checkpoint advances.
- V8 Chunks: each arriving chunk hashes to its manifest entry before any write into the CAS; a mismatch discards the bytes, blacklists the peer for the session, decrements its persistent score, and re-queues the chunk elsewhere. Artifact-level fail only if no source can supply a valid chunk: 40 (with peer attribution) or 20 (pure availability).
- V9 Assembly: each file's digest and the artifact (manifest) digest are confirmed over the assembled data. Fail: 40 (would indicate an internal fault, since V8 passed; still fails closed).
- V10 Provenance: the attestation's digest matches the manifest's binding, its subject digest matches the manifest, and its DSSE signature verifies under an authorized, unrevoked release key. Fail: 45.

When each runs. `fetch`: V1 through V10, then atomic materialization; state (high-water marks, checkpoint, scores) is committed only with success of the step that produced it. `verify PATH --ref`: V1, V2, V3, V6 (manifest from cache or network), then V8 and V9 recomputed over the local bytes, and V10; it never mutates the verified store. Materialization gate: nothing appears under `verified/` before V10 passes. `verify --deep`: re-runs V8 and V9 over an artifact already in the verified store, catching local bit rot or post-hoc tampering on disk. Metadata refresh (any command that goes to the network): V1 through V4 always run, so revocations propagate even when the user is not fetching.

Clock policy: expiry checks use the local clock with the fixed skew allowance; a timestamp that appears issued in the future beyond the allowance is rejected as invalid (41) rather than accepted, and the error text tells the user to check their clock.

## 7. Failure behavior

Principles: fail closed, attribute evidence, never degrade to unverified. There is no override flag; the only remediations are trust-state operations (`vouch trust add`, updating pins, publisher-side re-signing), never verification bypasses.

Exit codes, authoritative for both this document and the frontend spec:

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | usage error |
| 20 | network or peer availability failure |
| 21 | reference not found in a valid snapshot |
| 30 | metadata stale: no unexpired timestamp obtainable |
| 31 | rollback detected (seq or root version below high-water mark) |
| 40 | content digest mismatch (chunk, file, snapshot, or artifact) |
| 41 | signature invalid or key not authorized |
| 42 | key revoked |
| 43 | publisher unknown or pin mismatch |
| 44 | transparency log failure: inclusion, consistency, or equivocation |
| 45 | provenance invalid |
| 70 | internal error |

Quarantine: on any verification failure that involved received bytes, the offending material is moved to `quarantine/<utc-timestamp>-<code>/` containing the bytes, the expected and actual digests, the peer identity and URL, the metadata in force, and a machine-readable `report.json`. Quarantine is evidence, never input: nothing is ever read back from it into verification.

Retry matrix: transport errors (timeouts, resets, 5xx) retry on other peers up to a bounded budget; digest mismatches never retry against the same peer and re-queue elsewhere; signature, revocation, rollback, staleness, log, and provenance failures abort the operation immediately with no retry, because retrying an attack indication against another mirror cannot make a forged statement valid. Peer scores persist across runs; a peer that served a bad digest starts future sessions deprioritized.

## 8. Residual risks and honest limitations

Freshness freeze within one TTL: between issuance and expiry, withheld updates are undetectable; the TTL is the knob, defaulting to 24 hours. Publisher-signed poison: T3b is detective only; a publisher malicious from its first release, with self-consistent provenance, passes verification, and the system's contribution is that the release is public, ordered, attributable, and diffable. First-pin bootstrap: the initial fingerprint acquisition is out-of-band and can be attacked there; publishing the fingerprint through multiple independent channels is the practical defense. Privacy: mirrors observe who fetches what; Vouch does not attempt anonymity. Availability: a sufficiently resourced attacker can always deny service; the guarantee is that denial is loud and integrity is never traded for availability. Local host: bit rot and local tampering after materialization are caught only when `verify --deep` is run; the verified store is trusted between deep checks by assumption A.

## 9. Security testing plan

Every T-series test in Section 4 is implemented as an executable adversarial scenario in the milestone shown, using in-process fake peers so attacks are deterministic: a tampering mirror, a stale mirror, an equivocating metadata source, a wrong-key signer, a forged-lineage publisher, and an eclipsing peer set are all test fixtures. The PBT suite runs under Hypothesis with mutation strategies over payload bytes, signature bytes, chunk contents and lengths, and metadata histories. M4 adds parser fuzzing (manifest, root, timestamp, snapshot, envelope, proof inputs are attacker-controlled bytes and are treated as such) and a chaos scenario combining T1, T2b, and T6a simultaneously against one fetch. Each checkpoint report lists which tests ran, which threats they cover, and explicitly what was not tested yet.
