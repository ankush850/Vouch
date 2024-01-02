# Vouch: Product Requirements Document

Status: v1 (M1-M4) implemented; this document reflects the design as built. See `THREAT_COVERAGE.md` and `DECISIONS.md` for how each requirement below was verified.
Date: 2026-07-13
Origin: rework of `P2P-File-Sharing-System` (Python). The reframe to poisoning-resistant ML artifact distribution is the product; the old repo is scaffolding only.

## 1. Problem

ML artifacts are large, mirrored everywhere, and trusted almost nowhere in a verifiable way. Multi-gigabyte model checkpoints and dataset shards move through hubs, CDNs, university mirrors, torrents, cloud buckets, and local caches. Today, trust in that pipeline is either centralized (you trust the hub and the TLS connection to it) or absent (a checksum pasted on a wiki page, if you are lucky). Three specific gaps make this dangerous:

First, integrity is transport-scoped, not artifact-scoped. TLS protects one hop. The moment a file is re-hosted, every re-host becomes a fresh trust decision, and most consumers never make it consciously. A mirror operator, or anyone who compromises a mirror, can serve altered weights or datasets to everyone downstream.

Second, provenance is unverifiable prose. Model cards claim "fine-tuned from X on dataset Y", but nothing binds that claim to bytes. Lineage, version history, and training inputs can be fabricated freely, and there is no mechanism by which a forged history is even detectable.

Third, freshness and revocation do not exist. If a signing key is compromised or a release is discovered to be poisoned, there is no standard way to tell consumers. Stale or explicitly withdrawn artifacts circulate indefinitely, and a malicious mirror can deliberately pin consumers to an old vulnerable version.

The economics favor the attacker. Flipping labels in a dataset shard, injecting duplicated samples, or patching a tensor in a checkpoint is cheap, silent, and byte-valid: the file still loads, the model still runs, and the corruption surfaces only as degraded or backdoored behavior much later, far from the point of tampering.

## 2. Product summary

Vouch is a decentralized distribution system for ML models and datasets in which the publisher signs once, any number of untrusted mirrors carry bytes, and every consumer verifies locally that what they received is exactly what the publisher signed: content integrity, publisher identity, freshness, and hash-linked provenance. The design goal, stated as an invariant: a mirror must be structurally unable to poison, only able to withhold, and withholding must be loud. Verification is the default and only path; there is no unverified fetch mode.

## 3. Users

### 3.1 Publishers
Research labs, model authors, dataset curators. They want wide distribution without operating or paying for global infrastructure, tamper-evidence attached to their name so that a poisoned copy cannot be pinned on them, machine-verifiable lineage for what they release, and a credible recovery path when a signing key is compromised (rotation and revocation that consumers actually enforce).

### 3.2 Consumers
ML engineers, researchers, and automated pipelines (CI jobs, training scripts, production model loaders). They want one command that either yields exactly-signed bytes or fails loudly with a machine-readable reason, the ability to verify an artifact they already have on disk, the ability to audit what changed between two versions of a dataset, and deterministic exit codes so verification can gate a pipeline.

### 3.3 Mirror operators
Universities, companies caching internally, volunteers. They want to contribute bandwidth and storage with zero trust required of them and zero ambiguity about their role: the system must guarantee that nothing they do (or that an attacker does to their machine) can cause a consumer to accept corrupted content. Running a mirror should require no credentials, no registration with the publisher, and no key material.

## 4. Core use cases

UC1, Publish a model with lineage. A publisher runs `vouch publish` on a checkpoint directory, declaring the base model, training datasets, and code revision. Vouch chunks and hashes the content, writes a signed manifest and a signed provenance attestation, appends the release to the publisher's transparency log, and makes everything available from the publisher's origin node.

UC2, Fetch and verify. A consumer runs `vouch fetch acme-lab/bert-tiny@1.2.0`. Vouch resolves the pinned publisher identity, checks metadata freshness and rollback protection, downloads chunks in parallel from whatever mirrors are available, verifies every chunk against the signed manifest before writing it, verifies the transparency log proofs and the provenance attestation, and only then materializes the artifact. Any failure aborts with a specific exit code and quarantined evidence.

UC3, Verify an existing local artifact. A consumer who obtained a file elsewhere (USB drive, another tool) runs `vouch verify ./weights --ref acme-lab/bert-tiny@1.2.0` and gets a byte-exact pass or fail against the publisher's signed manifest.

UC4, Inspect provenance. `vouch provenance acme-lab/bert-tiny@1.2.0` renders the lineage DAG: parent models, datasets, and code references, each edge a digest, each node's verification state shown.

UC5, Audit a dataset version diff. For datasets published with a record index, `vouch diff acme-lab/sst5@1.4.1 acme-lab/sst5@1.4.2` lists added, removed, and modified records by digest, making injected samples, duplications, and label flips between versions visible and attributable.

UC6, Rotate keys. A publisher performs planned rotation of release or timestamp keys, or of the root itself, and consumers accept the new keys automatically because the rotation is cross-signed from the trust they already hold.

UC7, Revoke a compromised key. A publisher revokes a release key; consumers with fresh metadata reject everything signed by it, and the publisher re-signs known-good releases with a new key to restore availability.

UC8, Operate a mirror. An operator runs `vouch mirror sync` against any existing source and `vouch mirror serve`. No keys, no accounts. Optionally the mirror verifies content on ingest purely to avoid wasting its own disk on garbage; this is never trust-relevant to consumers.

UC9, CI verification gate. A pipeline step runs `vouch fetch --json` and branches on exit code, treating any nonzero verification code as a build failure with structured evidence attached.

## 5. Non-goals

Quality or safety auditing of publisher-signed artifacts. If the legitimate publisher signs poisoned content, integrity verification passes by definition; this is an integrity system, not an evaluation system. Vouch does ship a lightweight provenance-based mitigation (mandatory attestations, record-level version diffs, and a public transparency log that makes every release attributable and auditable), detailed in the security document, but it is detective, not preventive.

Access control, DRM, or private artifacts. v1 assumes public artifacts. A private distribution mode is a plausible later layer and is explicitly deferred.

Incentive layers, tokens, or blockchains. The trust root is the publisher's key, not consensus. Log equivocation is handled with cryptographic proofs and cross-source comparison, which needs no global ledger.

Anonymity or censorship resistance. Vouch is not Tor. Mirrors can observe who fetches what; this is recorded as a privacy limitation, not solved.

Hub-style discovery and search UX. Finding artifacts is out of scope; Vouch starts from a reference the consumer already has.

Sophisticated NAT traversal. v1 assumes mirrors are reachable at an address. Relaying and hole-punching are deferred.

Defending a fully compromised consumer machine. If the attacker controls the host, they control the verifier and the pinned trust store. Stated as an assumption, not a mitigation target.

## 6. Success criteria

Vouch v1 (through milestone M4) is done when all of the following hold:

1. Threat coverage with proof. Every row of the threat model in the security document has at least one adversarial test that demonstrates the attack being caught and the system failing closed. Test IDs are assigned in the security document and referenced from the milestone plan. A mitigation without its failing-closed test does not count as done.
2. End-to-end adversarial demo. A scripted scenario runs one origin plus three mirrors, of which one serves tampered chunks, one serves stale metadata, and one is honest. `vouch fetch` completes successfully, the tampering and staleness are detected and logged with peer attribution, and the artifact materializes byte-identical to what was published.
3. Rollback and freshness. A consumer that has seen version N provably rejects any metadata or artifact set older than N (exit code 31), and rejects metadata older than the freshness TTL (exit code 30), in tests.
4. Revocation propagation. After a revocation is published, a consumer with fresh metadata rejects artifacts signed by the revoked key, including artifacts that verified successfully before the revocation, in tests.
5. Performance. On a 1 Gbps LAN with a 5 GiB artifact, verified fetch adds no more than 5 percent wall-clock over an unverified HTTP download of the same bytes. Hashing throughput is at least 1 GB/s on a commodity multi-core CPU. Verification memory is bounded by O(chunk size), independent of artifact size, via streaming.
6. No bypass exists. The codebase contains no flag, environment variable, or code path that yields an unverified artifact in the verified store. This is checked by test and by grep in review.
7. Operational simplicity. Publishing a release is at most two commands after one-time setup; fetching is one command after one-time pinning; running a mirror is two commands and zero key material.

## 7. Assumptions

Consumers can obtain the publisher's root key fingerprint through at least one out-of-band channel (project website, code repository, printed in a paper). The first pin is the trust bootstrap and is outside the cryptographic guarantees. The publisher keeps the root key offline and can perform a signing ceremony when needed. System clocks on consumers are within roughly 10 minutes of true time; TTLs are sized to tolerate this. Artifacts are public. The consumer host and the Vouch store on it are not compromised.

## 8. Deferred questions

These are noted so they are not silently decided: a namespace or directory service for discovering publishers (v1 uses local pins only), private artifact distribution, mirror-side bandwidth accounting, and witness co-signing of transparency log checkpoints by third parties. None block M1 through M4.
