# Vouch: Threat Coverage

Per 03_SECURITY_AND_ACCESS.md section 9: "Each checkpoint report lists
which tests ran, which threats they cover, and explicitly what was not
tested yet." This is that report, cumulative across all four milestones
(M1-M4, all complete) rather than an M4-only artifact, hand-maintained
alongside `DECISIONS.md`, not generated tooling, matching this project's
existing "inspectable over clever" convention (D9).

Mitigation text is summarized from 03_SECURITY_AND_ACCESS.md section 4's
threat table; read that document for the authoritative wording.

## Threats (T1-T6b)

| ID | Threat | Mitigation | Proving test(s) | Milestone | Residual risk / not tested |
|---|---|---|---|---|---|
| T1 | Malicious/compromised mirror alters bytes | every chunk hash-verified before write; peer blacklisted on mismatch | `tests/adversarial/test_t1_mirror_tamper.py` | M2 | availability only |
| T2a | Tampering in transit | end-to-end content addressing; nothing trusted for being "from" anyone | `tests/adversarial/test_t2a_transit_tamper.py` | M1 | none for integrity |
| T2b | Replay of stale artifacts | signed, TTL-bounded, monotonic timestamp `seq`; consumer high-water marks; snapshot digest-bound to timestamp | `tests/adversarial/test_t2b_replay_rollback.py` | M2 | freeze within one TTL window (loud after) |
| T3a | Byte-valid poison from a non-publisher | any byte change breaks chunk/file digests, mechanically identical to T1 | covered by T1's mechanism directly (`cas.write_verified` doesn't distinguish attacker identity); no separate dedicated test | M2 | none |
| T3b | Byte-valid poison signed by the publisher | out of scope for prevention (integrity, not quality); detective: mandatory provenance, record-index diff, transparency log | `tests/e2e/test_m3_ceremony.py` (dataset diff + log inclusion/checkpoint advance, scripted through the real CLI) | M3 | poison present from v1.0 with plausible provenance is not detectable |
| T4a | Spoofed publisher identity | identity is the root-key fingerprint; local pin fails against any other key | `tests/adversarial/test_t4a_identity_spoof.py` | M1 | first-pin bootstrap is out-of-band |
| T4b | Key rotation abused/broken | root chain requires TUF-style cross-signing (root N+1 satisfies root N's threshold AND its own) | `tests/adversarial/test_t4b_rotation.py`, `tests/unit/test_root.py` | M3 | root-key compromise itself (see playbook, T4a/root-key drill below) |
| T4c | Compromised signing key keeps working | signed revocation in the root document; rejected everywhere, retroactively (D13/D24) | `tests/adversarial/test_t4c_revocation.py`, `tests/unit/test_manifest.py`, `tests/unit/test_timestamp.py` (revoked-key rejection cases) | M3 | window between compromise and revocation; log monitoring shortens it |
| T5a | Provenance/lineage forgery | lineage edges are digests inside release-key-signed attestations, bound to the manifest in both directions | `tests/unit/test_provenance.py` (parametrized single-field mutation) | M3 | publisher can lie about its own lineage (collapses to T3b) |
| T5b | Fake version history / equivocation | append-only Merkle log; inclusion + consistency proofs; checkpoints cross-checked across independent sources | `tests/adversarial/test_t5b_split_view.py`, `tests/unit/test_freshness.py` (`cross_check_checkpoints`) | M3 | equivocation across consumers who never compare checkpoints and share no source |
| T6a | Eclipse of a consumer | freshness hard-fails at TTL lapse (exit 30); metadata fetched from >=2 sources when configured (M4: `cross_check_timestamps` closes the timestamp half of this promise) | `tests/adversarial/test_t6a_eclipse_freeze.py`, `tests/adversarial/test_m4_chaos_scenario.py` (combined with T1+T2b), `tests/unit/test_freshness.py` (`cross_check_timestamps`) | M4 | availability loss under total eclipse; freeze within TTL |
| T6b | Sybil flooding | endpoint verification makes Sybils unable to poison; per-peer scoring, session blacklists, bounded retries | `tests/adversarial/test_t6b_sybil_exhaust.py` | M4 | wasted bandwidth, degraded availability |

## Property-based tests (mechanism-level, backing the table above)

| ID | Property | Test file | Milestone |
|---|---|---|---|
| PBT-MANIFEST-MUTATE | any valid signed manifest, any single-byte mutation of payload/signature → verification fails | `tests/property/test_pbt_manifest_mutate.py` | M1 |
| PBT-CHUNK-MUTATE | any chunk, any mutation (flip/truncate/extend) → rejected before write | `tests/property/test_pbt_chunk_mutate.py` | M1 |
| PBT-HISTORY-MONOTONE | any valid metadata history, any replayed prefix or reordering → rollback/staleness error | `tests/property/test_pbt_history_monotone.py` | M2 |
| (unnamed, informal) | Merkle tree Merkle math: any valid tree, any single-element mutation of a proof/leaf → verification fails | `tests/property/test_pbt_log.py` | M3 |
| (M4 parser fuzzing) | every named parser entry point (envelope, manifest, root, timestamp, checkpoint, provenance, snapshot, proof), fed structurally-arbitrary (not single-byte-mutated) input, never raises anything but a documented `VouchError` | `tests/property/test_pbt_fuzz_envelope.py`, `test_pbt_fuzz_documents.py`, `test_pbt_fuzz_snapshot.py`, `test_pbt_fuzz_proofs.py` | M4 |

M4's parser fuzzing pass (run at both the default 100-example budget and an
opt-in 1000-example "thorough" profile, `--hypothesis-profile=thorough`,
across several random seeds) found and fixed five real crash bugs beyond
the two found by pre-reading the code; see `DECISIONS.md`'s M4 section
for each. None were reachable by a network attacker without holding a
currently-authorized signing key or, in the transparency-log proof case,
controlling a configured peer's responses; all are now fail-closed.

## Compromise-playbook drills (03_SECURITY_AND_ACCESS.md section 5.6)

| Playbook | Test | Milestone |
|---|---|---|
| Release key compromise (revoke → rotate → resign-all → advisory) | `tests/e2e/test_m3_ceremony.py` (recovery) + `tests/adversarial/test_t4c_revocation.py` (attacker's-perspective half) | M3 |
| Timestamp key compromise (revoke → rotate → reissue) | `tests/e2e/test_m4_compromise_playbooks.py::test_timestamp_key_compromise_playbook` | M4 |
| Root key compromise (out-of-band re-pin to a new identity) | `tests/e2e/test_m4_compromise_playbooks.py::test_root_key_compromise_playbook_repin_to_new_identity` | M4 |

The root-key drill found and fixed a real bug in the recovery path itself
(`trust_store.add_pin` didn't clear the old identity's rollback/
equivocation state on re-pin); see `DECISIONS.md`.

## The chaos scenario (03_SECURITY_AND_ACCESS.md section 9)

`tests/adversarial/test_m4_chaos_scenario.py` combines T1 (tampering
mirror) + T2b (stale mirror) + T6a (eclipse peers) simultaneously against
one fetch: Variant A proves an honest peer surviving among all three
attacks at once still yields a correct, successful fetch; Variant B
proves that once no honest peer remains, the fetch fails loud (never
silent, never wrong data), consistent with every constituent threat's own
individual proving test.

## Explicitly out of scope / not tested

- A standalone mirror daemon (D10; noted as a strictly post-M4, Rust-
  revisit option; nothing in the current one-shot `mirror sync`/`mirror
  serve` CLI commands changes).
- Concurrent (as opposed to sequential fallback) multi-source metadata
  resolution and equivocation checking, a deliberate M2/M3/M4-consistent
  simplification (Open Decision 6 in the M2 plan; carried through
  `cross_check_checkpoints` and `cross_check_timestamps`).
- Root document same-session cross-source equivocation checking
  (`DECISIONS.md` D36): TUF-style cross-signing already makes a
  divergent-but-valid root history require actual root key compromise, a
  scenario no code-level mechanism recovers from.
- Anonymity/privacy: mirrors observe who fetches what; not attempted
  (03_SECURITY_AND_ACCESS.md section 8).
- Local host bit-rot / tampering after materialization, between `verify
  --deep` runs (assumption A; out of scope by design).
- Denial of service beyond what T6a/T6b already characterize (a
  sufficiently resourced attacker can always deny service; the guarantee
  is that denial is loud, never traded for silently-wrong data).
