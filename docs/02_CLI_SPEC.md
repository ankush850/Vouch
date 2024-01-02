# Vouch: Frontend Spec

Status: v1 (M1-M4) implemented; this document reflects the design as built.
Date: 2026-07-13

## 1. Surface choice: CLI-first

The surface is a single binary-style CLI, `vouch`. Justification against the users and the threat model rather than taste:

All three personas live in terminals and pipelines. Publishers release from build machines and CI; consumers pull inside training scripts, Dockerfiles, and CI gates, where the whole point is a deterministic exit code; mirror operators run daemons. None of the v1 use cases has a step that benefits from a pointer.

A GUI or web frontend for a trust tool is attack surface. A web viewer that renders untrusted metadata (artifact names, provenance fields, peer URLs are all attacker-influenced strings) imports an injection class into the component whose only job is to be trustworthy. The CLI treats those strings as data, escapes nothing into a DOM, and keeps the trusted computing base equal to the verifier plus a terminal.

Verification results must be consumable by machines first. Human-readable output is a rendering of the same structured result that `--json` emits, so scripting is never second-class.

A read-only web viewer for provenance graphs is a plausible later addition and is explicitly out of scope for v1; `vouch provenance --dot` exports Graphviz for anyone who wants a picture today.

## 2. Design principles

Verified by default, and only. No flag, environment variable, or config key produces an unverified artifact; the spec deliberately defines no `--no-verify`.

Loud, specific failure. Every failure prints what check failed (V1 through V10, matching the security document), the evidence location, and the remediation if one exists. Deterministic exit codes per the shared table.

Human plus machine. Every command accepts `--json`; human output is derived from the same result object. `--quiet` suppresses progress; `NO_COLOR` and non-TTY output disable color; color never carries meaning alone (pass/fail words are always printed).

Secrets hygiene. Passphrases via prompt or `--passphrase-fd`, never argv or environment. Key files are created 0600.

## 3. Command surface

| Persona | Commands |
|---|---|
| Publisher | `keygen`, `publisher init`, `publisher delegate`, `publish`, `rotate`, `revoke`, `origin serve`, `log show` |
| Consumer | `trust add / list / reset`, `fetch`, `verify`, `provenance`, `diff`, `status` |
| Mirror operator | `mirror sync`, `mirror serve` |

Reference forms: publishers are local pin names; artifacts are `NAME/ARTIFACT@VERSION`.

## 4. Publisher experience

One-time setup, then publishing is two commands (a PRD success criterion):

```
$ vouch keygen --role root --out /media/airgap/acme-root.key      # offline machine
new root key: b3:9f2a11c4...  (fingerprint to distribute out-of-band)

$ vouch publisher init acme-lab --root-pub acme-root.pub
$ vouch keygen --role release
$ vouch keygen --role timestamp
$ vouch publisher delegate --role release --key rk-2026-07.pub    # prints root-doc
$ vouch publisher delegate --role timestamp --key tk-2026-07.pub  # update to sign
                                                                    # on the offline
                                                                    # machine, then import
```

Publishing a release:

```
$ vouch publish ./bert-tiny-out \
    --name bert-tiny --version 1.2.0 --type model \
    --base acme-lab/bert-base@2.1.0 \
    --dataset acme-lab/sst5@1.4.2 \
    --code git+https://github.com/acme/train@ab12cd3
hashing 3 files, 5.1 GiB ... done (4.9 GB/s, 1319 chunks)
manifest b3:77e1... signed (release key rk-2026-07)
provenance b3:03bd... signed (2 materials, 1 code ref)
log: leaf 141 appended, checkpoint signed (tree size 141)
snapshot + timestamp reissued (seq 141, expires in 24h)
published bert-tiny@1.2.0

$ vouch origin serve --store ~/.vouch-origin --bind 0.0.0.0:7433
```

Rotation and revocation print the exact ceremony steps, since part of each requires the offline root:

```
$ vouch revoke b3:5cc0... --reason "laptop stolen"
prepared root doc v4: revokes b3:5cc0..., adds nothing
ACTION REQUIRED: sign root-v4.json with the offline root key, then run
  vouch publisher import-root root-v4.signed.json
after import: re-sign current manifests with a new release key:
  vouch publish --resign-all --key rk-new.pub
```

## 5. Consumer experience

Pinning (one-time per publisher), then fetching is one command:

```
$ vouch trust add acme-lab b3:9f2a11c4... \
    --mirror https://mirror1.example.org --mirror https://cdn.acme.dev
pinned acme-lab -> b3:9f2a11c4... (2 mirrors)
```

Fetch, the flagship flow. The checklist lines map one to one onto V1 through V10:

```
$ vouch fetch acme-lab/bert-tiny@1.2.0
pin        ok  acme-lab -> b3:9f2a11c4...                      [V1]
root       ok  chain v1->v3, no expiry, 0 revocations apply    [V2,V3]
freshness  ok  timestamp seq 141, expires in 21h (2 sources)   [V4]
snapshot   ok  b3:e0ff...                                      [V5]
manifest   ok  b3:77e1... sig rk-2026-07, name/version match   [V6]
log        ok  inclusion leaf 141, consistency 139 -> 141      [V7]
fetching 5.1 GiB in 1319 chunks from 3 peers
  [##########........] 61%  842 MiB/s
  warn: mirror1.example.org chunk 412 digest mismatch,
        blacklisted for session, refetched from cdn.acme.dev   [V8]
chunks     ok  1319/1319 verified                              [V8]
assembly   ok  3 files, artifact digest b3:77e1...             [V9]
provenance ok  2 materials, code ref recorded                  [V10]
materialized ~/.vouch/verified/acme-lab/bert-tiny/1.2.0
$ echo $?
0
```

Verify a file that arrived some other way:

```
$ vouch verify ./weights.safetensors --ref acme-lab/bert-tiny@1.2.0
manifest   ok  b3:77e1... (cached)
content    FAIL file digest b3:12f9... expected b3:77e1... (first bad chunk: 87)
result: NOT the signed artifact. evidence: ~/.vouch/quarantine/20260713T0912-40/
$ echo $?
40
```

Provenance and dataset diff:

```
$ vouch provenance acme-lab/bert-tiny@1.2.0
acme-lab/bert-tiny@1.2.0  b3:77e1...  [verified]
├── base-model  acme-lab/bert-base@2.1.0  b3:5aa9...  [manifest]
│   └── dataset  acme-lab/c4-mini@0.9.0  b3:aa17...  [recorded]
├── dataset  acme-lab/sst5@1.4.2  b3:03ab...  [verified]
└── code  git+https://github.com/acme/train@ab12cd3  [recorded]

$ vouch diff acme-lab/sst5@1.4.1 acme-lab/sst5@1.4.2
records: 66,120 -> 66,349   added 232  removed 3  modified 0
added   train.jsonl: 229 records (indices 65891..66119) digests listed with --json
removed train.jsonl: 3 records  b3:71c2... b3:8be0... b3:930d...
note: byte-identical duplicates among added records: 0
```

`vouch status` summarizes trust state per pinned publisher: root version, timestamp age, checkpoint size, count of verified artifacts, and any artifacts flagged `revoked` pending re-signed manifests.

## 6. Mirror operator experience

```
$ vouch mirror sync acme-lab --from https://origin.acme.dev:7433 --store /srv/vouch
synced: root v3, timestamp seq 141, snapshot, 2 manifests, log(141), 2,204 chunks (8.3 GiB)
note: mirror verified content on ingest (advisory only; consumers never rely on this)

$ vouch mirror serve --store /srv/vouch --bind 0.0.0.0:7433
serving 8.3 GiB, 2 publishers' content is whatever synced; no keys loaded
```

No credentials exist to configure, which is itself part of the spec: the help text for `mirror` states that mirrors are untrusted by design and cannot affect what consumers accept.

## 7. Failure UX

Each failure class has a fixed shape: FAIL line with the check ID, one evidence line, one remediation line. Four canonical examples:

Tampered chunk with no honest source left (T1 taken to completion):

```
chunks     FAIL chunk 412 digest mismatch from all 2 configured peers      [V8]
evidence:  ~/.vouch/quarantine/20260713T0931-40/
remedy:    add an honest mirror (vouch trust add ... --mirror URL) or retry later
$? = 40
```

Stale or frozen metadata (T2b, T6a):

```
freshness  FAIL newest obtainable timestamp expired 26h ago (seq 141)      [V4]
this can mean the publisher stopped publishing OR your peers are withholding
remedy:    add an independent mirror; do not use the stale copy, vouch will not
$? = 30
```

Revoked key (T4c):

```
manifest   FAIL signature by revoked key b3:5cc0... (revoked 2026-06-30,
           reason: compromise)                                             [V3/V6]
remedy:    none on the consumer side; the publisher must re-sign this release
$? = 42
```

Unknown publisher (T4a):

```
pin        FAIL no pin for "acme-lab"                                      [V1]
remedy:    obtain the fingerprint from an out-of-band channel, then
           vouch trust add acme-lab <fingerprint>
$? = 43
```

## 8. Machine interface

`--json` emits one result object; the human output above is a view of it:

```json
{
  "vouch": "result/v1",
  "op": "fetch",
  "ref": "acme-lab/bert-tiny@1.2.0",
  "ok": false,
  "exit_code": 40,
  "checks": [
    {"id": "V1", "ok": true},
    {"id": "V8", "ok": false, "detail": "chunk 412 digest mismatch",
     "peer": "https://mirror1.example.org", "expected": "b3:aa9c...",
     "actual": "b3:41d0...", "evidence": ".../quarantine/20260713T0931-40/"}
  ],
  "artifact": {"digest": "b3:77e1...", "seq": 14},
  "timing": {"wall_s": 41.2, "bytes": 5477632000}
}
```

Exit codes are the shared table from the security document: 0, 2, 20, 21, 30, 31, 40, 41, 42, 43, 44, 45, 70. Progress and warnings go to stderr; the result object goes to stdout; logs are line-oriented `ts level check peer detail`.

## 9. Configuration and state

```toml
# ~/.vouch/config.toml
[consumer]
parallel_streams = 8
timestamp_max_age_hours = 24     # advisory display only; enforcement uses the
                                 # publisher-set expiry in the timestamp itself

[[publisher]]
name = "acme-lab"
fingerprint = "b3:9f2a11c4..."
mirrors = ["https://mirror1.example.org", "https://cdn.acme.dev"]
```

Environment: `VOUCH_HOME` relocates the store; `NO_COLOR` respected. State paths are the storage layout from the architecture document; the config file never contains key material or verification toggles.

## 10. Out of scope for the v1 surface

Web or TUI provenance viewer (DOT export covers it), shell completions (cheap, slated as an M4 nicety), interactive prompts beyond passphrases (everything is flag-driven so CI never hangs), and any command that would download without verifying, which is excluded by design rather than deferred.
