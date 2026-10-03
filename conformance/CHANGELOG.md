# Changelog

## Unreleased

## v0.6.1 - 2026-09-26

### Changed

Each change here refuses input that 0.6.0 accepted, so a record that passed on
0.6.0 can fail on 0.6.1. The first two are the ones producers will hit.

- **Duplicate member names are refused at load (exit 2) (#124).** This covers
  records, anchor receipts and policy manifests. `json.loads` kept the last
  value, the signature was checked over it, and a consumer whose parser keeps
  the first read a value no signature covered. RFC 8785 is defined over
  I-JSON, which forbids duplicates. A producer that emits a repeated key now
  gets a load error instead of a report.
- **TR-SIG accepts one spelling of `signature` and `cnf.jwk.x` (#124):**
  unpadded base64url. The standard alphabet, `=` padding, characters outside
  the alphabet and nonzero trailing bits were all accepted before, and since
  the signature sits outside the body it signs, each was a different record
  that still verified. A record signed with padded or standard base64 now
  fails TR-SIG.
- Digest, `subject` and receipt hash checks use `fullmatch` (#124). Python's
  `$` matched before a trailing newline, so `sha256:<64 hex>
` passed
  TR-RTE-002, TR-SCA-002, TR-TXN-001, TR-POL-001 and TR-ENV-003.
- TR-ANC-002 refuses claims outside the anchor-leaf profile of
  registry-anchor-v1 section 1: non-integer numbers and integers outside the
  safe range, whose leaf bytes differ between implementations (#124).

### Fixed

- Untrusted input no longer reaches the CLI as a traceback (#124): a non-ASCII
  `runtime.nonce` (`TypeError` from `hmac.compare_digest`), a lone surrogate in
  an object key (`UnicodeEncodeError` from `rfc8785`), a non-string
  `transparency` in `report --html`, and non-UTF-8, over-deep or unreadable
  input files. Each is now a finding or a load error.

### Internal

- ClusterFuzzLite targets over the record loader and every module, the
  signature path and the anchor receipt, run on pull requests and nightly
  (#124).
- The maintainer approval gate drops the unused `statuses: write` scope and
  runs with `contents: read` and `pull-requests: read` (#125).

## v0.6.0 - 2026-09-25

### Changed

- **Level 2 now verifies the anchor instead of parsing its URI (#79, closes #70).**
  `TR-ANC-001` only ever checked that `transparency` was a well-formed https URI,
  so any record could clear Level 2 by typing a string. The new `TR-ANC-002`
  replays the record's RFC 9162 inclusion proof against the committed Merkle
  root, offline and standard library only. The receipt is passed with the new
  `--receipt` option on `verify` and `report`; without one, `TR-ANC-002` fails.
  A record that passed Level 2 on 0.5.1 without a receipt will fail it on 0.6.0.

### Added

- **`TR-ENV-005`: `cnf.jwk` must carry no private key material (#98).** A record
  carrying its own private key (`d` and the other private JWK members) passed
  the whole suite, because `TR-ENV-004` only checked that `kty` was present. The
  packaged `schemas/trace-claim.json` copy is closed the same way. This is the
  trace-tests half of GHSA-vc4p-h84j-7qxj; trace-spec#296 fixed the other two
  schema copies.
- **`TR-APR`: appraisal well-formedness at every level (#82, closes #63).**
  `appraisal` is required by the schema and no module read it. Five codes now
  check the status enum, the verifier URI and appraisal timing. No network, no
  filesystem, no resolver.
- **`TR-POL-003` resolves `policy_uri` against `bundle_hash` (#69).** A
  `policy_resolver` callable on `runner.run` and a `--policy-dir` option on the
  CLI supply the policy bytes; the check compares their digest to the record.
- Machine-readable execution accounting in CLI JSON reports for the bounded
  `TR-APR-001`, `TR-POL-003` and `TR-SCA-002` pilot (#93). Accounted findings
  and accounting come from one immutable execution snapshot; unreconciled
  accounting is rejected on that path, the operational policy-correspondence rule
  is separated from supporting schema locators and all carry value digests for
  comparison against the referenced trace-spec bytes, scheduler non-execution
  carries a reason, and existing verdict policy and CLI exit behavior are unchanged.

### Fixed

- `TR-SIG` reports a record with no RFC 8785 canonical form (an integer outside
  the safe range, a non-finite float) as a finding instead of raising and ending
  the run (#86).
- Malformed arrays or objects in `policy.enforcement_mode`, `runtime.platform`,
  `build_provenance.slsa_level` and `cnf.jwk.kty` raised
  `TypeError` before the runner could return findings; boolean SLSA levels
  passed as `1` and `0`. Both are now findings (#85, closes #84).

### Internal

- The finding to level failure decision lives in one place, read by both the
  CLI and the JSON report (#88).
- Release and CI actions pinned to SHAs with a token permissions floor (#97);
  CI installs from hash-pinned locks (#101); actionlint and a test-environment
  guard added (#100).

## v0.5.1 — 2026-08-22

- Level 1 and Level 2 verification now requires a verifier-issued challenge via
  `--expected-nonce` and checks it against the signed `runtime.nonce` using
  constant-time comparison. Previously nonce binding existed only as an
  assertion over the repository's own pytest fixture; the shipped runner and
  CLI could report conformance for a fresh signed record containing an
  attacker-chosen or replayed nonce.

## v0.5.0 — 2026-08-09

### Added

- **`trace-tests report`: conformance results as an artifact somebody can forward.** `verify` answers a question for whoever ran it; a pass/fail in a terminal is useless to an auditor, a counterparty or an acquirer. The new command emits self-contained HTML, a machine-readable JSON document (`schema: agentrust-io/trace-tests/report/1`), and an SVG level badge.

  It runs every level up to `--max-level` instead of one, because the answer a reader needs is the highest level the record reaches, not whether it cleared the level the person running the tool happened to choose. `--fail-under N` gates CI on a level; without it the command exits `0`, since producing an artifact and enforcing a threshold are different jobs.

  **The report states that it is not evidence.** It is unsigned HTML describing one run of one suite version, and anyone can edit it, so every report carries the record's digest, the suite and authoring-library versions, and the command to reproduce the result — and tells a reader who does not trust the sender to go check the record instead. A conformance report that looks authoritative and cannot be checked is the same shape of thing as a control plane writing its own log, which is the problem this project exists to fix.

  Self-contained by construction: no scripts, no external CSS, no fonts, no badge service. A badge served from someone else's infrastructure would add a dependency to an artifact whose whole point is needing none. A test asserts the HTML fetches nothing.

  The HTML and the JSON are rendered from one assembled structure so they cannot disagree about the verdict, and unverified findings count as failures from Level 1 up exactly as they do in `verify`.

## v0.4.1 — 2026-08-03

### Fixed

- **`--version` reported the wrong version.** `__version__` was a second hardcoded literal alongside `pyproject.toml` and never moved, so it sat at `0.2.0` through both the 0.3.0 and 0.4.0 releases: `trace-tests --version` printed `0.2.0` from a 0.4.0 install while `importlib.metadata` correctly returned `0.4.0`. It is now read from installed distribution metadata, so there is one source of truth and the value cannot fall behind a release again.

  This mattered more than a wrong string usually would. The v0.2 profile cutover shipped in 0.4.0, and a 0.2.x suite rejects every v0.2 record, so `--version` is exactly the command someone runs to work out whether their suite matches their producer. It was the one command that could not answer.

## v0.4.0 — 2026-07-28

### Changed

- **BREAKING: the suite now conforms to TRACE v0.2.** `TR-ENV` requires the profile `tag:agentrust-io.com,2026:trace-v0.2` and fails a record carrying the v0.1 identifier. The v0.1 URI named `agentrust.io`, a domain this project never controlled, which RFC 4151 does not permit for a tag URI; see agentrust-io/trace-spec#107. Nothing else about the record format changed, so a producer migrates by updating the profile string and bumping `agentrust-trace` to 0.5.0.

  This is a deliberate cutover rather than dual acceptance: a conformance suite that passed both identifiers would certify records minted under a domain we do not own. A v0.1 record is checked with the 0.3.x releases of this suite, which stay published.

- Registry, verifier, and documentation hosts moved from `agentrust.io` to `agentrust-io.com`.

## v0.3.0 — 2026-07-21

- `azure-cvm-sev-snp` platform accepted (`runtime.platform`): Azure confidential VMs run SEV-SNP behind a Hyper-V paravisor (vTPM-rooted). Added to the bundled schema enum and the TR-RTE valid-platform set so Azure TRACE records pass conformance. Matches `agentrust-trace>=0.4`.

## v0.2.0 — 2026-06-19

- DID subject support: `subject` now accepts `did:` URIs in addition to `spiffe://`.
- Embedded signature verification: plain TRACE records signed with `agentrust-trace sign_record()` are now cryptographically verified at all levels.
- SLSA Level 0: `build_provenance.slsa_level: 0` is now valid for software-only / development records.
- Software-only platform: `runtime.platform: "software-only"` accepted at Level 0.
- Private key leak detection: TR-SIG now fails records that embed a private key (`d` member) in `cnf.jwk`.

## v0.1.0 — 2026-05-01

- Initial release with 7 test modules: TR-ENV, TR-SIG, TR-RTE, TR-POL, TR-TXN, TR-ANC, TR-SCA.
- Conformance levels 0, 1, 2.
