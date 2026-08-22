# Changelog

All notable changes to the TRACE specification will be documented here.

Format: [Semantic Versioning](https://semver.org/). Spec versions follow `MAJOR.MINOR.PATCH`:
- **MAJOR**: breaking changes to wire format or required Trust Record fields
- **MINOR**: new optional fields, new platform profiles, new conformance levels
- **PATCH**: editorial fixes, clarifications, non-normative additions

---

## [Unreleased]

### Added

- **Record-signing key revocation is anchored to transparency-log entry ordering, not to `iat`.** New spec section 3.2.3 defines the `TraceRevocation/1.0` claim type: a record from a revoked key is valid if and only if its SCITT inclusion entry ID is at or below `last_valid_entry_id` on the log the statement names. The intuitive time-based rule cannot work, because a compromised record-signing key also signs the `iat` it would be judged against, so an attacker backdates the record and the rule passes. Entry IDs are monotonic and bound to the Merkle structure, so ordering survives the compromise a timestamp does not.

  Distribution keeps section 3.3's no-callback property: statements are anchored in the same log as the records they govern, and verifiers cache a signed bundle carrying `valid_until`. An expired bundle is not a pass, and a verifier with none reports that it performed no revocation check rather than reporting an affirming appraisal. A revocation statement MUST be signed by a key above the revoked one in the section 3.2.1 hierarchy, or by a recovery key with an independent compromise domain, because a statement the compromised key could sign for itself is a tool for whoever stole it. Records with no usable inclusion entry ID fall back to binary revocation, which is the existing behaviour. Schemas: `schema/trace-revocation.json`, `schema/trace-revocation-bundle.json`. Resolves [#67](https://github.com/agentrust-io/trace-spec/issues/67).

  Section 3.2.1 previously required verifiers to "consult current revocation status at verification time", which contradicted the offline-verification property in the same document. It now points at 3.2.3.
- **A verification profile is proposed for the `delegation` block, with the conformance material to argue it against.** The block is normative in v0.2 and nothing says what a verifier does with a chain of them: `spec/trace-v0.2.md` never mentions `parent_record_hash` or `credential_id`, and the one descriptive sentence in `docs/schema.md` leaves every operative term open, so two conforming implementations can agree on nothing. [`docs/rfcs/a2a-delegation-profile.md`](docs/rfcs/a2a-delegation-profile.md) proposes ten rules over the fields that already exist — no schema change — and `examples/delegation-link/` carries 23 vectors that score an implementation against them. Three forks in the current text had to be settled before any vector could be written, and each is stated with the reason rather than assumed: the digest covers the complete parent record including its signature, because a digest of the signed body alone does not bind the parent's signer; there is no cycle rule, because a delegation cycle is a hash collision and the reachable analogue is an unbounded chain, which is what the depth bound is for; and a link naming a digest algorithm the verifier cannot compute makes the chain unverifiable rather than invalid, which is the delegation-surface instance of the semantics already merged in `docs/verification.md`. Nothing here binds an implementation until the profile is adopted. Targets the v0.3 A2A profile named in [`ROADMAP.md`](ROADMAP.md).

- **`build_provenance` now declares verification depth.** A new optional `provenance_depth` (`surface`, `builder`, `transitive`) says how far down the supply chain the issuer claims to have walked, and a new optional `appraisal.provenance_depth_verified` records how far the verifier actually walked. Spec section 3.3 step 7 previously left three stopping points equally conformant, so two verifiers could reach opposite conclusions on the same record with no way to say why. Both fields are optional and a record omitting `provenance_depth` is read as `surface`, so existing records keep their meaning. Evidence that does not resolve and evidence that resolves and contradicts the record are separate outcomes: the first downgrades the recorded depth and names what was missing, the second fails the appraisal and cannot be downgraded away. Resolves [#50](https://github.com/agentrust-io/trace-spec/issues/50).

### Security

- **Release gates now fail closed.** CodeQL analysis failures block instead of being ignored. Before trusted PyPI publication, clean virtual environments install and verify both the built wheel and source distribution outside the checkout, checking tag/version identity, packaged schema resources, signing and verification, and rejection of unknown security fields.

### Fixed

- **Local test runs now always exercise the checkout.** Pytest prepends `src` to its import path, and a regression test asserts that `agentrust_trace` resolves to the repository source. A stale installed wheel can no longer shadow current security fixes and produce misleading failures or passes.

### Fixed

- **The confirmation key must now match the trusted signing key.** `verify_record()` compares the RFC 7638 thumbprints of `cnf.jwk` and the caller-supplied trusted key before accepting the signature. A trusted signer can no longer produce a record that verifies under one key while naming another key for downstream proof-of-possession checks.

- **`verify_record()` now enforces the canonical v0.2 JSON Schema.** A cryptographically valid signature no longer causes an object with unknown fields, missing required claims, or invalid nested values to be accepted as a verified TRACE record. Schema failures are surfaced as `ValueError` with the failing field path.

### Fixed

- **Future-dated records no longer create an unbounded freshness window.** `verify_record()` now rejects an `iat` later than the verifier's clock plus `max_future_skew_seconds` (default 5 minutes), independently of the maximum-age check. The v0.2 freshness requirements and verification tutorial document both bounds.

## [0.9.0] — 2026-08-09

### Documentation

- **The security policy now describes the software that is actually released.** It puts the Python signing and verification APIs, schemas, adapters, packaging, and release automation in scope; lists TRACE v0.2 and `agentrust-trace` 0.x as supported; and marks the superseded v0.1 profile unsupported.

## [0.9.0] — 2026-08-09

### Added

- **`spec/content-marking-v1.md` and `agentrust_trace.content_marking`: bind a marked asset to the execution that produced it.** EU AI Act Article 50(2) and 50(4) have been in force since 2 August 2026 and are the only AI Act obligations that bite this year. One C2PA assertion, `com.agentrust-io.trace`, carries a hashed reference to the Trust Record for the execution that produced the asset.

  **The document opens with what this does not do**, because the temptation to overclaim here is strong. It does not stop anyone stripping the mark: removing a C2PA manifest from a file is trivial and nothing here changes that. It is not watermarking. It does not make a deployment compliant. What it buys is narrower and real: a mark that *is* present becomes checkable against a hardware-rooted claim instead of being an unverifiable label, and in a channel that requires marks an absent one is detectable.

  Three separate things must be checked and the assertion merges none of them: the C2PA signature says the assertion was in the manifest when the asset was signed, the TRACE signature says the execution happened as described, and the hash says the record being pointed at is the one the signer meant. A verifier that checks one of the three has checked a third.

  `build_assertion()` takes the **exact bytes** that will be served rather than a record object, because a hash over a re-serialized dict is a hash of bytes nobody will fetch; a test pins that `indent=2` alone breaks the binding. `verify_assertion()` has no signature-only path: `record_bytes` is a required parameter, since an assertion whose hash was never checked is a URL in a file.

  17 tests.

### Added

- **`enforcement_mode: "declared"`.** The three existing modes all assert that *something evaluated the policy*: `enforce` acted on the result, `advisory` did not, `silent` acted with the log lines suppressed. `declared` asserts less — the policy is named and bound into the signed record, and nothing evaluated it.

  That is not a corner case, it is the common one. An agent framework has no policy engine, so a record built by observing a LangChain or LlamaIndex run has a policy the operator declares and no evaluation of it anywhere. With three values, such a record had to claim an evaluation that never happened; both framework adapters refused to default the field and documented the overstatement instead, which is honest and still leaves every framework record marginally untrue.

  `declared` is the weakest value and is never a default. A producer that evaluates policy MUST NOT use it, and a consumer MUST NOT read it as evidence that any rule was checked. A verifier appraising for enforcement SHOULD treat it as it treats an absent enforcement claim.

  Additive to a closed enum in both the model and the JSON schema, so unknown values are still rejected. Same one-directional consequence as `origin`: a verifier older than this release rejects a record carrying `declared`.

## [0.8.0] — 2026-08-09

### Added

- **`agentrust_trace.provenance`: build, sign and verify MCP Server Provenance Records.** Step 2 of the sequence, implementing `spec/server-provenance-v1.md`. In the SDK rather than in cMCP, so a publisher can produce a record without adopting a runtime, which is the only way the format reaches an ecosystem that will not adopt one.

  **`check_tool_catalog()` is a separate call on purpose.** Verifying the signature proves a document is internally consistent and signed by a key you trust, which is exactly what an attacker holding a stolen publisher key can produce. What they cannot do is make the server in front of you offer the tools their record describes. That comparison needs something `verify_record()` does not have — what the server said to *you* — so it is its own obvious call rather than a flag, and it raises its own exception type so a consumer can tell "bad document" from "wrong server".

  The builder refuses records that cannot mean anything: an identity with neither artifact nor endpoint, a `tee-attested` record with no evidence, evidence attached to a kind that does not claim it (a reader would take it as an attestation that was made), a publisher that is a display name rather than a resolvable DID or SPIFFE URI, and an endpoint URL with no key digest, since a URL alone is not an identity.

  `verify_record()` requires a trusted key and never takes one from the record. Verifying a document against a key it supplies proves only that it is internally consistent, which is what a forgery is.

  24 tests, including the one the format exists for: a perfectly valid signature over a description of a different server still fails the catalog check.

### Added

- **`spec/server-provenance-v1.md`: a signed statement about an MCP server.** cMCP enforces policy at the call boundary and can say nothing about whether the server on the other end is what it claims. Its catalog answers that locally — approved definitions, a measured catalog hash, a pinned TLS fingerprint — but every part of that is operator-asserted, so nothing one operator learns is usable by the next.

  The format carries the same shape of honesty as the `origin` block: a closed `kind` (`publisher-asserted`, `observer-attested`, `tee-attested`) because the interesting fact is never that provenance exists but who is asserting it, and an explicit rule that a verifier MUST NOT treat absence as any of them.

  Identity is `artifact`, `endpoint`, or both, with the record saying which. A URL is the obvious handle and the worst candidate: it moves, it is per-deployment, and two operators running the same server produce different ones. `artifact.digest` covers the entrypoint rather than the interpreter, for the reason the stdio work found: every interpreted server on a host shares one interpreter digest, so a pin over it matches a completely different server.

  The tool-catalog hash covers name, description and input schema. Description is in deliberately — a tool whose description changes from "search the docs" to "search the docs and email results to the address in the query" is exactly the rug-pull the hash exists to catch, and a hash over names alone misses it.

  Three things are stated as out of scope rather than hand-waved: key distribution for `publisher` (a PKI question this format would only pretend to solve), whether a server is any good (the moment a provenance format scores servers, its publisher becomes the party everyone must trust), and what the code does at runtime (provenance narrows what code you are talking to, nothing more).

### Fixed

- **The packaged schema had drifted from the normative one, and a DID subject was the casualty.** `validate_json()` loads `src/agentrust_trace/schema/trace-v0.2.json`, while the spec, README and CONTRIBUTING all point a reader at `schema/trace-claim.json`. The two disagreed in three places, so the schema someone reads was not the schema their record was checked against. The visible consequence: the root file and `models.py` both accept a `did:` subject, the packaged copy still required `^spiffe://`, so `agentrust_trace.validate_json()` rejected a subject form the specification permits. Also resynced: the `slsa_level` description, and the root file's `$id`, which still said `trace-v0.1.json` on a schema whose `eat_profile` const is v0.2.

  `tests/test_validate.py` now compares the two as parsed JSON on every run, so the next drift fails instead of shipping. Compared parsed rather than byte for byte because the two files differ in line endings by long-standing accident, which changes nothing about how either validates a record.

- **A 0.6.0 changelog entry was filed under 0.5.1.** The `verify_record()` profile-cutover enforcement shipped in 0.6.0; its entry landed in the 0.5.1 section, next to the cutover declaration it implements, which left 0.5.1 with two `### Fixed` blocks and 0.6.0 with no entry for a behaviour change. Moved, with its two internal cross-references corrected to match where it now sits.

## [0.7.0] — 2026-08-08

### Added

- **`origin` (optional object): who assembled this record, when it was not the runtime that ran.** `{kind, producer, source_event_id, ingested_at}`. Additive and backward compatible; existing records without it stay valid, and absence means `self`. Same shape of change as `delegation` in 0.4.0, under the same v0.2 profile URI.

  It exists because `runtime.platform: "software-only"` is ambiguous, and the ambiguity is about to matter. It is the honest value for a dev-mode record, where nothing attested the execution, and for a record transcribed from a third-party control plane, where the party asserting the evidence also wrote the log. Those are different claims, and a consumer weighing a record could not tell them apart from `platform` alone. `kind` is a closed set (`self`, `third-party-control-plane`, `log-import`) rather than free text, because the value of the field is that a verifier can key on it.

  **A record whose `kind` is not `self` MUST carry `runtime.platform: "software-only"`,** enforced in the model and in `schema/trace-claim.json` via `if`/`then`, so a validator that never loads the Python still rejects it. An importer holding someone else's log has no quote to present, so a hardware platform there is untrue rather than stronger. It is also exactly what an adapter produces by starting from a hardware example and editing the fields it understood, which is why it is a MUST and why it is tested from both directions.

  The block launders assurance in neither direction. Naming your producer does not make unattested evidence attested, and a record with a verified hardware quote is what it is whether or not it says `origin: self`.

  Spec §3.1.1, `docs/schema.md`, both schemas, 11 tests.

- **`spec/registry-anchor-v1.md`: the registry anchor and inclusion-proof format is now public (#111).** The format was already normative and already written so a conforming verifier could be built from it alone, but it lived in `trace-registry`, which is private. The effect was that the one document an external verifier needs was the one they could not read, and an inclusion proof nobody outside can check is not transparency. It is published here, in the public spec home, as @l33tdawg proposed in the discussion that raised this.

  §0 leads with the trap, because it is the one that costs an implementer a day and gives no useful error: TRACE canonicalizes with **RFC 8785 (JCS)** for *signing* and with **sorted-key JSON** for the *anchor leaf*. The two agree on ASCII-only records with integer numbers, which is most records, which is exactly what makes assuming JCS at the leaf dangerous.

  §8 states conformance, including the requirement that the append-only property be externally checkable rather than asserted. An operator that issues verifiable proofs but publishes nothing an outsider can audit is running a log, not a transparency log.

### Fixed

- `docs/schema.md` described `transparency` as required with an empty string for unanchored records. It has been optional below Level 2 since 0.5.1, and `""` is rejected.

- **Four documents told readers to send signed records to a domain this project does not own.** `docs/integration/agt.md`, `docs/integration/cmcp.md`, `docs/trust-levels.md` and `docs/verification.md` still named `registry.agentrust.io`, which resolves to third-party parked addresses. This is the same defect the v0.2 profile cutover fixed in the identifier, missed in the prose. Moved to `registry.agentrust-io.com`, which is what the SDK's adapters already emit. The v0.1 spec keeps its original values; it is a superseded document and a record of what was published.

- **The anchoring tutorial documented an API that does not exist.** It instructed readers to POST signed Trust Records to a SCITT HTTP endpoint at the parked domain above and to read a `receipt_uri` from the response. There is no such endpoint. Rewritten against the actual mechanism: submit to staging, retrieve an inclusion proof, and verify that proof yourself against the published entry. It also still described `transparency` as a required string, which 0.5.1 changed. The page carries a dated note saying what it used to say, because anyone who built against it deserves to know nothing they sent was received.

### Changed

- **The spec, the README and the roadmap named three different standards homes between them.** §6.1 proposed splitting TRACE between CoSAI and the Linux Foundation entity hosting MCP; the README said "Targeting AAIF"; neither is where this is going. TRACE is being formed at the Linux Foundation as its own series, "TRACE Specification, a Series of LF Projects, LLC" (see #127). §6.1 is rewritten, the README line is corrected, and §7 Q1 is marked resolved rather than deleted so a reader tracking it can see how it landed.

- **§4.1 described the MCP and A2A profiles as "targeted for v0.2" in the v0.2 document.** Neither shipped in v0.2. Both are now stated as targeted for v0.3, and the A2A entry says what did land: the `delegation` link block, as the foundation the binding rules will attach to. §7 Q6 (A2A timing) is marked resolved, since A2A stabilizing at v1.x was the blocker it asked about.

- **§7 was headed "These need input before v0.2".** Now v1.0. No normative text, schema, or record field changed.

## [0.6.0] — 2026-08-07

### Fixed

- **`__version__` reported the wrong number for four releases.** It was a literal that drifted from `pyproject.toml` at #36 and was never corrected, so v0.3.0, v0.4.0, v0.5.0 and v0.5.1 each shipped a wheel reporting `0.2.0` at runtime. Anyone pinning or logging on `agentrust_trace.__version__` got the wrong answer, and nothing failed. It now derives from installed package metadata, which makes the two unable to disagree, and `tests/test_version.py` pins the source tree against `pyproject.toml` and requires the changelog to carry a section for the declared version before a tag is cut.

- **The package description advertised TRACE v0.1.** The PyPI summary still named the superseded profile.

- **`verify_record()` now enforces the profile cutover this changelog already declares.** The 0.5.1 cutover entry states that a v0.2 verifier "requires the new URI and rejects the old one; it does not accept both" — but `verify_record()` never read `eat_profile`, so a record carrying the v0.1 identifier, a future version, a foreign tag, or no profile at all verified exactly as a v0.2 record, provided its signature checked out. A valid signature over semantics this build does not implement is not evidence, so the profile is now checked first, before any cryptographic work: anything other than `TRACE_PROFILE_V0_2` (newly exported) raises `ValueError`, with a message that says why when the profile is the superseded v0.1 identifier. Same shape as the revocation enforcement in this release: an already-merged spec requirement (`spec/trace-v0.2.md` section 2) that the reference implementation did not carry out. `docs/verification.md` step 4 notes the check is now built in. No normative text, schema, or record field changed.

### Added

- **`TraceSandboxAdapter`: Trust Records from a sandboxed agent runtime.** A kernel sandbox confines one agent on one machine. It does not answer, on its own, which agent on which of two hundred machines took an action, what actually ran rather than what the policy said, or how to say either on a host with no secure hardware. The adapter builds a record from what such a runtime already has at session close: sandbox identity, image digest, the effective policy bundle bytes, and the decision log. No change to the runtime is required.

  Unlike `TraceAGTAdapter`, one code path spans Level 0 and Level 1. Passing a `SandboxAttestation` moves the record from `software-only` to the attested platform and nothing else about the call changes, because a sandbox runs wherever the customer runs it and the deployments that most need evidence often have the least hardware.

  A caller cannot claim hardware it does not have: `platform` is only ever set from a supplied attestation, an attestation may not name `software-only`, the platform is validated against the enum on `RuntimeInfo` rather than a copy of it, and the measurement must be a `sha256:`/`sha384:` digest. Sandbox identity and image ride the existing `subject` and `build_provenance.digest`, so no schema change was needed.

  Two defaults differ from the AGT adapter, deliberately. `appraisal.status` is `"none"`, because building a record does not appraise it and `affirming` would put a verdict in the field a consumer reads to find out whether anybody checked. `transparency` is `None` and omitted, which is what an unanchored record should say.

  `tool_transcript.hash` is taken over the RFC 8785 canonical form of the decision log rather than `json.dumps(sort_keys=True)`. The two agree on ASCII and diverge on non-ASCII strings and number formatting; a decision log carries paths and hostnames, and the signature pre-image already uses JCS. See `docs/integration/sandbox-runtime.md` and `examples/sandbox-runtime.json`.

- **`verify_record(..., revocation=...)` enforces key revocation at verification time (#76).** §3.2.1 has always required that "Verifiers MUST consult current revocation status at verification time", but `verify_record()` checked only signature and freshness, so a record signed by a revoked or compromised key kept verifying. The new `revocation` parameter accepts either a container of revoked key identifiers or a callable performing a live CRL, status-endpoint, or SCITT lookup. A listed key is rejected, and a store that cannot answer is also rejected: an unavailable revocation source is not evidence that a key is unrevoked.

  Keys are identified by RFC 7638 JWK Thumbprint or `kid`. The check reads the *trusted* key rather than `record["cnf"]["jwk"]`, which is attacker-controlled until the signature verifies.

  Additive and backward compatible: `revocation` defaults to `None`, which leaves verification purely offline and unchanged. That mode cannot prove non-revocation, now stated in `LIMITATIONS.md` and `docs/verification.md`. No normative text, schema, or record field changed.

- **`jwk_thumbprint(jwk)`**: RFC 7638 JWK Thumbprint (RFC 8037 §2 for OKP), exported so callers can key a revocation list on the same identifier the verifier derives.

## [0.5.1] — 2026-07-28

### Fixed

- **`transparency` is optional below Level 2.** The model required a non-empty URI on every record, which was stricter than both `schema/trace-claim.json` (required, no `minLength`) and the conformance suite, which runs `TR-ANC` at Level 2 only. A Level 0 or Level 1 record is not anchored, so it has no receipt to name, and that state was unrepresentable. `None` now means unanchored; an empty string stays rejected, since `""` is not a URI and a field that looks populated but resolves to nothing is worse in a trust record than an absent one.

### Changed

- **BREAKING: TRACE v0.2 changes the EAT profile URI to `tag:agentrust-io.com,2026:trace-v0.2`** (was `tag:agentrust.io,2026:trace-v0.1`). `agentrust.io` was never a domain this project controlled; it resolves to third-party parked addresses. RFC 4151 permits a tag URI only where the minting authority controlled the named domain on the stated date, so the v0.1 identifier was invalid rather than merely misspelled: it asserted authority over a name someone else could stand up a conflicting definition at.

  **Cutover, not coexistence.** A v0.2 verifier requires the new URI and rejects the old one; it does not accept both. Dual acceptance would keep the invalid identifier live indefinitely, which is the thing being fixed. Records already issued under v0.1 stay verifiable against `spec/trace-v0.1.md` and the published `agentrust-trace` 0.4.x releases, which remain on PyPI. They are v0.1 records and are read as such.

  Nothing else in the record format changed. No field was added, removed, or re-typed, so migration for a producer is the profile string and a dependency bump.

  Moved together: `spec/trace-v0.2.md` (new, with a "Changes from v0.1" section), `spec/trace-v0.1.md` (retained, marked superseded), the root `schema/trace-claim.json` const, the packaged `agentrust_trace/schema/trace-v0.2.json`, the `eat_profile` `Literal` in `models.py`, the AGT adapter, `validate.py`'s schema resource, the four platform example records, and the docs.

- Other `agentrust.io` URLs moved to `agentrust-io.com`: the registry and verifier hosts in the AGT adapter and the schema `$id`.

## [0.4.0]

### Added

- **`azure-cvm-sev-snp` platform** — Azure confidential VMs run AMD SEV-SNP behind a Hyper-V paravisor: the SNP report is read from the vTPM (the guest does not control `REPORT_DATA`), so the runtime binding rides a vTPM AK-signed quote rather than the SNP `report_data`. Given its own `runtime.platform` value (distinct from `amd-sev-snp`) so a consumer keying on `runtime.platform` knows the root of trust is vTPM-rooted, not direct-silicon. Added to the `RuntimeInfo` model and the JSON schema enum. Hardware-validated on a live Azure SEV-SNP VM via cMCP.

- `delegation` (optional object): the A2A profile delegation-link block, carrying `parent_record_hash` (digest of the parent hop's Trust Record) and `credential_id` (the delegation credential this hop acted under). A chain of records linked this way forms an offline-verifiable delegation DAG. Backward-compatible: existing records without `delegation` remain valid. This is a MINOR (additive) change and the foundation of the forthcoming A2A profile; A2A is now stable at v1.x, clearing the prior blocker.

---

## [0.3.0] — 2026-06-30

### Security

- `verify_record` now requires an explicit trusted key. Self-verification from the embedded `cnf.jwk` is no longer the default; use `allow_embedded_key=True` to opt in.
- Verification enforces freshness (`iat` / `max_age_seconds`, default 24h) and an optional `expected_nonce`. JWK `kty` / `crv` are validated.

### Breaking

- **BREAKING:** Canonicalization is now RFC 8785 (JCS). Trust records are NOT cross-verifiable with 0.2.0 (the prior `json.dumps` canonicalization was non-conformant).

---

## [0.1.0] — 2026-06-23

Initial public draft. Announced at Confidential Computing Summit, San Francisco.

### Specification

- Trust Record logical schema (§3.1): `subject`, `model`, `runtime`, `policy`, `data_class`, `tool_transcript`, `build_provenance`, `appraisal`, `transparency`, `cnf`
- Wire format (§3.2): EAT/JWT and CBOR-COSE envelopes; profile URI `tag:agentrust.io,2026:trace-v0.1`
- Signing and key management (§3.2.1): ES256/ES384/EdDSA; four-layer key hierarchy; hash agility; revocation
- Verification protocol (§3.3): five-step offline verification, no issuer callback
- Standards composition (§4): RATS/EAT, SLSA, SPIFFE, SCITT, EAR, MCP, A2A, AIBOM, C2PA
- Hardware roots (§4.2): NVIDIA H100/Blackwell, Intel TDX, AMD SEV-SNP, Azure MAA, GCP Confidential Space, AWS Nitro
- Reference implementation (§5): cMCP Phase 1–3 roadmap

### Schema

- `schema/trace-claim.json`: JSON Schema (draft/2020-12) for Trust Record validation

### Examples

- `examples/amd-sev-snp.json`: AMD SEV-SNP Trust Record
- `examples/intel-tdx.json`: Intel TDX Trust Record
- `examples/nvidia-h100.json`: NVIDIA H100 Confidential Computing Trust Record

### Open questions

Seven open questions requiring community input before v0.2 are documented in §7 of the spec.

---

## [0.2.0] — TBD

### Specification

- Extend `subject` field to accept DID URIs (any `did:` method) in addition to SPIFFE SVIDs.
  Previously `^spiffe://` only; now `^(spiffe://|did:)`. Additive, backward-compatible.
  DID-native runtimes (e.g. AGT `did:mesh:` identities) no longer require a parallel SPIFFE identity.
  Closes: microsoft/agent-governance-toolkit ADR-0032, agentrust-io/trace-spec#35.

### Schema

- `schema/trace-claim.json`: `subject` pattern updated to `^(spiffe://|did:)`, description updated.

### Reference Implementation

- `TrustRecord.subject` pattern updated to `r"^(spiffe://|did:)"`.

---

## Upcoming

See [ROADMAP.md](ROADMAP.md) for planned changes in v0.2 and v1.0.
