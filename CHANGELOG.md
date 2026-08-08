# Changelog

All notable changes to the TRACE specification will be documented here.

Format: [Semantic Versioning](https://semver.org/). Spec versions follow `MAJOR.MINOR.PATCH`:
- **MAJOR**: breaking changes to wire format or required Trust Record fields
- **MINOR**: new optional fields, new platform profiles, new conformance levels
- **PATCH**: editorial fixes, clarifications, non-normative additions

---

## [Unreleased]

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

### Fixed

- **`verify_record()` now enforces the profile cutover this changelog already declares.** The entry above states that a v0.2 verifier "requires the new URI and rejects the old one; it does not accept both" — but `verify_record()` never read `eat_profile`, so a record carrying the v0.1 identifier, a future version, a foreign tag, or no profile at all verified exactly as a v0.2 record, provided its signature checked out. A valid signature over semantics this build does not implement is not evidence, so the profile is now checked first, before any cryptographic work: anything other than `TRACE_PROFILE_V0_2` (newly exported) raises `ValueError`, with a message that says why when the profile is the superseded v0.1 identifier. Same shape as the revocation fix above: an already-merged spec requirement (`spec/trace-v0.2.md` section 2) that the reference implementation did not carry out. `docs/verification.md` step 4 notes the check is now built in. No normative text, schema, or record field changed.

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
