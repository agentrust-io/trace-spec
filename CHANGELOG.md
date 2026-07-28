# Changelog

All notable changes to the TRACE specification will be documented here.

Format: [Semantic Versioning](https://semver.org/). Spec versions follow `MAJOR.MINOR.PATCH`:
- **MAJOR**: breaking changes to wire format or required Trust Record fields
- **MINOR**: new optional fields, new platform profiles, new conformance levels
- **PATCH**: editorial fixes, clarifications, non-normative additions

---

## [Unreleased]

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
