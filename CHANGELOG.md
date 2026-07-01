# Changelog

All notable changes to the TRACE specification will be documented here.

Format: [Semantic Versioning](https://semver.org/). Spec versions follow `MAJOR.MINOR.PATCH`:
- **MAJOR**: breaking changes to wire format or required Trust Record fields
- **MINOR**: new optional fields, new platform profiles, new conformance levels
- **PATCH**: editorial fixes, clarifications, non-normative additions

---

## [Unreleased]

### Added

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
