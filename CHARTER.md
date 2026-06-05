# Technical Charter — TRACE

**Proposed hosting**: CoSAI (Coalition for Secure AI) for the technical workstream; Linux Foundation entity hosting the Model Context Protocol for specification, IP, trademark, and conformance mark.  
**Status**: Pre-acceptance draft — effective upon host organization acceptance.  
**Version**: 0.1 (aligned with spec v0.1)

---

## 1. Mission

The TRACE project develops and maintains an open, portable, hardware-enforced governance record for AI agents and other confidential workloads. The mission is to make execution governance evidence verifiable by any party — without trusting the operator, without callbacks to the issuer, and without vendor lock-in to any cloud, silicon vendor, or AI provider.

## 2. Scope

The project includes:

- **The TRACE Specification** — normative text defining the Trust Record schema, wire format, signing and key management protocol, verification rules, hardware root profiles, and conformance requirements.
- **JSON Schema** — machine-readable schema for Trust Record validation.
- **Conformance test suite** — the canonical tests validating compliance (in [agentrust-io/trace-tests](https://github.com/agentrust-io/trace-tests)).
- **Vendor platform annexes** — informative, vendor-co-authored claim-mapping documents for each silicon and cloud attestation surface.
- **Reference examples** — example Trust Records for each supported hardware platform.

Out of scope: runtime policy enforcement engines, TEE platform SDKs, AI model governance beyond execution evidence, and hardware side-channel mitigations.

## 3. Technical Steering Committee

Upon host organization acceptance, governance transitions from the current Project Lead model to a Technical Steering Committee (TSC).

**Composition**: 3–9 members. No single organization may hold more than 40% of TSC seats. The founding Project Lead (Imran Siddique, OPAQUE Systems) holds one founding seat for the v1.0 ratification cycle.

**Election**: TSC members are elected annually by active contributors (at least one merged PR or accepted spec change in the preceding 12 months). Each contributor has one vote.

**Quorum**: Two-thirds of TSC members must participate for a vote to be valid.

**Decisions**:
- Spec errata and editorial changes: simple TSC majority
- Non-breaking spec versions (new optional fields, new platform profiles): two-thirds TSC majority + 14-day public comment
- Breaking spec versions (mandatory field changes, algorithm deprecations, wire format changes): two-thirds TSC majority + 30-day public comment + explicit backward-compatibility statement

**Meetings**: Monthly public TSC meeting. Notes published within 5 business days.

## 4. Intellectual Property Policy

All contributions must be made under the terms of [LICENSE](LICENSE). Contributors must sign commits with the Developer Certificate of Origin (DCO). No contribution may incorporate material covered by a patent the contributor is unwilling to license royalty-free to conforming implementations.

The specification text is licensed under CC BY 4.0. Schema, examples, and code are licensed under Apache 2.0 with Patent Promise (see LICENSE).

## 5. Trademark Policy

"TRACE" as a specification name and the "TRACE-conformant" conformance mark are currently held by OPAQUE Systems, Inc. Upon host organization acceptance, trademark ownership transfers to the host under their standard trademark policy.

Use of "TRACE-conformant" to describe an implementation is permitted only when that implementation passes the published conformance test suite for the version being claimed.

## 6. Conformance

An implementation may claim TRACE conformance only by passing the conformance test suite in [agentrust-io/trace-tests](https://github.com/agentrust-io/trace-tests) at the level being claimed (Level 0, 1, or 2). Conformance claims must reference the test suite version and include a link to a passing run.

Test suite changes that would invalidate previously conformant implementations require a spec version increment.

## 7. Relationship to other standards

TRACE profiles, and does not replace:

- **RATS / EAT (RFC 9711)** — wire envelope
- **SLSA** — build provenance
- **SPIFFE / SPIRE** — workload identity
- **SCITT** — transparency anchoring
- **EAR (draft-ietf-rats-ar4si)** — verifier appraisal
- **MCP / A2A** — agent execution surface
- **AIBOM (SPDX 3.0, CycloneDX 1.7)** — model component inventory

TRACE participates in IETF RATS, SCITT, and EAR working groups as a consuming profile, not a competing standard.

## 8. Transition timeline

| Milestone | Target |
|---|---|
| v0.1 draft — CC Summit announcement | June 2026 |
| CoSAI committee formation | Q3 2026 |
| MCP profile and A2A profile (v0.2) | Q3 2026 |
| Host organization submission | Q3 2026 |
| v1.0 ratification under TSC governance | 2027 |

## 9. Amendments

Amendments to this charter require a two-thirds TSC majority and a 30-day public comment period. Before host organization acceptance, amendments require Project Lead approval and 14-day notice to contributors.
