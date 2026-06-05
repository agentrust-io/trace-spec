# Roadmap

## Now — v0.1 draft (June 2026)

Announced at Confidential Computing Summit, San Francisco, June 23 2026.

**In scope:**
- Full Trust Record schema: `subject`, `model`, `runtime`, `policy`, `data_class`, `tool_transcript`, `build_provenance`, `appraisal`, `transparency`, `cnf`
- Wire formats: EAT/JWT and CBOR-COSE
- Hardware roots: NVIDIA H100/Blackwell, Intel TDX, AMD SEV-SNP, Azure MAA, GCP Confidential Space, AWS Nitro
- JSON Schema and three hardware examples
- Reference implementation: cMCP Phase 1 (runtime trust, no policy enforcement)

**Not in v0.1:** MCP profile (normative), A2A profile, vendor platform annexes, OWASP/ATLAS cross-walks, encrypted claims envelope.

## Next — v0.2 (Q3 2026)

Driven by founding-member feedback and open questions from §7 of the spec.

- **MCP profile** — normative claim shape and binding rules for MCP tool-call transcripts (`tool_transcript`); proposed for upstream contribution to MCP spec governance
- **A2A profile** — same, for Google Agent-to-Agent; pending A2A protocol stability
- **Vendor platform annexes** — co-authored informative claim-mapping docs for NVIDIA NRAS, Intel Trust Authority, AMD CoRIM, Azure MAA, GCP Confidential Space
- **OWASP Agentic AI Top 10 cross-walk** — which TRACE claim evidences which control for each of the 10 ASIs
- **MITRE ATLAS cross-walk** — TRACE claim coverage mapped to relevant ATLAS tactics
- **Encrypted claims envelope** — normative profile for JWE / COSE-Encrypt when `data_class` requires confidential transport to verifiers (open question §7 Q5)
- **Reference to IETF AIIP** — coordinate with draft-ritz-aiip and determine disposition (open question §7 Q7)
- **cMCP Phase 2** — policy enforcement and `tool_transcript` binding; first full Trust Records

## Later — v1.0 standard (2027)

- TSC governance under CoSAI / Linux Foundation
- All §7 open questions resolved
- Complete conformance certification program
- Post-quantum signature profile (ML-DSA, tracking NIST SP 800-208)
- MCP and A2A profiles ratified and proposed to respective upstream governance bodies
- AAIF-assigned canonical profile URI replacing the provisional v0.1 tag URI
- Multi-language verification libraries (Python, TypeScript, Go, Rust)

## What TRACE will not do

- Replace RATS, EAT, SLSA, SPIFFE, SCITT, or MCP — TRACE is a profile of these
- Specify a centralized Trust Record registry — verification is designed to work without one
- Build a TEE platform — hardware support targets open silicon (TDX, SEV-SNP, NVIDIA CC) and any platform that produces RATS-conformant evidence
- Adjudicate model alignment or output correctness — TRACE proves what executed and what was in force; correctness is out of scope

## Influencing the roadmap

Open a GitHub issue with the `spec` or `roadmap` label. Founding-member and vendor feedback from the CC Summit period (June–September 2026) has priority for v0.2 scope.
