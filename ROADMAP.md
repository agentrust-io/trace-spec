# Roadmap

Status as of August 2026. Spec **v0.2** is current ([`spec/trace-v0.2.md`](spec/trace-v0.2.md)); the `agentrust-trace` reference SDK is at **0.6.0** and the conformance suite (`agentrust-io/trace-tests`) at **0.4.1**.

## Shipped — v0.2 (July–August 2026)

- **EAT profile URI cutover** to `tag:agentrust-io.com,2026:trace-v0.2`. The v0.1 identifier named a domain this project never controlled, which RFC 4151 does not permit, so it was invalid rather than misspelled. A v0.2 verifier requires the new URI and rejects the old one; `verify_record()` enforces the cutover before any cryptographic work. Records issued under v0.1 stay verifiable against `spec/trace-v0.1.md` and the published 0.4.x releases.
- **`delegation` link block** (`parent_record_hash` + `credential_id`), optional and additive. A chain of records linked this way forms an offline-verifiable delegation DAG. This is the foundation the A2A profile binds to, not the profile itself.
- **`transparency` is optional below Level 2.** A Level 0 or Level 1 record is unanchored and has no receipt to name; that state was previously unrepresentable.
- **`azure-cvm-sev-snp` platform**, distinct from `amd-sev-snp`, because Azure runs SEV-SNP behind a Hyper-V paravisor and the runtime binding rides a vTPM AK-signed quote rather than a guest-controlled `REPORT_DATA`. A consumer keying on `runtime.platform` can tell the two roots apart.
- **Revocation at verification time** (`verify_record(..., revocation=...)`). §3.2.1 always required it; the verifier did not do it. A revocation source that cannot answer is rejected rather than treated as a pass.
- **OWASP Agentic AI Top 10 cross-walk** — [`docs/crosswalks/owasp-agentic-top-10.md`](docs/crosswalks/owasp-agentic-top-10.md).
- **Acta decision-receipt cross-walk** — [`docs/crosswalks/acta-decision-receipts.md`](docs/crosswalks/acta-decision-receipts.md).
- **Producer adapters** for AGT, cMCP, and sandboxed agent runtimes, one code path spanning Level 0 and Level 1.
- **Platform bindings documented** for AMD SEV-SNP, Intel TDX, and NVIDIA H100 ([`docs/platforms/`](docs/platforms/)). This SDK verifies the record; verification of the attestation evidence itself lives in `cmcp` and `agent-manifest`, both of which have been run against genuine hardware quotes.
- **Reference implementation.** cMCP enforces Cedar policy inside the TEE and emits signed GatewayClaims carrying `policy`, `data_class`, and `tool_transcript`.

## Next — v0.3

- **MCP profile (normative)** — claim shape and binding rules for MCP tool-call transcripts. The `tool_transcript` claim exists and is bound; what is missing is the normative rule set, for upstream contribution to MCP spec governance.
- **A2A profile (normative)** — binding rules over the `delegation` block now that A2A is stable at v1.x, including the mutual case. cA2A is the reference implementation.
- **Anchor and inclusion-proof format** — the normative format that lets a third party verify an anchor without trusting the registry operator. Specified but not published; the registry repository is private. This is the gap that makes "verifiable without trusting the operator" a claim about the future rather than the present, and it is the highest priority item on this page. Tracked in [#111](https://github.com/agentrust-io/trace-spec/issues/111).
- **Attested memory and persistent state** — a claim for agent memory integrity at runtime, digesting the whole store rather than a manifest of it. Nothing in the ecosystem measures agent memory today; every runtime treats the agent as stateless between actions.
- **MITRE ATLAS cross-walk** — TRACE claim coverage mapped to relevant ATLAS tactics.
- **Encrypted claims envelope** — normative profile for JWE / COSE-Encrypt where `data_class` requires confidential transport to verifiers (open question §7 Q5).
- **Vendor platform annexes** — co-authored informative claim-mapping docs for NVIDIA NRAS, Intel Trust Authority, AMD CoRIM, Azure MAA, GCP Confidential Space. Co-editor seats are open (§4.4); the informative platform docs in `docs/platforms/` are ours, not vendor-co-authored.
- **Disposition on IETF AIIP** — coordinate with `draft-ritz-aiip`: absorb, supersede, or coexist (open question §7 Q7).

## Later — v1.0 standard (2027)

- TSC governance under "TRACE Specification, a Series of LF Projects, LLC" (formation with LF Projects, LLC complete; the TSC transition under [CHARTER.md](CHARTER.md) is the remaining step)
- All §7 open questions resolved
- Complete conformance certification program
- Post-quantum signature profile (ML-DSA, tracking NIST SP 800-208)
- MCP and A2A profiles ratified and proposed to their respective upstream governance bodies
- A canonical profile URI assigned by the standards home, replacing the provisional tag URI
- Multi-language verification libraries (Python, TypeScript, Go, Rust)

## What TRACE will not do

- Replace RATS, EAT, SLSA, SPIFFE, SCITT, or MCP — TRACE is a profile of these
- Specify a centralized Trust Record registry — verification is designed to work without one
- Build a TEE platform — hardware support targets open silicon (TDX, SEV-SNP, NVIDIA CC) and any platform that produces RATS-conformant evidence
- Adjudicate model alignment or output correctness — TRACE proves what executed and what was in force; correctness is out of scope

## Influencing the roadmap

Open a GitHub issue with the `spec` or `roadmap` label. Items land here when they are implemented and tested, not when they are planned; anything above the "Next" line is exercisable today.
