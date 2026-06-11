# TRACE Specification — Trust, Runtime Attestation, and Compliance Evidence

| Field | Value |
|---|---|
| Version | 0.1 — Draft |
| Status | RFC — Request for Comments |
| Authors | Rishabh Poddar, Aaron Fulkerson (OPAQUE Systems) |
| Target announcement | Confidential Computing Summit, San Francisco — 23 June 2026 |
| Reference implementation | [agentrust-io/cmcp](https://github.com/agentrust-io/cmcp) — Confidential MCP |
| License | CC BY 4.0 |

> **Note:** This is a pre-ratification draft. Fields, wire formats, and conformance requirements are subject to change before v1.0. Send feedback to: open an issue on this repository.

---

## Abstract

TRACE (Trust, Runtime Attestation, and Compliance Evidence) defines an open, portable, hardware-enforced governance record for AI agents and other confidential workloads. It binds *what executed* (model, code, runtime), *under what policy*, *on what data class*, *invoking which tools*, into a single signed artifact rooted in silicon attestation. The record travels with the workload across hosts, clouds, and providers and is verifiable offline by any party.

TRACE composes existing standards rather than replacing them. It profiles RATS/EAT (RFC 9711) for the wire envelope, SLSA for build-time provenance, SCITT for transparency anchoring, SPIFFE for workload identity, EAR for evidence appraisal, and MCP / A2A for the agent execution surface. Where gaps exist — notably the AI-agent execution profile — TRACE proposes the minimum new schema to close them.

The first reference build is **Confidential MCP (cMCP)**: runtime attestation, policy enforcement, and signed evidence at the Model Context Protocol boundary, on Intel TDX, AMD SEV-SNP, and NVIDIA H100/Blackwell confidential GPUs.

---

## 1. Problem

AI builders shipping agents into regulated environments hit the same wall at every deployment: security and compliance review. Internal risk teams, external auditors, and customer CISOs all ask one question:

> *"How do you prove the agent handled our data according to policy?"*

The vocabulary lags the system. Auditors still say *the model* because that is the language that has been in use since before agents existed. What they are actually asking about — and what the AI builder owes them — is the entire agent execution: the model invocation, the tools the agent called, the data classes it touched at each step, and the policies that bound the whole sequence.

The wall is not technical capability — it is evidence. AI builders today produce policy documents, SOC reports, vendor self-attestation, and mutable application logs. None prove what actually happened during execution, so review cycles stretch from days into months.

| Layer | What exists | What is missing |
|---|---|---|
| Static documentation | Model Cards, Data Cards, AIBOMs (SPDX 3.0 / CycloneDX 1.7) | No runtime binding — diverges from deployed reality |
| Operational tracking | MLflow, W&B, vendor logs | Self-reported, mutable, no tamper evidence |
| Hardware attestation | NVIDIA NRAS, Intel Trust Authority, AMD SEV-SNP, AWS Nitro, Azure MAA, GCP Confidential Space | Proves the environment is genuine — no governance, policy, or data-class binding |
| Content provenance | C2PA Content Credentials | Proves content origin — silent on inference execution |
| Compliance frameworks | NIST AI RMF, ISO 42001, EU AI Act Annex IV / Article 12 | Mandate documentation; no prescribed cryptographic format |
| **Execution governance proof** | **Vendor-proprietary artifacts** | **No open, portable, vendor-neutral standard exists** |

The result: every regulated AI deployment re-litigates trust at every host boundary. Each cloud, each model provider, each agent framework ships its own evidence shape. Auditors cannot compare. Verifiers cannot federate. Workloads cannot move.

The EU AI Act mandates tamper-evident logging for high-risk AI (Article 12); under the current provisional timeline those obligations apply from around December 2027. Frameworks already in force — DORA for financial entities, HIPAA for healthcare — carry equivalent audit-trail requirements today. Autonomous agents inside critical infrastructure are landing before the standard exists to govern them.

---

## 2. Threat Model

TRACE is sound only against named adversaries and named failure modes, under named assumptions.

### 2.1 The three questions an AI builder cannot answer today

1. **What actually ran?** Not what was deployed. Not what the manifest says. *What was loaded into memory and executed at the moment the customer's data was processed* — model weights digest, agent code, dependency tree, runtime image, policy bundle — bound together cryptographically and reproducibly verifiable by an outside party.

2. **What did it actually do?** Which tools the agent called. With what parameters. Against what data class. With what response. In what order. Across how many agent hops. Software-layer telemetry is self-reported and mutable. *Scope: TRACE captures invocations crossing a protocol boundary (MCP, A2A, and other instrumented surfaces). Functions embedded inside the deployed binary fall outside `tool_transcript` and are bound only by `build_provenance` and `model`.*

3. **What rules were actually in force?** Not the policy on the document. *The policy bundle hash bound to the workload at execution time, with the enforcement mode it ran under*, verifiable independently of the workload that ran it.

Each question maps to a Trust Record claim:

- `runtime` + `model` + `build_provenance` answer (1).
- `tool_transcript` answers (2).
- `policy` + `data_class` answer (3).

### 2.2 Adversary classes in scope

- **The agent itself, under autonomy.** AI agents are non-deterministic. They may invoke tools, route data, and act in ways no software policy anticipated under prompt injection, goal hijack, alignment drift, tool misuse, or routine non-determinism. TRACE does not prevent misbehavior. It makes misbehavior crossing a protocol boundary visible at the moment of execution.
- **Cloud or infrastructure operator with root.** A privileged operator on the host — CSP staff, data center personnel, a compromised hypervisor, or a co-tenant that escapes isolation. Cannot be trusted to honor policy or to report execution faithfully.
- **Compromised orchestration layer.** A kubelet, container runtime, or control plane that may substitute, restart, or steer the workload it schedules.
- **Malicious or compromised dependency.** A poisoned model artifact, agent package, container base image, or transitive build-chain dependency.
- **Colluding verifier or issuer.** A relying party that may collude with the issuer to fabricate evidence.

### 2.3 Trusted Computing Base

TRACE Records are sound only when:

- The silicon root of trust (Intel TDX, AMD SEV-SNP, NVIDIA H100/Blackwell CC, and equivalents) is uncompromised, with current firmware and unrevoked vendor keys.
- The published Reference Integrity Manifests (RIMs) for firmware, kernel, image, and workload are accurate and signed by their respective vendors.
- The transparency log substrate(s) honor append-only semantics.
- The verifier evaluates evidence against current revocation, reference data, and policy as of the verification time.

### 2.4 Permanent scope boundaries

TRACE does not protect against:

- TEE side-channel attacks (cache, timing, speculative execution, power analysis).
- Compromise or coercion of a silicon root vendor or transparency log operator.
- Model behavior — prompt injection, jailbreaks, hallucination, alignment drift. TRACE proves what executed and which countermeasures were in force; it does not adjudicate whether the model's output was correct.
- Availability and denial-of-service.
- UX-layer attacks against the human in the loop.

---

## 3. Trust Record

### 3.1 Logical schema

The Trust Record is the unit of evidence. All fields are required unless marked OPTIONAL.

| Field | Description | Source primitive |
|---|---|---|
| `subject` | Workload identity (agent, tool, model invocation) | SPIFFE SVID |
| `model` | Model identity, weights digest, version | EAT claim + AIBOM reference |
| `runtime` | TEE measurement chain (firmware → kernel → image → workload) | RATS Evidence + vendor RIM |
| `policy` | Bound policy set hash + enforcement mode | Policy artifact hash sealed to TEE measurement |
| `data_class` | Classification of inputs and outputs | Classification label bound to per-call execution |
| `tool_transcript` | MCP / A2A tool calls invoked, parameters classified, responses filtered | MCP / A2A protocol transcripts bound to TEE measurement |
| `build_provenance` | How the running code and model were built | SLSA Provenance v1.0 |
| `appraisal` | Verifier's appraisal of evidence | EAR (EAT Attestation Results) |
| `transparency` | Inclusion proof on append-only log | SCITT Receipt URI |
| `cnf` | Confirmation key — binds record to TEE-held signing key | EAT `cnf` claim (RFC 8747) |
| `eat_profile` | Profile URI identifying this as a TRACE v0.1 record | EAT profile claim |
| `iat` | Issued-at timestamp (Unix epoch) | EAT standard claim |
| `signature` | OPTIONAL as a record field: embedded signature by the `cnf` key over the canonical record (section 3.2.2). Profiles using an enveloping signature (JWS, COSE, cMCP RuntimeClaim) omit this field and carry the signature in the envelope. The signature binding itself is mandatory either way. | JWS / COSE signature over canonical JSON |

Each field is independently verifiable. Sub-records (e.g., per-tool-call transcripts) compose under one root envelope.

### 3.2 Wire format

**Envelope:** EAT (RFC 9711) — JWT (JSON, human-readable contexts) or CWT/CBOR-COSE (constrained and high-throughput contexts).

**Profile URI:** `tag:agentrust.io,2026:trace-v0.1`

**JWT example (readable form):**

```json
{
  "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
  "iat": 1750676142,
  "subject": "spiffe://trust.example.org/agent/payments-processor/prod",
  "model": {
    "provider": "anthropic",
    "model_id": "claude-sonnet-4-6",
    "version": "20251001",
    "weights_digest": "sha256:a3f8d2c1e9b04756..."
  },
  "runtime": {
    "platform": "amd-sev-snp",
    "measurement": "sha384:c9e4b1d2e3f4a5b6...",
    "rim_uri": "https://kdsintf.amd.com/vcek/v1/Milan/..."
  },
  "policy": {
    "bundle_hash": "sha256:b2c3d4e5f6a7b8c9...",
    "enforcement_mode": "enforce",
    "version": "1.2.0"
  },
  "data_class": "confidential",
  "tool_transcript": {
    "hash": "sha256:d4e5f6a7b8c9d0e1...",
    "call_count": 3,
    "transcript_uri": "https://registry.agentrust.io/transcript/..."
  },
  "build_provenance": {
    "slsa_level": 2,
    "builder": "https://github.com/slsa-framework/slsa-github-generator",
    "digest": "sha256:e5f6a7b8c9d0e1f2..."
  },
  "appraisal": {
    "status": "affirming",
    "verifier": "https://trust-authority.example.org",
    "policy_ref": "https://trust-authority.example.org/policy/agent-v1"
  },
  "transparency": "https://registry.agentrust.io/claim/trace-2026-06-23T09:15:42Z-f2a8d1",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "MEkwEw...",
      "y": "GHkVPy..."
    }
  }
}
```

#### 3.2.1 Signing and key management

- **JWT contexts (RFC 7515):** `ES256`, `ES384`, or `EdDSA` (Ed25519). Composite chains across silicon-root and workload segments are expressed as nested JWTs with `x5c` chains or `kid` resolving into vendor RIM directories.
- **CBOR-COSE contexts (RFC 9052/9053):** `COSE_Sign1` for single-signer records; `COSE_Sign` for multi-signer records.
- **Key hierarchy:** silicon root key (vendor-managed, hardware-bound) → platform attestation key (e.g., Intel TDX Quote signing key, AMD VCEK/VLEK, NVIDIA NRAS) → workload attestation key (TEE-bound, ephemeral) → record-signing key (per workload, optionally per session).
- **Revocation:** silicon-root revocation is consumed from existing vendor channels. Workload-level keys SHOULD rotate at TEE-image boundaries. Verifiers MUST consult current revocation status at verification time.
- **Hash agility:** SHA-256 minimum; SHA-384 required for FIPS-aligned profiles. Algorithm signaled in the EAT envelope per RFC 9711 §6.

#### 3.2.2 Mandatory signature and freshness binding

**Signature binding.** Every TRACE Trust Record MUST be cryptographically bound by a signature over its canonical JSON form, made by the key in `cnf`. Canonicalization is RFC 8785 (JCS) unless the profile declares a different canonicalization. The signature MAY be either:

- **Embedded:** carried in the record's top-level `signature` field (base64url, no padding), computed over the canonical form of the record with the `signature` field absent; or
- **Enveloping:** carried by a signed wrapper structure, e.g. a JWS (RFC 7515) whose payload is the record, a COSE_Sign1 envelope, or cMCP's RuntimeClaim (signature over the canonical record, key in `trace.cnf.jwk`).

Each profile MUST declare which binding form it uses. A record with no verifiable signature binding is not a Trust Record: verifiers MUST reject it. Schema validity alone confers no trust.

**Freshness.** Records MUST carry `iat`. Verifiers MUST enforce a maximum record age: a record whose `iat` is older than the maximum age MUST be rejected. The default maximum age is 24 hours; a deployment profile MAY specify a different value. Verifiers SHOULD additionally support challenge-nonce binding for online verification: the verifier supplies a nonce, the issuer echoes it in `runtime.nonce`, and the verifier checks the echo. When a challenge nonce was issued, a record that omits or mismatches it MUST be rejected.

**Conformance alignment.** The TRACE conformance suite (trace-tests) already enforces both rules: records without a verifiable signature fail at conformance level 1 and above, and the default 24-hour max-age is enforced.

### 3.3 Verification

Any party — browser, CLI, in-cluster verifier, third-party auditor — verifies:

1. The record's signature binding (section 3.2.2) verifies against the key in `cnf`, BEFORE any other field is trusted. A record with no verifiable binding MUST be rejected.
2. The record is fresh: `iat` is within the maximum age (default 24 hours unless the deployment profile specifies otherwise). If the verifier issued a challenge nonce, `runtime.nonce` echoes it.
3. Signature chain resolves to a known silicon root (NVIDIA, Intel, AMD, or equivalent).
4. Runtime measurements match published Reference Integrity Manifests (RIMs).
5. Policy hash matches the policy bundle the verifier expects.
6. SCITT receipt resolves on the named transparency log.
7. SLSA provenance resolves to a trusted builder.

No callback to the issuer. No vendor in the trust path beyond silicon root and transparency log operators.

### 3.4 Scope

TRACE governs any confidential workload — AI agent execution, regulated data processing, sovereign compute, secure multi-party computation. AI agents are the forcing function and the first reference profile, not the limit of the standard.

---

## 4. Standards Composition

TRACE is a **profile**, not a parallel stack. It binds existing primitives into one coherent artifact.

```
                   ┌─────────────────────────────────────┐
                   │       TRACE Trust Record            │
                   │   (EAT envelope, JWT or CBOR-COSE)  │
                   └─────────────────────────────────────┘
                                     │
     ┌───────────────────────────────┼──────────────────────────────┐
     │                               │                              │
┌────▼─────┐    ┌──────────┐    ┌────▼────┐    ┌──────────┐    ┌────▼────┐
│  SLSA    │    │ SPIFFE   │    │  RATS   │    │   EAR    │    │  SCITT  │
│provenance│    │  SVID    │    │ Evidence│    │ Appraisal│    │ Receipt │
│ (build)  │    │(identity)│    │ (TEE)   │    │(verifier)│    │ (anchor)│
└──────────┘    └──────────┘    └─────────┘    └──────────┘    └─────────┘
                                      │
                               ┌──────▼──────┐    ┌──────────┐
                               │  EAT        │    │  AIBOM   │
                               │  RFC 9711   │    │ SPDX 3.0 │
                               │ (envelope)  │    │CycloneDX │
                               └─────────────┘    └──────────┘
```

### 4.1 Primitives composed

- **RATS / EAT (RFC 9711)** — wire envelope and claim model. NVIDIA NRAS, Intel Trust Authority, and Azure MAA produce attestation tokens that map into this envelope through vendor-co-authored annexes (see §4.4).
- **SLSA Provenance v1.0** — build-time provenance. Build Level 2 minimum for TRACE-conformant records in v1.0; Build Level 3 is the target for production reference implementations.
- **SPIFFE / SPIRE** — workload identity. The SVID is bound to the TEE measurement so identity is rooted in hardware.
- **SCITT** — append-only transparency log. TRACE defines a SCITT profile for Trust Record inclusion (Signed Statement registration, Receipt format, key rotation semantics).
- **EAR (draft-ietf-rats-ar4si)** — verifier output format. Separates *what was claimed* from *what was accepted*.
- **MCP** — Model Context Protocol tool surface. TRACE adds (a) cryptographic binding of the transcript hash into the EAT envelope and (b) a per-call `data_class` classification. MCP profile targeted for v0.2.
- **A2A** — Agent-to-Agent communication. TRACE adds transcript binding and cross-protocol identity threading via SPIFFE SVID. A2A profile targeted for v0.2.
- **AIBOM (SPDX 3.0 AI Profile, CycloneDX 1.7 ML-BOM)** — component inventory for models, datasets, dependencies. Referenced by digest from `model`.
- **C2PA** — adjacent, not absorbed. Where a TRACE'd execution produces media, the output may carry a C2PA manifest that references the Trust Record.

### 4.2 Hardware roots

- **NVIDIA** — H100, H200, Blackwell with confidential computing mode. NRAS EAT.
- **Intel** — TDX with Trust Authority. TDX Quote (DCAP) + MRTD + RTMRs.
- **AMD** — SEV-SNP with VCEK/VLEK chain to AMD Root Key. CoRIM CBOR mapping.
- **Cloud platform attestation** — Azure MAA, GCP Confidential Space, AWS Nitro Enclaves all expressible as RATS Evidence and composable into a TRACE envelope.

### 4.3 Bindings TRACE adds

These components exist in their respective ecosystems. TRACE adds the binding rule that places each into a hardware-attested envelope:

- **`policy` claim.** Policy artifacts (OPA bundles, Cedar policies, custom DSLs) and policy hashing are established. TRACE adds the binding: the policy bundle hash is sealed to the TEE measurement, the enforcement mode is recorded, and substituting the policy invalidates the runtime claim.
- **`data_class` claim.** Data classification schemes are established (DLP labels, NIST SP 800-60, sensitivity tags). TRACE adds: a classification label is attached to inputs and outputs at the per-call layer and recorded in the Trust Record alongside the runtime evidence.
- **`tool_transcript` claim.** MCP and A2A transcripts exist at the protocol layer. TRACE adds cryptographic binding of the transcript hash into the EAT envelope and per-call parameter classification.
- **AI-agent execution profile.** A profile registry that pins the claim set, evidence requirements, and verification rules for AI-agent workloads specifically.

### 4.4 Vendor profile annexes

TRACE will publish vendor-co-authored claim-mapping annexes — one per silicon-root and cloud-attestation surface — as informative companions to v1.0. Co-editor slots open for:

| Surface | Co-editor slot |
|---|---|
| NVIDIA Remote Attestation Service | NVIDIA |
| Microsoft Azure Attestation | Microsoft |
| Google Cloud Attestation / Confidential Space | Google |
| Intel Trust Authority | Intel |
| AMD CoRIM (SEV-SNP) | AMD |

---

## 5. Reference Implementation: Confidential MCP (cMCP)

the reference implementation at the MCP tool-call boundary.

| Phase | What ships | TRACE fields | Timeline |
|---|---|---|---|
| **Phase 1 — Runtime Trust** | MCP server runs in TEE; SPIFFE identity bound to TEE measurement; signed Trust Record per invocation | `subject`, `runtime`, `build_provenance`, `cnf`, `transparency` | Q2 2026 |
| **Phase 2 — Policy Enforcement** | Transparent JSON-RPC proxy inside TEE; per-tool policy + parameter classification | + `policy`, `data_class`, `tool_transcript` | Q3 2026 |
| **Phase 3 — Workflow Provenance** | Native SDK; cross-MCP lineage; provenance DAG | Full Trust Record | Q4 2026+ |

**Hardware:** Intel TDX, AMD SEV-SNP, NVIDIA H100/Blackwell CC.

**Deployment:** Confidential VMs and Confidential Containers (Kata-CC) on AKS, GCP Confidential Space, AWS Nitro Enclaves, and on-prem. BYOW — existing MCP servers run unchanged.

---

## 6. Governance

### 6.1 Proposed host

**CoSAI** (Coalition for Secure AI) for the technical workstream; the **Linux Foundation entity hosting the Model Context Protocol** for spec, IP, trademark, and conformance mark. Co-locating TRACE governance with the protocol whose attestation surface TRACE most directly profiles inherits LF's IP and trademark machinery.

Other standards bodies participate as technical-liaison partners: OpenSSF (SLSA stewardship), CNCF (SPIFFE/SPIRE stewardship), IETF (RATS, EAT, SCITT, EAR working groups).

### 6.2 Invited founding members

Anthropic, NVIDIA, Intel, AMD, Microsoft, Google, Linux Foundation, Confidential Computing Consortium, ATRC, TII, AI71.

### 6.3 IP and licensing

- **Specifications:** CC BY 4.0.
- **Reference code:** Apache 2.0.
- **Test suite:** Apache 2.0, mandatory for conformance claims.
- **Conformance mark:** managed by host org.

---

## 7. Open Questions

These need input before v0.2:

1. **Host organization.** CoSAI, Linux Foundation, or a federated arrangement?
2. **AI-agent profile vs general profile.** One inclusive profile or split agent execution and generic confidential workload from day one?
3. **Transparency log operator(s).** One canonical SCITT log, federated logs, or BYO with conformance criteria?
4. **Policy language.** TRACE binds a policy *hash*. Does v1.0 also specify a policy *language* (Cedar, Rego, custom DSL), or stay language-agnostic?
5. **Privacy of the record.** Records may contain sensitive classifications. Standardize encrypted-claims envelope (JWE / COSE-Encrypt) from v1.0?
6. **A2A profile timing.** Ship A2A as a peer profile to MCP in v1.0, or wait for A2A to stabilize?
7. **Relationship to IETF AIIP.** Absorb, supersede, or coexist with draft-ritz-aiip?

---

## Appendix A — Glossary

| Term | Definition |
|---|---|
| TCB | Trusted Computing Base. Components whose correctness a TRACE Record's validity depends on |
| TEE | Trusted Execution Environment — Intel TDX, AMD SEV-SNP, NVIDIA H100/Blackwell CC |
| EAT | Entity Attestation Token (RFC 9711). RATS wire envelope. JWT or CBOR-COSE |
| RATS | Remote Attestation Procedures (IETF). The attestation architecture |
| EAR | EAT Attestation Results — verifier appraisal output format |
| SLSA | Supply-chain Levels for Software Artifacts (OpenSSF). Build-time provenance |
| SCITT | Supply Chain Integrity, Transparency, Trust (IETF). Append-only transparency log primitive |
| SPIFFE | Secure Production Identity Framework For Everyone (CNCF). Workload identity |
| AIBOM | AI Bill of Materials (SPDX 3.0 AI Profile, CycloneDX 1.7 ML-BOM) |
| MCP | Model Context Protocol. Agent tool-call surface |
| A2A | Agent-to-Agent (Google). Inter-agent communication protocol |
| C2PA | Coalition for Content Provenance and Authenticity. Content origin manifests |
| RIM | Reference Integrity Manifest. Vendor-published reference measurements |
| Trust Record | TRACE's portable signed artifact — see §3 |
| cMCP | Confidential MCP — TRACE reference implementation at the MCP boundary |

---

## Appendix B — References

### IETF

- RATS Architecture (RFC 9334) — https://www.rfc-editor.org/rfc/rfc9334
- EAT — Entity Attestation Token (RFC 9711) — https://www.rfc-editor.org/rfc/rfc9711
- SCITT Architecture (draft-ietf-scitt-architecture) — https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
- SCITT Reference APIs (draft-ietf-scitt-scrapi) — https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
- EAR / AR4SI (draft-ietf-rats-ar4si) — https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/
- JWS (RFC 7515) — https://www.rfc-editor.org/rfc/rfc7515
- JWE (RFC 7516) — https://www.rfc-editor.org/rfc/rfc7516
- COSE (RFC 9052/9053) — https://www.rfc-editor.org/rfc/rfc9052

### Foundation Specifications

- SLSA Specification v1.0 (OpenSSF) — https://slsa.dev/spec/v1.0/
- SPIFFE / SPIRE Specifications (CNCF) — https://spiffe.io/docs/latest/spiffe-about/
- SPDX 3.0 AI Profile — https://spdx.dev/use/specifications/
- CycloneDX 1.7 ML-BOM — https://cyclonedx.org/specification/overview/
- C2PA Technical Specification v2 — https://c2pa.org/specifications/specifications/2.0/
- Sigstore / Rekor — https://docs.sigstore.dev/

### Vendor Hardware Attestation

- NVIDIA Remote Attestation Service — https://docs.nvidia.com/attestation/api-docs-nras/
- Intel Trust Authority — https://www.intel.com/content/www/us/en/security/trust-authority.html
- Intel TDX — https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- AMD SEV-SNP — https://www.amd.com/en/developer/sev.html
- Microsoft Azure Attestation — https://learn.microsoft.com/en-us/azure/attestation/overview
- Microsoft Azure Confidential Ledger — https://learn.microsoft.com/en-us/azure/confidential-ledger/
- GCP Confidential Space — https://cloud.google.com/confidential-computing/confidential-space/docs
- AWS Nitro Enclaves — https://aws.amazon.com/ec2/nitro/nitro-enclaves/

### Adjacent Work

- Project Oak (Google DeepMind) — https://github.com/project-oak/oak
- Anthropic MCP Specification — https://modelcontextprotocol.io/specification/
- Google A2A Specification — https://a2a-protocol.org/latest/specification/
- MITRE ATLAS — https://atlas.mitre.org/
- OWASP Top 10 for Agentic Applications — https://genai.owasp.org/
