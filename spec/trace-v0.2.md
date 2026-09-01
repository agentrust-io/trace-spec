# TRACE Specification: Trust, Runtime Attestation, and Compliance Evidence

| Field | Value |
|---|---|
| Version | 0.2: Draft |
| Status | RFC: Request for Comments |
| Authors | Imran Siddique, Rishabh Poddar, Aaron Fulkerson (OPAQUE Systems) |
| Target announcement | Confidential Computing Summit, San Francisco: 23 June 2026 |
| Reference implementation | [agentrust-io/cmcp](https://github.com/agentrust-io/cmcp): Confidential MCP |
| License | Community Specification License 1.0 (see [LICENSE](../LICENSE)) |

> **Note:** This is a pre-ratification draft. Fields, wire formats, and conformance requirements are subject to change before v1.0. Send feedback to: open an issue on this repository.

## Changes from v0.1

One normative change, and it is breaking.

**The EAT profile URI is now `tag:agentrust-io.com,2026:trace-v0.2`** (was `tag:agentrust.io,2026:trace-v0.1`).

`agentrust.io` was never a domain this project controlled; it resolves to third-party parked addresses. RFC 4151 permits a tag URI only where the minting authority controlled the named domain on the stated date, so the v0.1 identifier was not merely misspelled, it was invalid: it asserted authority over a name belonging to someone else, who could at any point stand up a conflicting definition at it.

Everything else in the record format is unchanged from v0.1. No field was added, removed, or re-typed. The non-normative sections have moved on: §6.1 now names the Linux Foundation series as the host, and §7 marks two open questions resolved.

**Cutover, not coexistence.** A v0.2 verifier MUST require `tag:agentrust-io.com,2026:trace-v0.2` and MUST reject the v0.1 identifier. It MUST NOT accept both. A dual-accepting verifier would leave the invalid identifier live indefinitely, which is the thing being fixed, and would let a record minted under a domain we do not own continue to pass as conformant.

Records already issued under v0.1 remain verifiable against the v0.1 specification and the `agentrust-trace` 0.4.x releases, which stay published. They do not become invalid retroactively; they are v0.1 records and are read as such. Producers should move to v0.2 at their next release.

---

## Abstract

TRACE (Trust, Runtime Attestation, and Compliance Evidence) defines an open, portable, hardware-attested governance record for AI agents and other confidential workloads. It binds *what executed* (model, code, runtime), *under what policy*, *on what data class*, *invoking which tools*, into a single signed artifact rooted in silicon attestation. The record travels with the workload across hosts, clouds, and providers and is verifiable offline by any party.

TRACE composes existing standards rather than replacing them. It profiles RATS/EAT (RFC 9711) for the wire envelope, SLSA for build-time provenance, SCITT for transparency anchoring, SPIFFE for workload identity, EAR for evidence appraisal, and MCP / A2A for the agent execution surface. Where gaps exist, notably the AI-agent execution profile, TRACE proposes the minimum new schema to close them.

The first reference build is **Confidential MCP (cMCP)**: runtime attestation, policy enforcement, and signed evidence at the Model Context Protocol boundary, on Intel TDX, AMD SEV-SNP, and NVIDIA H100/Blackwell confidential GPUs.

---

## 1. Problem

AI builders shipping agents into regulated environments hit the same wall at every deployment: security and compliance review. Internal risk teams, external auditors, and customer CISOs all ask one question:

> *"How do you prove the agent handled our data according to policy?"*

The vocabulary lags the system. Auditors still say *the model* because that is the language that has been in use since before agents existed. What they are actually asking about, and what the AI builder owes them, is the entire agent execution: the model invocation, the tools the agent called, the data classes it touched at each step, and the policies that bound the whole sequence.

The wall is not technical capability: it is evidence. AI builders today produce policy documents, SOC reports, vendor self-attestation, and mutable application logs. None prove what actually happened during execution, so review cycles stretch from days into months.

| Layer | What exists | What is missing |
|---|---|---|
| Static documentation | Model Cards, Data Cards, AIBOMs (SPDX 3.0 / CycloneDX 1.7) | No runtime binding: diverges from deployed reality |
| Operational tracking | MLflow, W&B, vendor logs | Self-reported, mutable, no tamper evidence |
| Hardware attestation | NVIDIA NRAS, Intel Trust Authority, AMD SEV-SNP, AWS Nitro, Azure MAA, GCP Confidential Space | Proves the environment is genuine: no governance, policy, or data-class binding |
| Content provenance | C2PA Content Credentials | Proves content origin: silent on inference execution |
| Compliance frameworks | NIST AI RMF, ISO 42001, EU AI Act Annex IV / Article 12 | Mandate documentation; no prescribed cryptographic format |
| **Execution governance proof** | **Vendor-proprietary artifacts** | **No open, portable, vendor-neutral standard exists** |

The result: every regulated AI deployment re-litigates trust at every host boundary. Each cloud, each model provider, each agent framework ships its own evidence shape. Auditors cannot compare. Verifiers cannot federate. Workloads cannot move.

The EU AI Act mandates tamper-evident logging for high-risk AI (Article 12); under the current provisional timeline those obligations apply from around December 2027. Frameworks already in force, DORA for financial entities, HIPAA for healthcare, carry equivalent audit-trail requirements today. Autonomous agents inside critical infrastructure are landing before the standard exists to govern them.

---

## 2. Threat Model

TRACE is sound only against named adversaries and named failure modes, under named assumptions.

### 2.1 The three questions an AI builder cannot answer today

1. **What actually ran?** Not what was deployed. Not what the manifest says. *What was loaded into memory and executed at the moment the customer's data was processed*, model weights digest, agent code, dependency tree, runtime image, policy bundle, bound together cryptographically and reproducibly verifiable by an outside party.

2. **What did it actually do?** Which tools the agent called. With what parameters. Against what data class. With what response. In what order. Across how many agent hops. Software-layer telemetry is self-reported and mutable. *Scope: TRACE captures invocations crossing a protocol boundary (MCP, A2A, and other instrumented surfaces). Functions embedded inside the deployed binary fall outside `tool_transcript` and are bound only by `build_provenance` and `model`.*

3. **What rules were actually in force?** Not the policy on the document. *The policy bundle hash bound to the workload at execution time, with the enforcement mode it ran under*, verifiable independently of the workload that ran it.

Each question maps to a Trust Record claim:

- `runtime` + `model` + `build_provenance` answer (1).
- `tool_transcript` answers (2).
- `policy` + `data_class` answer (3).

### 2.2 Adversary classes in scope

- **The agent itself, under autonomy.** AI agents are non-deterministic. They may invoke tools, route data, and act in ways no software policy anticipated under prompt injection, goal hijack, alignment drift, tool misuse, or routine non-determinism. TRACE does not prevent misbehavior. It makes misbehavior crossing a protocol boundary visible at the moment of execution.
- **Cloud or infrastructure operator with root.** A privileged operator on the host: CSP staff, data center personnel, a compromised hypervisor, or a co-tenant that escapes isolation. Cannot be trusted to honor policy or to report execution faithfully.
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
- Model behavior: prompt injection, jailbreaks, hallucination, alignment drift. TRACE proves what executed and which countermeasures were in force; it does not adjudicate whether the model's output was correct.
- Availability and denial-of-service.
- UX-layer attacks against the human in the loop.

---

## 3. Trust Record

### 3.1 Logical schema

The Trust Record is the unit of evidence. All fields are required unless marked OPTIONAL.

| Field | Description | Source primitive |
|---|---|---|
| `subject` | Workload identity (agent, tool, model invocation) | SPIFFE SVID or DID URI |
| `model` | Model identity, weights digest, version | EAT claim + AIBOM reference |
| `runtime` | TEE measurement chain (firmware → kernel → image → workload) | RATS Evidence + vendor RIM |
| `policy` | Bound policy set hash + enforcement mode. `enforcement_mode` MUST default to `enforce`; a deployment MUST explicitly configure `silent` mode. | Policy artifact hash sealed to TEE measurement |
| `data_class` | Classification of inputs and outputs | Classification label bound to per-call execution |
| `tool_transcript` | MCP / A2A tool calls invoked, parameters classified, responses filtered | MCP / A2A protocol transcripts bound to TEE measurement |
| `origin` | OPTIONAL. Where the evidence came from, when that is not this runtime. See §3.1.1. |: |
| `references` | OPTIONAL. Facts outside this record that it points at. Assurance-neutral: see §3.1.2. <!-- CHANGED: #197 - new optional assurance-neutral reference block --> |: |
| `build_provenance` | How the running code and model were built | SLSA Provenance v1.0 |
| `appraisal` | Verifier's appraisal of evidence | EAR (EAT Attestation Results) |
| `transparency` | Inclusion proof on append-only log | SCITT Receipt URI |
| `cnf` | Confirmation key: binds record to TEE-held signing key | EAT `cnf` claim (RFC 8747) |
| `eat_profile` | Profile URI identifying this as a TRACE v0.2 record | EAT profile claim |
| `iat` | Issued-at timestamp (Unix epoch) | EAT standard claim |
| `signature` | OPTIONAL as a record field: embedded signature by the `cnf` key over the canonical record (section 3.2.2). Profiles using an enveloping signature (JWS, COSE, cMCP RuntimeClaim) omit this field and carry the signature in the envelope. The signature binding itself is mandatory either way. | JWS / COSE signature over canonical JSON |

Each field is independently verifiable. Sub-records (e.g., per-tool-call transcripts) compose under one root envelope.

#### 3.1.1 `origin`: who assembled this record

A Trust Record normally describes an execution and is produced by the runtime that performed it. Not every record is: a record can also be **assembled** from evidence someone else produced, which is what an adapter over a third-party governance product does.

`runtime.platform: "software-only"` is the honest platform value in both cases, and that is the problem this block solves. It is the correct value for a dev-mode record, where nothing attested the execution, and for a record transcribed from another vendor's control plane, where the party asserting the evidence also wrote the log. Those are different claims and a consumer weighing a record needs to tell them apart. It cannot, from `platform` alone.

| Field | Required | Meaning |
|---|---|---|
| `kind` | yes | `self`, `third-party-control-plane`, or `log-import` |
| `producer` | yes | Identifier of the system that produced the source evidence |
| `source_event_id` | no | Identifier of the source event in that system, so a record traces back to it |
| `ingested_at` | no | Unix time the source evidence was ingested; distinct from `iat`, which is when this record was issued |

`kind` is a closed set, because the value of the field is that a verifier can key on it.

- **`self`**: the runtime produced its own record. Equivalent to omitting the block; stating it is allowed so a producer can be explicit rather than leave it inferred.
- **`third-party-control-plane`**: assembled from another vendor's runtime governance output. The evidence is asserted by the system that produced it, with no root outside that system.
- **`log-import`**: assembled from a log or export whose producer is not a control plane: a SIEM export, an audit trail, a batch job.

**A record whose `origin.kind` is not `self` MUST carry `runtime.platform: "software-only"`, and a verifier MUST reject it otherwise.** An importer holding someone else's log has no quote to present, so a hardware platform value on such a record is not a stronger claim but an untrue one. It is also the exact shape an adapter produces by starting from a hardware example and editing the fields it understood, which is why this is a MUST rather than a recommendation.

`origin` is absent on every hardware profile in this specification and on every record a TEE-backed runtime produces. Absence means `self`.

**This block does not launder assurance in either direction.** It cannot raise a record: nothing about naming your producer makes unattested evidence attested. It cannot lower one either: a record with a hardware platform and a verified quote is what it is, whether or not it says `origin: self`.

#### 3.1.2 `references`: facts this record points at

<!-- CHANGED: #197 - new subsection -->

`origin` records where evidence *came from* and can lower assurance. `references` records what a record *points at* and cannot. Those are different questions and the spec previously had only the first, so any record that needed to reference something external had to use `origin` and take `runtime.platform: "software-only"` with it.

A `references` entry is a pointer, not evidence. What the signature attests is that this record points there, not the truth of what it points at. The pointer is produced inside the boundary that produced the record; the target is not.

| Field | Required | Meaning |
|---|---|---|
| `rel` | yes | Relationship type. Registered set, see below. |
| `id` | yes | Identifier of the referenced fact within the resolver's system. |
| `resolver` | yes | Identifier of the party obliged to resolve `id`. |
| `retention` | no | Period for which `resolver` undertakes to keep `id` resolvable, as an ISO 8601 duration. |
| `digest` | no | Digest of the referenced object, when the producer holds it at issue time. |

Registered `rel` values:

- **`authorized-intent`**. An authorization decided before execution, held in another system.
- **`approval-outcome`**. An attributable human approval attached to a step-up or defer decision.
- **`behavior-trace`**. A behavioural record of what the agent did, of which this record is the environment evidence.

1. `references` MUST NOT affect `runtime.platform`. A record carrying `references` and no `origin` block is `self` and carries whatever platform value it actually earned.
2. The record signature MUST cover `references`, under the canonicalisation in §3.2.2.
3. A verifier MUST NOT reject a record because an entry in `references` cannot be resolved, and MUST NOT treat a resolved reference as attested evidence.
4. A producer that cannot name a `resolver` MUST omit the entry rather than emit one with an empty or self-asserted resolver.

Rule 3 is what makes the block safe to add. A reference that could invalidate a record would hand whoever controls the target a way to invalidate evidence they do not hold, and a reference that counted as evidence would be the assurance laundering §3.1.1 exists to prevent.

**What the block cannot carry.** Two consequences follow from assurance-neutrality, and they are general to `references` rather than specific to any one relation. First, a reference cannot carry compliance evidence. The block commits to the pointer and not to the target, so no registered `rel` turns an entry into evidence that an obligation was met: a record pointing at a policy, a configuration, or an approval attests that it points there, and nothing about what the target says or whether it was in force. Second, a reference cannot carry a pre-execution commitment. A Trust Record is issued per execution, so a commitment a party needs to check before the workload runs has nothing to read; the evidence exists only after the thing it would have governed has already happened. Either reason alone settles the question, and registering a new `rel` does not touch either, because both are properties of the block rather than of its relation set.

**`resolver` names who must retain, not who adjudicates.** The field is a retention undertaking: it identifies the party obliged to keep `id` resolvable, alongside `retention` as the period they undertake to keep it so. It is not a verification authority, and the two read as the same field until they are separated. The conformance suite refuses the opposite arrangement for a different field: TR-POL-003 takes its resolver from the caller and never derives it from the record, because a record that names its own checker can name one that agrees with it. Naming yourself as the party who must retain an artifact is ordinary and non-circular; naming yourself as the party who decides whether it is true is the circularity that rule refuses. An operator naming themselves as `resolver` for their own artifact is therefore within this section and would still be refused under TR-POL-003's rule, and both are correct. Rule 4 is aimed at a producer who can name no obliged party at all, not at one who is that party.

**Unsettled, and deliberately named rather than hidden.** `retention` states an undertaking and nothing in this specification enforces it. A reference is worth only the ability to resolve it later, and transparency-log practice shows that gap is real rather than theoretical: a record can remain valid and become unreachable when the index that addressed it is removed. §7 open question 3 covers the same ground for `transparency` and the two should be resolved together.

### 3.2 Wire format

**Envelope: ** EAT (RFC 9711): JWT (JSON, human-readable contexts) or CWT/CBOR-COSE (constrained and high-throughput contexts).

**Profile URI:** `tag:agentrust-io.com,2026:trace-v0.2`

**JWT example (readable form):**

```json
{
  "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
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
    "transcript_uri": "https://registry.agentrust-io.com/transcript/..."
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
  "transparency": "https://registry.agentrust-io.com/claim/trace-2026-06-23T09:15:42Z-f2a8d1",
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
- **Revocation:** silicon-root revocation is consumed from existing vendor channels. Workload-level keys SHOULD rotate at TEE-image boundaries. Record-signing key revocation is defined in section 3.2.3, which anchors to transparency-log entry ordering rather than to a status callback, so it does not withdraw the offline-verification property of section 3.3.
- **Hash agility:** SHA-256 minimum; SHA-384 required for FIPS-aligned profiles. Algorithm signaled in the EAT envelope per RFC 9711 §6.

#### 3.2.2 Mandatory signature and freshness binding

**Signature binding.** Every TRACE Trust Record MUST be cryptographically bound by a signature over its canonical JSON form, made by the key in `cnf`. Canonicalization is RFC 8785 (JCS) unless the profile declares a different canonicalization. The signature MAY be either:

- **Embedded:** carried in the record's top-level `signature` field (base64url, no padding), computed over the canonical form of the record with the `signature` field absent; or
- **Enveloping:** carried by a signed wrapper structure, e.g. a JWS (RFC 7515) whose payload is the record, a COSE_Sign1 envelope, or cMCP's RuntimeClaim (signature over the canonical record, key in `trace.cnf.jwk`).

**Canonical form (RFC 8785 JCS).** The canonical form of a TRACE record for signature purposes is produced by the following algorithm:

1. Construct the record object with all fields EXCEPT the `signature` field (for embedded-signature profiles) or the outer envelope (for enveloping-signature profiles). The `cnf` field, including `cnf.jwk`, is included in the canonical form.
2. Apply RFC 8785 JSON Canonicalization Scheme (JCS) to produce a deterministic byte sequence:
   - Object keys are sorted by UTF-16 code unit (ascending), per RFC 8785 §3.2.3. This is not the same as Unicode code-point order: the two agree across the Basic Multilingual Plane and diverge once a key contains a supplementary-plane character, because surrogates occupy U+D800 to U+DFFF and therefore sort below high BMP characters. Sorting Python `str` values with `sorted()` gives code-point order and is wrong here; an RFC 8785 library gets this right.
   - No whitespace between tokens.
   - Numbers are serialized in IEEE 754 double-precision format using the shortest decimal representation that round-trips. RFC 8785 §3.2.2.3 defers this to ECMA-262 §7.1.12.1, which converts through a double, so `9007199254740992` and `9007199254740993` become the same bytes and one signature would stand for two different objects. RFC 8785 Appendix B note 1 makes the range -9007199254740991 to 9007199254740991 a SHOULD on values interpreted as true integers; TRACE raises it to a MUST. No object canonicalized under this section may carry an integer outside that range, and one that does MUST be rejected. A value that needs to be larger is carried as a JSON string, which RFC 8785 Appendix D requires of any number without a natural place in JSON. No field is typed `number`, and none should be: floating-point values raise a second question, the shortest decimal form that round-trips, which a range does not settle.
   - Strings are serialized as UTF-8; only the characters mandated by RFC 8259 §7 are escaped (U+0022, U+005C, and U+0000 to U+001F).
3. Encode the result as UTF-8 bytes. This byte sequence is the pre-image for the signature.

Implementations MUST use an RFC 8785-conformant library. Using `json.dumps(sort_keys=True)` (Python) or equivalent ad-hoc sorting is insufficient: it diverges from RFC 8785 for non-ASCII strings and for IEEE 754 number serialization. Libraries that do pass every other part of this section still disagree on integers outside the safe-integer domain, and the disagreement is not between a right answer and a wrong one. `canonicalize` 4.0.0 (npm) applies the algorithm as written and emits the same bytes for `9007199254740992` and `9007199254740993`. `rfc8785` 0.1.4 (PyPI) refuses both rather than emit bytes that stand for more than one value, which is not what §3.2.2.3 says to do and is the safer way to be wrong. A record carrying such a value gets whichever behaviour the verifier happens to have. The schema bound removes the case instead of choosing between them.
**The range, and why a profile MUST NOT widen it.** One place in particular looks safe and is not. 2^53 is exactly representable, and no two integers in -2^53 to 2^53 share a double, so a range ending there appears sound. It is not, because a validator whose only number type is the double never sees the instance value; it sees what the value parsed to. It reads `9007199254740993` as `9007199254740992`, finds it inside a maximum of 2^53, and admits the one value the range exists to exclude. At 2^53 - 1 every out-of-range integer parses to something still outside the range, so the bound holds in a language that cannot represent what it is rejecting. It is the widest bound that is enforceable at all, which is a stronger reason to use it than convention.

**What the rule covers.** It is on the object, not only on its declared fields: the pre-image covers every member, including the members RFC 7517 permits a `cnf.jwk` to carry that this schema does not name, and the schema holds those to the same range. It is also not only about a Trust Record. It covers the revocation statements and bundles of section 3.2.3, and it covers any object whose digest is taken over its canonical form, such as a bridge profile's declaration and tool-call digests, where no schema constrains the input and this rule is the only thing standing between two different objects and one digest.


Each profile MUST declare which binding form it uses. A record with no verifiable signature binding is not a Trust Record: verifiers MUST reject it. Schema validity alone confers no trust.

**Freshness.** Records MUST carry `iat`. Verifiers MUST enforce a maximum record age: a record whose `iat` is older than the maximum age MUST be rejected. The default maximum age is 24 hours; a deployment profile MAY specify a different value. Verifiers MUST also reject a record whose `iat` is later than the verifier's current time plus an allowed clock-skew tolerance. The default tolerance is 5 minutes; a deployment profile MAY specify a different value. Without the upper bound, a far-future `iat` creates a record that remains fresh until that time plus the maximum age. Verifiers SHOULD additionally support challenge-nonce binding for online verification: the verifier supplies a nonce, the issuer echoes it in `runtime.nonce`, and the verifier checks the echo. When a challenge nonce was issued, a record that omits or mismatches it MUST be rejected.

**Conformance alignment.** The TRACE conformance suite (trace-tests) already enforces both rules: records without a verifiable signature fail at conformance level 1 and above, and the default 24-hour max-age is enforced.

#### 3.2.3 Revocation of record-signing keys

A signature stays valid forever. A record signed by a key that was later compromised passes every check in section 3.3, and nothing inside the record can withdraw the key that signed it. What a verifier needs is not "is this key trusted now" but "was this key trusted when this record was made", and the record cannot answer that about itself.

**Why `iat` cannot carry the boundary.** The obvious rule is to reject a record from a revoked key when its `iat` is later than the compromise time. A compromised record-signing key also signs the `iat` field, so an attacker holding the key backdates it and the rule passes. Any revocation rule anchored to a timestamp the compromised key controls is defeated by the compromise it is meant to contain. This is not a clock-skew problem and no tolerance setting fixes it.

**Anchor: transparency-log entry ordering.** Entry IDs in the log named by the record's SCITT receipt are monotonic and cryptographically bound to the Merkle structure. The attacker cannot choose an entry ID for a record submitted after the log has moved past it, and cannot reorder entries already committed. Ordering therefore survives the compromise of the record-signing key, which a timestamp does not.

`TraceRevocation/1.0` claim type:

```json
{
  "type": "TraceRevocation/1.0",
  "compromised_key_id": "<RFC 7638 JWK thumbprint or kid of the revoked key>",
  "last_valid_entry_id": "<SCITT log entry ID>",
  "revoked_after_entry": "<the next entry ID>",
  "log_id": "<identifier of the transparency log the entry IDs refer to>",
  "reason": "key compromise | superseded | operator request | ...",
  "revocation_key_id": "<thumbprint of the key signing this statement>",
  "sig": { "alg": "ed25519", "value": "<base64url, no padding>" }
}
```

**Verifier rule.** A record signed by a revoked key is valid if and only if its SCITT inclusion entry ID is less than or equal to `last_valid_entry_id` in the applicable revocation statement, and that entry ID is on the log named by `log_id`. A record whose entry ID is greater MUST be rejected. Entry IDs from a different log are not comparable and MUST NOT be used to satisfy the rule.

**Fallback for records with no usable receipt.** A record without a SCITT inclusion entry ID on the named log has no external anchor, so there is no reliable way to place it before or after the compromise. Revocation for such records is binary: a verifier MUST reject every record signed by the revoked key. This is a fallback rather than a lesser mode; it is what the absence of an anchor costs, and it is the existing behaviour for deployments that carry no receipts.

**Signing-key independence.** A revocation statement for key K MUST be signed by a key at a higher level in the section 3.2.1 hierarchy than K, or by a designated organisational recovery key whose compromise domain is independent of K. A statement K could sign for itself lets whoever holds a compromised key issue a revocation naming a `last_valid_entry_id` of their choosing, which converts the mechanism into a tool for the attacker.

**Distribution, offline-verifiable.** Revocation statements are anchored in the same transparency log as the records they govern, which preserves the no-callback property of section 3.3: a verifier that can resolve receipts can resolve revocations. Verifiers cache a signed revocation *bundle* carrying a `valid_until` field, under the same maximum-age model as section 3.2.2. A verifier operating offline states what it checked against: "verified against revocation bundle valid at T". This deliberately replaces a well-known status endpoint, which would require a callback at verification time and withdraw the property section 3.3 is built on.

An expired bundle is not a pass. A verifier whose newest bundle is older than the profile's maximum age MUST report the record as unverified for revocation rather than as verified, and a verifier with no bundle at all MUST report that it performed no revocation check. Neither may be reported as an affirming appraisal.

### 3.3 Verification

Any party, browser, CLI, in-cluster verifier, third-party auditor, verifies:

1. The record's signature binding (section 3.2.2) verifies against the key in `cnf`, BEFORE any other field is trusted. A record with no verifiable binding MUST be rejected.
2. The record is fresh: `iat` is neither older than the maximum age (default 24 hours) nor later than the current time plus the allowed clock skew (default 5 minutes), unless the deployment profile specifies different bounds. If the verifier issued a challenge nonce, `runtime.nonce` echoes it.
3. Signature chain resolves to a known silicon root (NVIDIA, Intel, AMD, or equivalent).
4. Runtime measurements match published Reference Integrity Manifests (RIMs).
5. Policy hash matches the policy bundle the verifier expects.
6. SCITT receipt resolves on the named transparency log.
7. SLSA provenance resolves to a trusted builder.
8. The record-signing key is not revoked as of the entry the record was logged at, per section 3.2.3. A verifier holding no revocation bundle, or only an expired one, reports that rather than treating it as a pass.

No callback to the issuer. No vendor in the trust path beyond silicon root and transparency log operators.

#### 3.3.1 Build provenance verification depth

`build_provenance.provenance_depth` declares the supply-chain depth the issuer claims to
have walked. A verifier MUST record the depth it actually checked in
`appraisal.provenance_depth_verified`. The ordered depth values are `surface`, `builder`, and
`transitive`; a record that omits `provenance_depth` MUST be treated as `surface`.

At `surface`, the verifier MUST confirm that `digest` matches the independently held workload
artifact and that `builder` belongs to its configured trusted-builder set. At `builder`, it MUST
also fetch `provenance_uri`, verify the SLSA attestation signature, and confirm that the
attestation subject and builder identity match the record. At `transitive`, it MUST additionally
enumerate the attestation's materials or `resolvedDependencies` and attempt to verify a publisher
attestation for every enumerated input.

When evidence required for an attempted depth is absent, unreachable, or otherwise cannot be
resolved, the verifier MAY stop at the preceding depth. It MUST record that lower verified depth
and identify the unresolved evidence. It MUST NOT record a depth higher than it executed. There
is no downgrade below `surface`.

When evidence resolves and contradicts the record, the verifier MUST fail the appraisal and MUST
NOT downgrade to suppress the contradiction. Examples include an attestation whose subject or
builder differs from the record and a dependency attestation signed by an issuer outside the
configured trusted set.

A deployment profile MAY set a minimum acceptable verified depth. If
`appraisal.provenance_depth_verified` is below that floor, the verifier MUST set
`appraisal.status` to `contraindicated`.

Until dependency discovery and evidence resolution are standardized, `transitive` records a
floor on verification effort rather than a claim that independent verifiers covered identical
dependency sets.

#### 3.3.2 External execution evidence (optional)

Some deployments attach independent, out-of-band receipts to individual audit-chain entries: for example, a signed assertion from a safety controller confirming or rejecting an actuation request. The TRACE Trust Record commits the audit chain by hash; the receipts live inside that chain, not inside the Trust Record itself. This section defines how a verifier treats them.

A receipt within an audit-chain entry is characterized by: an issuer identity (`issuer`), a key reference (`issuer_key_id`), a signature over the canonical receipt fields (`signature`), a content digest (`evidence_hash`), a type tag (`evidence_type`), and a binding to the corresponding tool call (`linked_call_id`).

**Verification rule.** When a verifier is configured with a trusted public key for the named `issuer_key_id`:

1. Compute the canonical form (RFC 8785 JCS) of the receipt fields excluding `signature`.
2. Verify the `signature` against that canonical form using the configured issuer key.
3. Assert that `linked_call_id` equals the `call_id` of the enclosing audit-chain entry.

A verifier configured with the issuer key that fails any of these three checks MUST treat the audit entry as invalid and reject the Trust Record.

**When the issuer key is not configured.** A receipt whose issuer key is unknown to the verifier is unverified, not invalid. The Trust Record's gateway-produced evidence (signature, audit-chain hash, policy hash, TEE measurement) is unaffected. Verifiers SHOULD surface an advisory status (e.g., `external_evidence_unverified`) rather than silently ignoring the receipt.

**Trust boundary.** External execution evidence is only as trustworthy as the issuer key and the PKI behind it. TRACE binds the receipt into the audit chain: it does not certify that a physical action occurred, that it was executed safely, or that any functional-safety standard was met. Those claims belong to the issuer and its certification body, not to TRACE.

#### 3.3.3 Action receipts for embodied workflows (informative)

Embodied-agent profiles need to keep three evidence layers separate:

| Layer | TRACE role | Boundary |
|---|---|---|
| Session evidence | The Trust Record, policy hash, runtime measurement, and `tool_transcript.hash` bind the governed session. | Does not expose every call unless the verifier has the transcript bytes. |
| Action issuance evidence | Per-call receipts can prove that a specific action request was issued, signed, ordered, and bound to the session or call. | Does not prove that the requested physical or business outcome completed. |
| Outcome evidence | Controller, monitor, human-review, or safety-system observations can describe acceptance, rejection, aborts, or completion. | The claim belongs to the external issuer, not to core TRACE validity. |

This split is intentionally independent of build-provenance depth. A verifier
can have a fully verified dependency chain with no action receipts, or a
complete action-receipt chain for a workload whose builder is only surface
checked. Future profiles may express this as a separate action-receipt
requirement, such as `required`, `optional`, or `none`, without folding action
evidence into the supply-chain provenance axis.

An action receipt profile can build on the external execution evidence rules in
section 3.3.2 by requiring the verifier to:

1. recompute the receipt's action or evidence digest from the canonical action
   preimage;
2. verify the receipt signature against a pinned, manifest-bound, or otherwise
   trusted issuer key, not only against a key embedded in the receipt;
3. verify receipt ordering when receipts are hash-chained;
4. verify that the receipt binds back to the TRACE session, transcript entry, or
   cMCP call identifier; and
5. report missing, stale, mismatched, or unverifiable receipts separately from a
   verified controller rejection.

A signed controller rejection is valid negative evidence: it can prove that the
controller rejected the action request under a trusted key and session binding.
It is not a TRACE verification failure unless the receipt itself is malformed,
untrusted, stale, out of order, or not bound to the expected call. Conversely, a
signed acceptance receipt is not proof of physical completion or
functional-safety certification unless the external issuer and profile
explicitly make, and the verifier is configured to trust, that stronger claim.

#### 3.3.4 Disclosed gaps in a receipt chain

<!-- CHANGED: #117 - GapDisclosure chain element and the receipt_gap_disclosed outcome -->

Under a profile requiring action receipts, completeness of the receipt chain is the
load-bearing property. No emitter can be made gap-proof: any writer operating
asynchronously has a window in which a crash loses a tail of receipts. A specification
that offers only "complete" and "broken" therefore rewards concealment, because an
operator who backfills a lost receipt scores better than one who reports the loss.

A `GapDisclosure` is a signed statement, occupying a position in the receipt chain, that
receipts which would have occupied that position were never emitted. It is negative
evidence contributed by the emitter about itself. It does not establish that the missing
receipts ever existed, how many were lost, or that the emitter did not omit them
selectively; what the splice proves is where the gap sits in the chain, and nothing else.

**Structure.** A `GapDisclosure` is a chain element. It MUST carry:

- `type`, the value `GapDisclosure/1.0`;
- `previous_receipt_hash`, the digest of the chain element immediately preceding the gap,
  in the same form and computed the same way as on a receipt;
- `session_id`, naming the receipt stream the disclosure belongs to;
- `issuer_key_id`, identifying the key that signed it;
- `signature`, over the canonical form of the disclosure with the signature field removed.

It MAY carry `cause` and `receipts_lost_estimate`. Both are descriptive self-reports and
nothing more: the receipts an estimate counts are absent by definition, so nothing in the
chain corroborates either field. A verifier MUST NOT treat them as established, MUST NOT
condition any outcome on their values, and MUST NOT reject a disclosure because either
disagrees with other evidence. They exist to be reported, not relied on.

**Stream binding.** The `session_id` is covered by the signature, and a verifier MUST
reject a disclosure whose `session_id` does not match the receipt stream under
verification. Without that comparison, a disclosure honestly signed for one stream is a
transplantable excuse for a gap in any other: replay, in the position where replay is
hardest to distinguish from recovery.

**Chain binding.** A `GapDisclosure` MUST be spliced into the receipt chain at the point
of resumption. Concretely, its `previous_receipt_hash` MUST name a chain element that is
present, and the next chain element emitted after resumption MUST carry a
`previous_receipt_hash` naming the disclosure. A disclosure that is not linked from both
directions has not been sealed into the chain and MUST NOT be treated as covering
anything.

That requirement has a window in which it cannot be met honestly: at the live tail of
the chain, after the failure and before resumption, the sealing successor does not exist
yet. A verifier meeting a tail disclosure whose other checks pass MUST NOT report
`receipt_gap_disclosed`, and MUST NOT report `receipt_invalid` either: the absence of a
successor is an inability to check, not evidence of a defect, the same principle as
section 3.3.2's treatment of unknown issuer keys. It MUST surface the disclosure as
unverified with a distinct advisory, and re-verification after the chain resumes upgrades
or impeaches it on the seal that then exists. This matters adversarially: a chain
truncated immediately after a disclosure is indistinguishable from an honest tail, so
whatever a verifier grants the honest tail, it grants the truncation.

Gap boundaries MUST NOT be expressed as timestamps or as emitter-assigned sequence
numbers. Both are signed by the same key that signs the receipts, so neither constrains
an emitter that is misrepresenting the gap. The chain links are the boundaries.

**Issuer.** A `GapDisclosure` MUST be signed by the key that signed the chain element its
`previous_receipt_hash` names, or by an ancestor of that key in the hierarchy of
section 3.2.1. A disclosure signed by any other key MUST be treated as invalid, whether
or not that key is otherwise trusted. A gap is the moment at which introducing an
unrelated key is most useful to an adversary and least distinguishable from recovery.

**Consecutive disclosures.** A `GapDisclosure` MAY name another `GapDisclosure` as its
predecessor, which represents an emitter that failed again before emitting a receipt. A
verifier MUST report the number of consecutive disclosures. It MUST NOT reject solely on
that basis: an emitter failing repeatedly and disclosing each time is behaving better
than one that is silent.

**Verifier outcomes.** The action-receipt outcome `receipt_missing_required` is narrowed,
and the outcome `receipt_gap_disclosed` is added beside it:

| Outcome | Meaning |
|---|---|
| `receipt_gap_disclosed` | Required receipts are absent, and a valid `GapDisclosure` occupies their position in the chain. Emitter-attested negative evidence. |
| `receipt_missing_required` | Required receipts are absent and no valid disclosure occupies their position. Silent, and treated as presumptively adversarial. |

A verifier MUST report `receipt_gap_disclosed` distinctly from
`receipt_missing_required`. Collapsing them discards the distinction the disclosure was
issued to make.

Whether `receipt_gap_disclosed` is accepted or rejected MUST be a verifier policy input,
not implementation-defined behaviour. A relying party evaluating a payment authorisation
and one evaluating a telemetry batch will reasonably differ, and neither should have to
change verifier to express that. One bound on that policy is not negotiable: a profile
that requires independently proven completeness of the receipt chain MUST NOT accept
`receipt_gap_disclosed` as satisfying it. A disclosed gap is an attested absence, not a
proof of completeness, and no policy setting may promote the former into the latter.

A `GapDisclosure` that fails signature verification, is not bound into the chain from
both directions, names a session other than the stream under verification, is signed by
a key outside the permitted set, or whose claimed gap is contradicted by chain elements
that are in fact present, MUST yield `receipt_invalid` rather than falling back to
`receipt_missing_required`. A forged, transplanted or self-contradictory disclosure is
worse evidence than no disclosure: it is an attempt to convert silence into attestation,
and the attempt itself is a finding.

**Reporting.** A verification result MUST report each disclosed gap individually,
carrying at minimum the linked predecessor, the number of consecutive disclosures, and
the `cause` when one was supplied. Reducing disclosed gaps to a count or a boolean
discards exactly the detail a relying party's policy needs.

The conformance vectors for this section are `examples/action-receipts/gap-disclosure/`:
twenty fixtures, two independent vectors per rule, with a generator that reproduces them
byte for byte, and the live-tail contrast pinned by a dedicated test.

### 3.4 Scope

TRACE governs any confidential workload: AI agent execution, regulated data processing, sovereign compute, secure multi-party computation. AI agents are the forcing function and the first reference profile, not the limit of the standard.

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

- **RATS / EAT (RFC 9711)**: wire envelope and claim model. NVIDIA NRAS, Intel Trust Authority, and Azure MAA produce attestation tokens that map into this envelope through vendor-co-authored annexes (see §4.4).
- **SLSA Provenance v1.0**: build-time provenance. Build Level 2 minimum for TRACE-conformant records in v1.0; Build Level 3 is the target for production reference implementations.
- **SPIFFE / SPIRE**: workload identity. The SVID is bound to the TEE measurement so identity is rooted in hardware.
- **SCITT**: append-only transparency log. TRACE defines a SCITT profile for Trust Record inclusion (Signed Statement registration, Receipt format, key rotation semantics).
- **EAR (draft-ietf-rats-ar4si)**: verifier output format. Separates *what was claimed* from *what was accepted*.
- **MCP**: Model Context Protocol tool surface. TRACE adds (a) cryptographic binding of the transcript hash into the EAT envelope and (b) a per-call `data_class` classification. The normative MCP profile is not in this version; it is targeted for v0.3.
- **A2A**: Agent-to-Agent communication. TRACE adds transcript binding and cross-protocol identity threading via SPIFFE SVID. The `delegation` link block (§3.1) landed in v0.2 as the foundation; the normative A2A binding rules are targeted for v0.3.
- **AIBOM (SPDX 3.0 AI Profile, CycloneDX 1.7 ML-BOM)**: component inventory for models, datasets, dependencies. Referenced by digest from `model`.
- **C2PA**: adjacent, not absorbed. Where a TRACE'd execution produces media, the output may carry a C2PA manifest that references the Trust Record.

### 4.2 Hardware roots

- **NVIDIA**: H100, H200, Blackwell with confidential computing mode. NRAS EAT.
- **Intel**: TDX with Trust Authority. TDX Quote (DCAP) + MRTD + RTMRs.
- **AMD**: SEV-SNP with VCEK/VLEK chain to AMD Root Key. CoRIM CBOR mapping.
- **Cloud platform attestation**: Azure MAA, GCP Confidential Space, AWS Nitro Enclaves all expressible as RATS Evidence and composable into a TRACE envelope.

### 4.3 Bindings TRACE adds

These components exist in their respective ecosystems. TRACE adds the binding rule that places each into a hardware-attested envelope:

- **`policy` claim.** Policy artifacts (OPA bundles, Cedar policies, custom DSLs) and policy hashing are established. TRACE adds the binding: the policy bundle hash is sealed to the TEE measurement, the enforcement mode is recorded, and substituting the policy invalidates the runtime claim. Gateways MUST default `enforcement_mode` to `enforce`. A deployment MUST explicitly configure `silent` mode; `silent` MUST NOT be the default. In `silent` mode, the audit chain still records every would-have-denied decision; only operational log lines are suppressed.

  **`enforcement_mode: "declared"`.** The three modes above all assert that *something evaluated the policy*. `declared` asserts less: the policy is named and bound into the signed record, and nothing evaluated it. That is not a corner case, it is the common one for a producer with no policy engine: an agent framework observed by an adapter has a policy the operator declares and no evaluation of it anywhere, and with only three values such a record had to claim an evaluation that never happened.

  `declared` is the weakest value and MUST NOT be a default. A producer that evaluates policy MUST NOT use it. A consumer MUST NOT read it as evidence that any rule was checked; it says only that this is the policy the deployment states it was operating under. A verifier appraising for enforcement SHOULD treat `declared` as it treats an absent enforcement claim.
- **`data_class` claim.** Data classification schemes are established (DLP labels, NIST SP 800-60, sensitivity tags). TRACE adds: a classification label is attached to inputs and outputs at the per-call layer and recorded in the Trust Record alongside the runtime evidence.
- **`tool_transcript` claim.** MCP and A2A transcripts exist at the protocol layer. TRACE adds cryptographic binding of the transcript hash into the EAT envelope and per-call parameter classification.
- **AI-agent execution profile.** A profile registry that pins the claim set, evidence requirements, and verification rules for AI-agent workloads specifically.

### 4.4 Vendor profile annexes

TRACE will publish vendor-co-authored claim-mapping annexes, one per silicon-root and cloud-attestation surface, as informative companions to v1.0. Co-editor slots open for:

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
| **Phase 1: Runtime Trust** | MCP server runs in TEE; SPIFFE identity bound to TEE measurement; signed Trust Record per invocation | `subject`, `runtime`, `build_provenance`, `cnf`, `transparency` | Q2 2026 |
| **Phase 2: Policy Enforcement** | Transparent JSON-RPC proxy inside TEE; per-tool policy + parameter classification | + `policy`, `data_class`, `tool_transcript` | Q3 2026 |
| **Phase 3: Workflow Provenance** | Native SDK; cross-MCP lineage; provenance DAG | Full Trust Record | Q4 2026+ |

**Hardware:** Intel TDX, AMD SEV-SNP, NVIDIA H100/Blackwell CC.

**Deployment: ** Confidential VMs and Confidential Containers (Kata-CC) on AKS, GCP Confidential Space, AWS Nitro Enclaves, and on-prem. BYOW: existing MCP servers run unchanged.

---

## 6. Governance

### 6.1 Host

**The Linux Foundation**, as its own series: "TRACE Specification, a Series of LF Projects, LLC". Formation is in progress; on completion, governance transitions to a Technical Steering Committee as defined in `CHARTER.md`, and spec, IP, trademark, and conformance mark sit with the series.

This supersedes the earlier proposal to split the technical workstream to CoSAI and the spec, IP and trademark to the Linux Foundation entity hosting the Model Context Protocol. That arrangement made TRACE a guest of two hosts, neither of which owned the conformance mark outright.

Other standards bodies participate as technical-liaison partners: OpenSSF (SLSA stewardship), CNCF (SPIFFE/SPIRE stewardship), IETF (RATS, EAT, SCITT, EAR working groups), CoSAI (WS4 interoperability).

### 6.2 Target contributing organizations

The following organizations have been identified as natural contributors to this standard based on their work in confidential computing, AI safety, and open governance. Formal participation is subject to each organization's independent decision.

Anthropic, NVIDIA, Intel, AMD, Microsoft, Google, Linux Foundation, Confidential Computing Consortium, ATRC, TII, AI71.

### 6.3 IP and licensing

- **Specifications:** Community Specification License 1.0. Earlier publications and carried-forward text remain available under the licenses stated when they were published.
- **Reference code:** Apache 2.0.
- **Test suite:** Apache 2.0, mandatory for conformance claims.
- **Conformance mark:** managed by host org.

---

## 7. Open Questions

These need input before v1.0. Two are now resolved and are kept here, marked, so a reader tracking them can see how they landed.

1. ~~**Host organization.** CoSAI, Linux Foundation, or a federated arrangement?~~ **Resolved:** the Linux Foundation, as TRACE's own series. See §6.1.
2. **AI-agent profile vs general profile.** One inclusive profile or split agent execution and generic confidential workload from day one?
3. **Transparency log operator(s).** One canonical SCITT log, federated logs, or BYO with conformance criteria?
4. **Policy language.** TRACE binds a policy *hash*. Does v1.0 also specify a policy *language* (Cedar, Rego, custom DSL), or stay language-agnostic?
5. **Privacy of the record.** Records may contain sensitive classifications. Standardize encrypted-claims envelope (JWE / COSE-Encrypt) from v1.0?
6. ~~**A2A profile timing.** Ship A2A as a peer profile to MCP in v1.0, or wait for A2A to stabilize?~~ **Resolved:** A2A is stable at v1.x, which cleared the blocker. The `delegation` link block landed in v0.2 and the normative binding rules are targeted for v0.3, as a peer profile to MCP.
7. **Relationship to IETF AIIP.** Absorb, supersede, or coexist with draft-ritz-aiip?

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| TCB | Trusted Computing Base. Components whose correctness a TRACE Record's validity depends on |
| TEE | Trusted Execution Environment: Intel TDX, AMD SEV-SNP, NVIDIA H100/Blackwell CC |
| EAT | Entity Attestation Token (RFC 9711). RATS wire envelope. JWT or CBOR-COSE |
| RATS | Remote Attestation Procedures (IETF). The attestation architecture |
| EAR | EAT Attestation Results: verifier appraisal output format |
| SLSA | Supply-chain Levels for Software Artifacts (OpenSSF). Build-time provenance |
| SCITT | Supply Chain Integrity, Transparency, Trust (IETF). Append-only transparency log primitive |
| SPIFFE | Secure Production Identity Framework For Everyone (CNCF). Workload identity |
| AIBOM | AI Bill of Materials (SPDX 3.0 AI Profile, CycloneDX 1.7 ML-BOM) |
| MCP | Model Context Protocol. Agent tool-call surface |
| A2A | Agent-to-Agent (Google). Inter-agent communication protocol |
| C2PA | Coalition for Content Provenance and Authenticity. Content origin manifests |
| RIM | Reference Integrity Manifest. Vendor-published reference measurements |
| Trust Record | TRACE's portable signed artifact: see §3 |
| cMCP | Confidential MCP: TRACE reference implementation at the MCP boundary |

---

## Appendix B: References

### IETF

- RATS Architecture (RFC 9334): https://www.rfc-editor.org/rfc/rfc9334
- EAT, Entity Attestation Token (RFC 9711), https://www.rfc-editor.org/rfc/rfc9711
- SCITT Architecture (draft-ietf-scitt-architecture): https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
- SCITT Reference APIs (draft-ietf-scitt-scrapi): https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
- EAR / AR4SI (draft-ietf-rats-ar4si): https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/
- JWS (RFC 7515): https://www.rfc-editor.org/rfc/rfc7515
- JWE (RFC 7516): https://www.rfc-editor.org/rfc/rfc7516
- COSE (RFC 9052/9053): https://www.rfc-editor.org/rfc/rfc9052
- JWK / cnf claim (RFC 7517 / RFC 7800): https://www.rfc-editor.org/rfc/rfc7517
- JWK Thumbprint (RFC 7638): https://www.rfc-editor.org/rfc/rfc7638
- JSON Canonicalization Scheme / JCS (RFC 8785): https://www.rfc-editor.org/rfc/rfc8785

### Foundation Specifications

- SLSA Specification v1.0 (OpenSSF): https://slsa.dev/spec/v1.0/
- SPIFFE / SPIRE Specifications (CNCF): https://spiffe.io/docs/latest/spiffe-about/
- SPDX 3.0 AI Profile: https://spdx.dev/use/specifications/
- CycloneDX 1.7 ML-BOM: https://cyclonedx.org/specification/overview/
- C2PA Technical Specification v2: https://c2pa.org/specifications/specifications/2.0/
- Sigstore / Rekor: https://docs.sigstore.dev/

### Vendor Hardware Attestation

- NVIDIA Remote Attestation Service: https://docs.nvidia.com/attestation/api-docs-nras/
- Intel Trust Authority: https://www.intel.com/content/www/us/en/security/trust-authority.html
- Intel TDX: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- AMD SEV-SNP: https://www.amd.com/en/developer/sev.html
- Microsoft Azure Attestation: https://learn.microsoft.com/en-us/azure/attestation/overview
- Microsoft Azure Confidential Ledger: https://learn.microsoft.com/en-us/azure/confidential-ledger/
- GCP Confidential Space: https://cloud.google.com/confidential-computing/confidential-space/docs
- AWS Nitro Enclaves: https://aws.amazon.com/ec2/nitro/nitro-enclaves/

### Adjacent Work

- Project Oak (Google DeepMind): https://github.com/project-oak/oak
- Anthropic MCP Specification: https://modelcontextprotocol.io/specification/
- Google A2A Specification: https://a2a-protocol.org/latest/specification/
- MITRE ATLAS: https://atlas.mitre.org/
- OWASP Top 10 for Agentic Applications: https://genai.owasp.org/
