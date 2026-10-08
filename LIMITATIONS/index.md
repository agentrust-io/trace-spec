# Known Limitations

This page lists what TRACE does not do, so you know where you still need other safeguards. Read it before you rely on a TRACE record for anything that matters. A TRACE record (also called a Trust Record or claim) is a signed receipt describing one AI agent run; most of what follows is about the gap between "this receipt is genuine" and "what it describes really happened".

## What a TRACE claim does not prevent

**Operator-forged software-only records** Level 0 is the entry level, where a record is signed with an ordinary software key and no hardware evidence. Whoever runs the machine can read that key. A privileged operator with root access can produce a valid-looking Level 0 record for a run that never happened, or that violated policy. Level 0 is suitable for development and audit-trail tooling only, not for third-party verification.

**Replay of a valid past record** A genuine old record stays genuine, so someone can show you last week's record and pass it off as today's. A TRACE claim proves a specific run happened; it does not prevent a verifier from being shown a valid record from an earlier run. Verifiers that rely on recency must bound `iat` in both directions (maximum age and allowed future clock skew), check `exp` when present, require nonce binding to a challenge, or anchor records to a public transparency log and check for freshness.

**Policy correctness** A record can show which rules the agent ran under, but not whether those rules were any good. The `policy.bundle_hash` field attests that a specific policy was in force at runtime. It does not attest that the policy achieves the intended security outcome. Policy review is a separate control.

**What happened inside the model** TRACE sees what the agent did, not what the model thought. The call transcript records tool invocations, arguments, and responses that are observable at the gateway boundary. It does not record the model's internal chain-of-thought, intermediate reasoning, or context window contents. Reasoning that influences behavior without producing a tool call is not captured.

**Cross-boundary data propagation** TRACE can show that one tool call came after another, but not prove that data from the first actually fed the second. The call graph summary uses temporal adjacency to approximate data flow between tool calls. It cannot definitively prove which specific data from one tool response influenced which subsequent call. The `provenance_disclaimer` field in every call graph summary is required for this reason.

**TEE side-channel attacks** A TEE (trusted execution environment) is a sealed area of a processor that even the machine's operator cannot look into. Hardware attestation, the processor's signed report of what is running inside it, proves the TRACE signing key and policy engine were measured in silicon before execution. It does not protect against side-channel attacks (cache timing, power analysis) targeting the TEE itself. TEE-level side-channel defense is the responsibility of the TEE platform vendor.

**Revocation of the signing key after issuance** If a signing key is stolen later, everything it already signed still checks out. If the TRACE signing key is compromised after records are issued, existing records remain cryptographically valid. Key monitoring, rapid revocation, and transparency log integration are the required controls: TRACE provides the anchoring mechanism but cannot detect compromise itself.

**Pure offline verification cannot prove non-revocation** Checking a record with no network connection tells you it was signed by a given key, but not whether that key has since been withdrawn. Signature validity is permanent; trust is not. Nothing inside a record can retract the key that signed it, so a record signed by a since-revoked key verifies offline forever. Spec §3.2.1 accordingly requires verifiers to consult current revocation status at verification time, which is by definition an online step. `verify_record()` takes a `revocation` store, either a container of revoked identifiers or a callable performing a live CRL, status-endpoint, or SCITT lookup. It rejects a listed key, and fails closed when the store cannot answer. Without that store, verification is offline and its result means "this record was validly signed by this key", not "this key is still trusted".

## Platform state is not appraised

An AMD processor's signed report says which software is running and, separately, how the machine itself is configured. The checks described here cover the first part only, so a report from a machine with weaker security settings passes just as cleanly.

The SEV-SNP path here establishes that a report is authentic and which workload it describes: report signature, the VCEK to ASK to ARK chain with the ARK pinned by the operator, and measurement binding. Those are the right four checks and they are not in dispute.

**What none of them ask is what kind of machine the report came from.** A SEV-SNP report carries that separately in `PLATFORM_INFO` at offset 0x40: whether SMT is on, whether ECC is enabled, whether ciphertext hiding is enforced, and whether the firmware completed its boot-time DRAM alias check, which is AMD's mitigation for BadRAM (security bulletin SB-3015).

The practical consequence: a report from a machine with SMT enabled and the alias check never completed verifies exactly as cleanly as one from a machine with neither condition. If that distinction matters to your deployment, it has to be asserted explicitly.

Related: [google/go-sev-guest#195](https://github.com/google/go-sev-guest/issues/195), where the reference verifier's own platform-info policy field is documented as a ceiling while four of its seven fields are enforced as minimums. Worth reading before writing any policy over these bits.

**In TRACE.** A TRACE claim's runtime block carries the measurement and the evidence and has no field for platform state, so a verifier reading a conformant claim cannot appraise it even where the producer checked it. The spec does not assert it for you.

## What Level 0 does not provide

Level 0 is useful for development and for keeping an audit trail, but it is not evidence an outside party should accept on its own. Level 0 provides software signatures without hardware-rooted assurance. A privileged operator may extract the signing key; a valid signature does not establish that execution was protected by a TEE.

TRACE levels describe the strength of technical evidence; they say nothing about legal compliance. Article 12 of the EU AI Act requires a logging capability; it does not prescribe a TRACE level or tamper-evident format. See the [regulatory context in the specification](https://trace.agentrust-io.com/spec/trace-v0.2/#1-problem). Neither a TRACE level nor transparency-log anchoring alone establishes compliance with the EU AI Act or DORA. Deployment-specific obligations require a separate assessment.

## What the SDK does not do

The SDK is the `agentrust-trace` Python library that signs and checks records. These jobs sit outside it:

- **Evaluate Cedar policy**: the SDK includes the Cedar policy field in the claim; evaluation requires the Cedar engine (included in AGT or cMCP)
- **Store or index records**: the SDK produces and verifies TRACE claim documents; storage, rotation, and retrieval are the caller's responsibility
- **Anchor to a transparency log**: the SDK generates records suitable for SCITT anchoring; submission to a transparency log requires a separate SCITT client
- **Replace a secrets manager**: signing private keys must be stored in a secrets manager (Azure Key Vault, AWS Secrets Manager, HSM); do not store them on disk without protection
- **Provide an authoritative verification service**: the self-hosted verifier confirms cryptographic validity against the issuer's key; authoritative third-party verification with SLA is a separate commercial service

## Performance

Hardware evidence makes signing a record slower, once per record rather than on every tool call:

| Provider           | Typical claim signing latency |
| ------------------ | ----------------------------- |
| Software (Level 0) | < 1 ms                        |
| TPM                | 50 to 200 ms                  |
| SEV-SNP            | 10 to 50 ms                   |
| TDX                | 10 to 50 ms                   |

Claim verification (signature check + schema validation) is < 5 ms in all cases.
