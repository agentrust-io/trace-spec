# Known Limitations

This document describes what TRACE does not do, and where layered defenses are needed. Honest scope boundaries prevent misplaced trust.

## What a TRACE claim does not prevent

**Operator-forged software-only records**
A TRACE claim at Level 0 (software-only signing) is signed by a key held in software. A privileged operator with root access can produce a valid-looking Level 0 record for a run that never happened, or that violated policy. Level 0 is suitable for development and audit-trail tooling only — not for third-party verification.

**Replay of a valid past record**
A TRACE claim proves a specific run happened; it does not prevent a verifier from being shown a valid record from an earlier run. Verifiers that rely on recency must bound `iat` in both directions (maximum age and allowed future clock skew), check `exp` when present, require nonce binding to a challenge, or anchor records to a public transparency log and check for freshness.

**Policy correctness**
The `policy.bundle_hash` field attests that a specific policy was in force at runtime. It does not attest that the policy achieves the intended security outcome. Policy review is a separate control.

**What happened inside the model**
The call transcript records tool invocations, arguments, and responses that are observable at the gateway boundary. It does not record the model's internal chain-of-thought, intermediate reasoning, or context window contents. Reasoning that influences behavior without producing a tool call is not captured.

**Cross-boundary data propagation**
The call graph summary uses temporal adjacency to approximate data flow between tool calls. It cannot definitively prove which specific data from one tool response influenced which subsequent call. The `provenance_disclaimer` field in every call graph summary is required for this reason.

**TEE side-channel attacks**
Hardware attestation proves the TRACE signing key and policy engine were measured in silicon before execution. It does not protect against side-channel attacks (cache timing, power analysis) targeting the TEE itself. TEE-level side-channel defense is the responsibility of the TEE platform vendor.

**Revocation of the signing key after issuance**
If the TRACE signing key is compromised after records are issued, existing records remain cryptographically valid. Key monitoring, rapid revocation, and transparency log integration are the required controls — TRACE provides the anchoring mechanism but cannot detect compromise itself.

**Pure offline verification cannot prove non-revocation**
Signature validity is permanent; trust is not. Nothing inside a record can retract the key that signed it, so a record signed by a since-revoked key verifies offline forever. Spec §3.2.1 accordingly requires verifiers to consult current revocation status at verification time, which is by definition an online step. `verify_record()` takes a `revocation` store, either a container of revoked identifiers or a callable performing a live CRL, status-endpoint, or SCITT lookup. It rejects a listed key, and fails closed when the store cannot answer. Without that store, verification is offline and its result means "this record was validly signed by this key", not "this key is still trusted".

## Platform state is not appraised

<!-- This is the source copy of the marked block. cmcp and ca2a carry it
     verbatim and their limitations-parity workflows check it against this
     file, so a change here has to land before theirs. The paragraph after
     the end marker is TRACE's own and is not shared. -->

<!-- shared:platform-state-appraisal begin -->
The SEV-SNP path here establishes that a report is authentic and which workload it
describes: report signature, the VCEK to ASK to ARK chain with the ARK pinned by the
operator, and measurement binding. Those are the right four checks and they are not
in dispute.

**What none of them ask is what kind of machine the report came from.** A SEV-SNP
report carries that separately in `PLATFORM_INFO` at offset 0x40: whether SMT is on,
whether ECC is enabled, whether ciphertext hiding is enforced, and whether the
firmware completed its boot-time DRAM alias check, which is AMD's mitigation for
BadRAM (security bulletin SB-3015).

The practical consequence: a report from a machine with SMT enabled and the alias
check never completed verifies exactly as cleanly as one from a machine with neither
condition. If that distinction matters to your deployment, it has to be asserted
explicitly.

Related: [google/go-sev-guest#195](https://github.com/google/go-sev-guest/issues/195),
where the reference verifier's own platform-info policy field is documented as a
ceiling while four of its seven fields are enforced as minimums. Worth reading before
writing any policy over these bits.
<!-- shared:platform-state-appraisal end -->

**In TRACE.** A TRACE claim's runtime block carries the measurement and the evidence
and has no field for platform state, so a verifier reading a conformant claim cannot
appraise it even where the producer checked it. The spec does not assert it for you.

## What Level 0 does not provide

Level 0 (software-only signing) is suitable for development, internal audit trails, and staging environments. It does not satisfy:

- EU AI Act Art. 12 (tamper-evident logging) — requires Level 1+
- DORA Art. 9 (ICT risk management) — requires Level 1+ with transparency log anchoring
- Any claim of hardware-rooted trust — the signing key is held in software and can be extracted by a privileged operator

## What the SDK does not do

- **Evaluate Cedar policy** — the SDK includes the Cedar policy field in the claim; evaluation requires the Cedar engine (included in AGT or cMCP)
- **Store or index records** — the SDK produces and verifies TRACE claim documents; storage, rotation, and retrieval are the caller's responsibility
- **Anchor to a transparency log** — the SDK generates records suitable for SCITT anchoring; submission to a transparency log requires a separate SCITT client
- **Replace a secrets manager** — signing private keys must be stored in a secrets manager (Azure Key Vault, AWS Secrets Manager, HSM); do not store them on disk without protection
- **Provide an authoritative verification service** — the self-hosted verifier confirms cryptographic validity against the issuer's key; authoritative third-party verification with SLA is a separate commercial service

## Performance

Hardware attestation adds latency at the point of claim generation (not per-tool-call):

| Provider | Typical claim signing latency |
|---|---|
| Software (Level 0) | < 1 ms |
| TPM | 50–200 ms |
| SEV-SNP | 10–50 ms |
| TDX | 10–50 ms |

Claim verification (signature check + schema validation) is < 5 ms in all cases.
