# Known Limitations

This document describes what TRACE does not do, and where layered defenses are needed. Honest scope boundaries prevent misplaced trust.

## What a TRACE claim does not prevent

**Operator-forged software-only records**
A TRACE claim at Level 0 (software-only signing) is signed by a key held in software. A privileged operator with root access can produce a valid-looking Level 0 record for a run that never happened, or that violated policy. Level 0 is suitable for development and audit-trail tooling only — not for third-party verification.

**Replay of a valid past record**
A TRACE claim proves a specific run happened; it does not prevent a verifier from being shown a valid record from an earlier run. Verifiers that rely on recency must check the `iat` and `exp` claims, require nonce binding to a challenge, or anchor records to a public transparency log and check for freshness.

**Policy correctness**
The `policy.bundle_hash` field attests that a specific policy was in force at runtime. It does not attest that the policy achieves the intended security outcome. Policy review is a separate control.

**What happened inside the model**
The call transcript records tool invocations, arguments, and responses that are observable at the gateway boundary. It does not record the model's internal chain-of-thought, intermediate reasoning, or context window contents. Reasoning that influences behavior without producing a tool call is not captured.

**Physical execution or functional safety**
TRACE can bind optional downstream evidence, such as a controller-signed receipt attached by a cMCP audit-chain profile. That proves only that a trusted external issuer signed the receipt for the bound call. It does not prove that a physical action occurred, completed successfully, or satisfied functional-safety standards.

**Cross-boundary data propagation**
The call graph summary uses temporal adjacency to approximate data flow between tool calls. It cannot definitively prove which specific data from one tool response influenced which subsequent call. The `provenance_disclaimer` field in every call graph summary is required for this reason.

**TEE side-channel attacks**
Hardware attestation proves the TRACE signing key and policy engine were measured in silicon before execution. It does not protect against side-channel attacks (cache timing, power analysis) targeting the TEE itself. TEE-level side-channel defense is the responsibility of the TEE platform vendor.

**Revocation of the signing key after issuance**
If the TRACE signing key is compromised after records are issued, existing records remain cryptographically valid. Key monitoring, rapid revocation, and transparency log integration are the required controls — TRACE provides the anchoring mechanism but cannot detect compromise itself.

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
