# Trust Levels

This page explains the three levels of evidence a TRACE record can carry, from a plain software signature up to hardware proof and a public log entry. Read it if you produce records and need to know what each level asks of you, or if you receive records and need to decide how much to trust them.

TRACE's conformance suite (the public set of tests an implementation runs to show it follows the specification) groups its checks into three levels. A level describes which checks are required; it is not a blanket guarantee that an agent behaved correctly. The recipient still supplies its own trust anchors (the keys and roots it already trusts), the evidence, and the rules for what it will accept.

- **Level 0, software:** the record is signed with a key held in ordinary software.
- **Level 1, hardware evidence:** the record also carries a signed report from the processor showing where it ran.
- **Level 2, transparency:** the record is also published to an append-only log that others can audit.

## Summary

| Level                | Adds                                                   | What still needs scrutiny                                                                            |
| -------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| 0: software          | Record structure, signing, policy and appraisal fields | Trusted issuer, truth of producer claims, software key custody                                       |
| 1: hardware evidence | Runtime and build-provenance checks                    | Actual quote appraisal, expected measurements, key binding, provider-specific limits                 |
| 2: transparency      | Transcript and anchoring checks                        | Authenticated log/checkpoint, inclusion proof, record binding, completeness of the submitted history |

See the [suite's level definitions](https://tests.agentrust-io.com/docs/levels/) for required modules and its [limitations](https://tests.agentrust-io.com/LIMITATIONS/) for what a pass establishes. Record-format checks must not be described as a fresh hardware appraisal unless that evidence was actually verified.

## Level 0: software-only

A key held in ordinary software signs the record. The platform value `software-only` says plainly that no hardware backs the record. A recipient checks the signature against a key obtained through its own trust channel; the key embedded in an incoming record cannot establish its own authority.

A valid signature shows that the holder of that key made the statement. It does not prove that a policy ran or an action completed, and anyone who controls that key can sign other statements too.

Every record, even a software-only one, carries a `runtime.measurement` value, and `appraisal.status` is `"none"` when no hardware checker was involved. Use the [quick start](https://trace.agentrust-io.com/docs/quickstart/index.md) for a complete runnable record rather than copying abbreviated field examples.

Technical detail: `runtime.measurement` on a software-only record

`runtime.measurement` is required on every record, including `software-only` ones. Under `software-only`, the field is not a hardware measurement: it is a software commitment defined by the producing profile (for example, a hash over an image digest and policy bundle, or over a chain-tip), and that profile must document its preimage so a verifier can recompute it. All-zero (`sha256:000...000`) is reserved for a producer that has no commitment to offer at all, such as a bare development record with nothing measured; it is not the default for `software-only` in general. The `appraisal.status` of `"none"` is correct when no hardware verifier is in the path.

## Level 1: hardware evidence

At Level 1 the record also points to evidence from the hardware it ran on. Confidential-computing processors from AMD, Intel and NVIDIA can produce a signed report (called a quote or attestation) describing the protected environment, and a verifier checks that report against the manufacturer's keys. It also records build provenance: where the software came from and how it was built.

| Build-provenance field        | Schema range                                                        |
| ----------------------------- | ------------------------------------------------------------------- |
| `build_provenance.slsa_level` | SLSA Build Level (0-3); verify the supporting provenance separately |

A hardware-backed deployment needs authenticated evidence tying the record-signing key to the expected environment. Merely changing `runtime.platform`, copying a nonzero digest, or setting `appraisal.status="affirming"` does not establish that evidence.

Use the standalone platform identifiers from the [schema](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-claim.json), not a runtime's configuration aliases. Provider guarantees differ: a TPM quote is not equivalent to protecting application memory in a confidential VM. See [attestation platforms](https://trace.agentrust-io.com/docs/platforms/index.md).

`agentrust_trace.verify_record` does not itself appraise hardware quotes. A producing runtime's verifier must perform the relevant evidence checks. cMCP uses a different envelope; see [cMCP verification](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/).

## Level 2: transparency anchoring

Level 2 adds two things on top of the lower levels: the record is published to a transparency log (an append-only public list that nobody can quietly edit), and the record commits to the transcript of tool calls the agent made. A `transparency` URI is a reference, not an inclusion proof. The verifier needs proof bound to the record and a log or checkpoint it independently trusts. Inclusion does not establish that every event was logged or that each claim is true.

Changing any signed field, including `transparency`, changes the bytes the signature covers. Re-sign after adding or changing that field. The [registry anchor format](https://trace.agentrust-io.com/spec/registry-anchor-v1/index.md) defines which bytes the anchor commits to; the receipt must match that format and the signed record being checked.

For the worked sequence, see [anchoring to the registry](https://trace.agentrust-io.com/docs/tutorials/anchoring-to-the-registry/index.md). A software-only record does not become hardware-backed simply because it is logged.

## Choosing an acceptance policy

An acceptance policy is your own rule for when you will rely on a record. Decide which issuer, hardware evidence, artifact commitments, freshness, revocation status, and log you require for the operation. A successful signature check is only one input to that decision. These levels do not certify regulatory compliance or replace application authorization.

Read [verification protocol](https://trace.agentrust-io.com/docs/verification/index.md) for the checks and [limitations](https://trace.agentrust-io.com/LIMITATIONS/index.md) for the remaining boundaries.
