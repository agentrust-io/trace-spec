---
description: Understand TRACE's software, hardware, and transparency evidence levels and the checks a relying party still needs to perform.
---

# Trust Levels

TRACE's conformance suite groups checks into three levels. A level describes required checks; it is not a blanket guarantee that an agent behaved correctly. The recipient supplies trust anchors, evidence, and an acceptance policy.

## Summary

| Level | Adds | What still needs scrutiny |
|---|---|---|
| 0: software | Record structure, signing, policy and appraisal fields | Trusted issuer, truth of producer claims, software key custody |
| 1: hardware evidence | Runtime and build-provenance checks | Actual quote appraisal, expected measurements, key binding, provider-specific limits |
| 2: transparency | Transcript and anchoring checks | Authenticated log/checkpoint, inclusion proof, record binding, completeness of the submitted history |

See the [suite's level definitions](https://tests.agentrust-io.com/docs/levels/) for required modules and its [limitations](https://tests.agentrust-io.com/LIMITATIONS/) for what a pass establishes. Record-format checks must not be described as a fresh hardware appraisal unless that evidence was actually verified.

## Level 0: software-only

A software-held key signs the record. `software-only` identifies the absence of hardware assurance. A recipient checks the signature against a key obtained through its own trust channel; the key embedded in an incoming record cannot establish its own authority.

A valid signature authenticates the key's statement. It does not prove that a policy ran or an action completed. A privileged party holding that key can sign other statements.

`runtime.measurement` is required on every record, including `software-only` ones. Under `software-only`, the field is not a hardware measurement: it is a software commitment defined by the producing profile (for example, a hash over an image digest and policy bundle, or over a chain-tip), and that profile must document its preimage so a verifier can recompute it. All-zero (`sha256:000...000`) is reserved for a producer that has no commitment to offer at all, such as a bare development record with nothing measured; it is not the default for `software-only` in general. The `appraisal.status` of `"none"` is correct when no hardware verifier is in the path. Use the [quick start](quickstart.md) for a complete runnable record rather than copying abbreviated field examples.

## Level 1: hardware evidence

| Build-provenance field | Schema range |
|---|---|
| `build_provenance.slsa_level` | SLSA Build Level (0-3); verify the supporting provenance separately |

A hardware-backed deployment needs authenticated evidence binding the record-signing key to the expected environment. Merely changing `runtime.platform`, copying a nonzero digest, or setting `appraisal.status="affirming"` does not establish that evidence.

Use the standalone platform identifiers from the [schema](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-claim.json), not a runtime's configuration aliases. Provider guarantees differ: a TPM quote is not equivalent to protecting application memory in a confidential VM. See [attestation platforms](platforms/index.md).

`agentrust_trace.verify_record` does not itself appraise hardware quotes. A producing runtime's verifier must perform the relevant evidence checks. cMCP uses a different envelope; see [cMCP verification](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/).

## Level 2: transparency anchoring

Level 2 adds transparency and transcript requirements to the lower levels. A `transparency` URI is a reference, not an inclusion proof. The verifier needs proof bound to the record and a log or checkpoint it independently trusts. Inclusion does not establish that every event was logged or that each claim is true.

Changing any signed field, including `transparency`, changes the signature preimage. Re-sign after adding or changing that field. The [registry anchor format](../spec/registry-anchor-v1.md) defines which bytes the anchor commits to; the receipt must match that format and the signed record being checked.

For the worked sequence, see [anchoring to the registry](tutorials/anchoring-to-the-registry.md). A software-only record does not become hardware-backed simply because it is logged.

## Choosing an acceptance policy

Decide which issuer, hardware evidence, artifact commitments, freshness, revocation status, and log you require for the operation. A successful signature check is only one input to that decision. These levels do not certify regulatory compliance or replace application authorization.

Read [verification protocol](verification.md) for the checks and [limitations](../LIMITATIONS.md) for the remaining boundaries.
