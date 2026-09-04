# N'KEMBA Institutional Reconstruction Consumer Cross-walk

> **Non-normative.** This document is informative only. Nothing here changes a TRACE schema field, wire format, required claim, or conformance requirement. References to TRACE mean the TRACE v0.2 Trust Record defined in [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md). References to N'KEMBA mean a downstream consumer that reconstructs whether an institutional outcome is supported by independently verified evidence.

---

## Purpose

TRACE records verifiable facts about an agent execution and the environment in which it occurred. N'KEMBA consumes those facts alongside evidence from other institutional layers: authorization, approvals, operative documents, external outcomes, and organizational adoption.

This cross-walk describes how a downstream N'KEMBA evaluation can use TRACE evidence without treating a reference as the evidence it points to, without turning a valid runtime attestation into proof of a later institutional outcome, and without adding N'KEMBA-specific fields to TRACE.

The two systems answer different questions:

- TRACE supports verification of a runtime trust record and its claims.
- N'KEMBA evaluates whether evidence across several layers supports an institutional conclusion.
- A successful TRACE verification can satisfy the runtime layer of a N'KEMBA evaluation. It does not, by itself, satisfy the other layers.

## Evidence-layer mapping

| N'KEMBA layer | TRACE input | What it can satisfy | What it does not satisfy by itself |
|---|---|---|---|
| Runtime | Verified Trust Record, including applicable attestation and transcript checks | Identity and integrity of the verified runtime claims | Authorization, external completion, or institutional adoption |
| Authorized intent | A `references` entry with `rel: "authorized-intent"` | Discovery and binding of a pointer to the relevant intent artifact | Authenticity, authority, legal effect, or contents of the resolved artifact |
| Approval outcome | A `references` entry with `rel: "approval-outcome"` | Discovery and binding of a pointer to an approval result | Valid authority, scope, completeness, or continued validity of the approval |
| Behaviour trace | A `references` entry with `rel: "behavior-trace"` | Discovery and binding of a pointer to supporting execution evidence | Correctness, safety, or real-world effect of the behaviour |
| Action receipt | External action-receipt evidence verified independently | Evidence that an issuer made the recorded decision or assertion | Real-world completion, reversibility, or downstream acceptance |
| Operative document | Resolved external artifact plus digest, provenance, and version evidence | Identification and integrity of the exact document evaluated | Whether the document was in force or adopted by the competent institution |
| External outcome | Separately obtained outcome evidence | Evidence of the reported external state when provenance and scope check out | Runtime integrity or authority for the originating action |
| Adoption | Separately obtained institutional evidence | Evidence that the competent body adopted or implemented the result | Truth of every underlying claim or continued operational effect |

TRACE v0.2 section 3.1.2 defines a `references` entry as a pointer, not as evidence. A N'KEMBA consumer therefore preserves the pointer and its binding metadata separately from the resolved artifact and never promotes the pointer alone into attested evidence.

## Consumer processing

A N'KEMBA consumer applying this cross-walk:

1. verifies the TRACE Trust Record under the TRACE verification procedure;
2. records the verification result, the exact record or its stable digest, the TRACE version, and the verification time;
3. ingests registered `references.rel` values as typed pointers only;
4. resolves referenced artifacts out of band and records their provenance, digest, version, issuer, relevant time, and resolution result;
5. evaluates each institutional layer independently;
6. reports missing, unknown, conflicting, and adverse evidence without converting those states into a positive conclusion.

A fail-closed N'KEMBA evaluation uses the following result semantics:

| Result | Meaning |
|---|---|
| `PROVED` | Every required layer has explicit, recognized, positive evidence |
| `NOT PROVED` | At least one required layer is absent, unknown, pending, or otherwise unsupported |
| `INCOMPLETE` | Available evidence conflicts or cannot yet be reconciled |
| `CONTRADICTED` | Recognized evidence affirmatively opposes the proposed conclusion |

These are N'KEMBA consumer results. They are not TRACE conformance statuses and do not extend the TRACE data model.

## Illustrative consumer output

The following object is an illustrative N'KEMBA internal result, not a TRACE record and not a proposed TRACE schema addition:

```json
{
  "consumer": "nkemba",
  "trace_verification": {
    "record_digest": "sha256:<digest>",
    "status": "verified",
    "verified_at": "2026-09-04T00:00:00Z"
  },
  "layers": {
    "runtime": "supported",
    "authorized_intent": "unknown",
    "approval_outcome": "supported",
    "operative_document": "missing",
    "external_outcome": "unknown",
    "adoption": "missing"
  },
  "result": "NOT PROVED"
}
```

The example reaches `NOT PROVED` even though the TRACE runtime layer is verified, because the institutional conclusion needs positive evidence from additional layers.

## Verification and preservation obligations

For each TRACE input, the consumer preserves enough material to reproduce or audit the verification result, including the record identifier or digest, applicable verifier output, version, and time.

For each resolved external artifact, the consumer separately checks and records:

- whether the artifact resolved;
- whether its digest matches the binding supplied by the reference or surrounding evidence;
- who issued it and how issuer authority was established;
- the version and relevant validity interval;
- the relationship between the artifact and the evaluated case;
- whether later evidence revokes, supersedes, or contradicts it.

A cryptographically valid artifact can still be stale, out of scope, issued by an authority lacking the relevant competence, or unrelated to the institutional outcome. These checks remain outside TRACE record verification.

## Boundary

This cross-walk does not claim that a TRACE Trust Record proves:

- that a referenced artifact exists, is authentic, or says what the pointer's label suggests;
- that an authorized intention remained valid when the action occurred;
- that an approval came from the competent authority or covered the action taken;
- that a tool call or physical action completed successfully in the external world;
- that a document was legally or institutionally operative;
- that an external recipient accepted, implemented, or adopted the result;
- that the resulting action was safe, correct, lawful, or reversible.

Conversely, institutional evidence consumed by N'KEMBA does not establish the runtime, hardware-attestation, transcript-integrity, or transparency properties that TRACE verification covers.

## Relationship vocabulary

This cross-walk uses only the registered TRACE relationship values:

- `authorized-intent`
- `approval-outcome`
- `behavior-trace`

A deployment needing a different relationship follows the TRACE registry process rather than placing an unregistered value in a record.

## Conformance

Nothing in this document creates a TRACE conformance requirement. Tests of N'KEMBA's fail-closed evaluation logic demonstrate behaviour of that consumer only; they do not constitute TRACE conformance tests or alter the meaning of a successful TRACE verification.

## References

- TRACE v0.2 specification: [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md)
- TRACE external references, section 3.1.2: [`spec/trace-v0.2.md#312-external-references`](../../spec/trace-v0.2.md#312-external-references)
- TRACE cross-walk venue discussion: [trace-spec#274](https://github.com/agentrust-io/trace-spec/issues/274)
- TRACE relationship registry discussion: [trace-spec#226](https://github.com/agentrust-io/trace-spec/issues/226)
