# TRACE v0.2 → N’KEMBA Institutional Reconstruction Cross-walk

> **Non-normative.** This document is informative only. Nothing here changes TRACE v0.2 schema fields, wire formats, required claims, verification rules, or conformance requirements. It does not claim TRACE certification, endorsement, or conformance for N’KEMBA. TRACE evidence remains TRACE evidence; N’KEMBA is a downstream consumer that independently evaluates additional institutional evidence.

## Purpose

TRACE v0.2 provides portable governance evidence about agent execution: what ran, under what policy, on what data class, and which instrumented tool calls crossed the execution boundary. TRACE can also carry assurance-neutral `references` to facts held outside the Trust Record.

N’KEMBA starts at that downstream boundary. It preserves the upstream evidence and asks a different question: **what bounded institutional conclusion is supportable when runtime/session evidence, action evidence, human authority, operative document/version, external outcome, and institutional adoption are considered together?**

The core interoperability rule is:

> **tamper-evidence ≠ completeness ≠ institutional truth**

A cryptographically valid upstream record may be necessary evidence for an institutional reconstruction without being sufficient evidence for the institutional conclusion.

## Layer mapping

| Evidence / question | TRACE v0.2 role | N’KEMBA downstream role | Promotion rule |
|---|---|---|---|
| Runtime / session | Establishes execution environment and bound runtime claims, subject to TRACE verification semantics | Preserved as upstream evidence | Valid runtime evidence does not establish authority, external completion, or institutional adoption |
| Tool/action evidence | `tool_transcript` and profile/action-receipt evidence can establish calls, issuance, bindings, and issuer assertions | Correlated with the institutional case | A valid action receipt does not by itself prove the external physical/business result |
| Policy | Binds the policy set/enforcement mode in force at execution | Used as execution-context evidence | Policy binding does not prove that a human or institutional actor had authority for a later institutional act |
| `references` | Assurance-neutral pointers to external facts | Resolver targets may be retrieved and independently evaluated | Resolution never promotes the referenced target into TRACE-attested evidence |
| Human authority | May be referenced where an appropriate relation/profile exists; not inferred from runtime validity | Determines whether the relevant actor or approval was valid for the bounded institutional act | Missing or unrecognised authority cannot produce `PROVED` |
| Operative document/version | May be externally referenced; TRACE pointer identity does not establish institutional operativeness | Determines which document/version was operative at the relevant time | Digest or pointer identity alone does not prove institutional status |
| External outcome | May be represented by independently issued outcome evidence or external references | Determines whether the claimed real-world or business outcome is established | Issuance or acceptance remains separate from confirmed external outcome |
| Institutional adoption | Outside core runtime attestation | Determines whether a decision/result was recorded, adopted, rejected, pending, corrected, or superseded institutionally | No adoption evidence means the institutional conclusion remains unproved |

## TRACE `references` boundary

TRACE v0.2 §3.1.2 defines a `references` entry as a pointer rather than evidence. The Trust Record signature attests that the record points to the target; it does not attest the truth of the target. A TRACE verifier must not treat a resolved reference as attested evidence.

N’KEMBA follows that rule directly:

1. preserve the TRACE record and its verification result;
2. preserve the reference relation, identifier, resolver, retention metadata, and digest where present;
3. resolve the target independently when available;
4. evaluate the target under the downstream institutional evidence rules appropriate to that fact;
5. never raise the target’s assurance merely because a valid TRACE record referenced it.

This is particularly important for authority, approval, documentary state, external outcomes, and later institutional decisions.

## Fail-closed institutional verdict boundary

The current public N’KEMBA functional demonstrator models six required dimensions:

- runtime/session evidence;
- action receipt/signature evidence;
- human authority;
- operative document/version;
- external outcome;
- institutional adoption.

For the bounded synthetic claim in that demonstrator, `PROVED` is reachable only when every required dimension has an explicit recognised positive state. An absent or unrecognised required state fails closed to `NOT PROVED`; recognised conflicting or disputed evidence is kept distinct from contradiction and absence.

This evaluator behaviour is a N’KEMBA downstream rule. It is **not** a TRACE verification rule and does not alter the meaning or validity of a TRACE Trust Record.

## What this mapping satisfies

This mapping is compatible with the following TRACE v0.2 boundaries:

- upstream runtime evidence is preserved rather than relabelled as institutional proof;
- action evidence is not promoted into proof of physical or business completion;
- `references` remain assurance-neutral pointers;
- external targets are independently evaluated downstream;
- inability to establish a downstream institutional fact does not invalidate an otherwise valid TRACE record;
- downstream uncertainty is represented explicitly rather than silently falling through to a positive institutional conclusion.

## What this mapping does not satisfy or claim

This cross-walk does not claim that N’KEMBA:

- produces TRACE Trust Records;
- verifies every TRACE hardware or platform profile;
- changes TRACE conformance requirements;
- turns a resolved `references` target into attested evidence;
- proves physical completion from an action receipt alone;
- proves legal validity, regulatory compliance, or institutional authority merely from runtime evidence;
- certifies the correctness of model output;
- makes TRACE responsible for institutional reconstruction;
- has received TRACE certification, endorsement, or independent audit.

## Example hand-off

A simplified downstream sequence is:

```text
TRACE Trust Record
  └─ verified runtime / policy / tool evidence
       └─ action receipt or external reference
            └─ N’KEMBA preserves upstream verification state
                 ├─ evaluates authority evidence
                 ├─ establishes operative document/version
                 ├─ evaluates external outcome evidence
                 ├─ evaluates institutional adoption/supersession
                 └─ derives only the bounded institutional conclusion supported by all required evidence
```

A valid TRACE record can therefore remain valid while the N’KEMBA institutional verdict is `NOT PROVED`, `INCOMPLETE`, or `CONTRADICTED`. The two conclusions answer different questions and must not be collapsed.

## Public reproducibility surface

The current synthetic fail-closed demonstrator is published at:

- https://nkemba.pt/nkemba-evidence-demo-v08.html
- evaluator source: https://nkemba.pt/demo-evaluator-v08.js

The demonstrator is intentionally narrow. It is functional-logic evidence for the downstream verdict boundary, not a TRACE conformance fixture, certification surface, or independent audit.

## References

- TRACE v0.2 specification: https://github.com/agentrust-io/trace-spec/blob/main/spec/trace-v0.2.md
- TRACE downstream boundary discussion: https://github.com/agentrust-io/trace-spec/issues/223
- N’KEMBA external evaluation thread: https://github.com/agentrust-io/trace-tests/issues/96
- Cross-walk venue discussion: https://github.com/agentrust-io/trace-spec/issues/274
- Acta cross-walk precedent: https://github.com/agentrust-io/trace-spec/blob/main/docs/crosswalks/acta-decision-receipts.md
