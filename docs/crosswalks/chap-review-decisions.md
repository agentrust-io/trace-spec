# CHAP Review Decisions Cross-walk

> **Non-normative.** This document is informative only. Nothing here changes TRACE v0.2 schema fields, wire formats, required claims, or conformance requirements. "TRACE" means the Trust Record defined in [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md). "CHAP" means the [Collaborative Human-Agent Protocol](https://github.com/BrightbeamAI/chap) at version 0.2.13, with its `review/1.0` and `audit-scitt/1.0` profiles.

---

## Purpose

CHAP records the human side of agent work: a draft goes to review, and a named person approves, rejects or overrides it, with each decision appended to a hash-linked audit log. TRACE records the runtime side: what ran, where, and under which policy. An agent that acts on an approved draft produces both, and a relying party reading the TRACE record needs to find the approval and check it.

TRACE already has the slot for this. The `references` block (spec section 3.1.2) registers `rel: "approval-outcome"` for "an attributable human approval attached to a step-up or defer decision". This cross-walk shows a CHAP `decide.approve` filling it, with no change to either specification.

## What a CHAP review decision is

Under `review/1.0`, an agent's draft is held as the artefact under review, and one of `decide.approve`, `decide.reject` or `decide.override` settles it. Each is a JSON-RPC 2.0 envelope. Draft CEP-001 adds an optional `approved_artefact_digest` to all three, the SHA-256 of the RFC 8785 form of the artefact, which the Coordinator checks against the artefact under review. That makes the decision name the content it settled, and it is what these fixtures send.

Under `audit-scitt/1.0`, every accepted envelope is appended to a workspace log. An entry holds `seq`, `arrived`, `envelope` and `prev_hash`, and the chain link is `sha256(JCS(envelope) || prev_hash)`. `audit.verify_chain` replays the log and compares the result with the stored chain head.

## Field mapping

| TRACE `references` field | Value for a CHAP decision | Notes |
|---|---|---|
| `rel` | `approval-outcome` | Registered value. Do not use a CHAP-specific `rel`; the producer belongs in `resolver`. |
| `id` | `audit/<seq>` | The entry's position in the workspace log, which is unique and stable. The envelope's JSON-RPC `id` is not, since it is scoped to one client session. |
| `resolver` | the CHAP workspace, as a URI | The party obliged to keep the entry resolvable. |
| `retention` | the workspace's retention undertaking | Optional. Nothing in either specification enforces it. |
| `digest` | `sha256:` over the RFC 8785 form of the decision envelope | Both sides use RFC 8785. See the next section for where they were checked against each other. |

## Canonicalization agreement

A digest is only portable if both implementations produce the same bytes. CHAP canonicalizes with its own implementation, and TRACE with the `rfc8785` package. On every envelope in these fixtures, and on test objects with non-ASCII strings and non-BMP keys, the two produce identical digests. CHAP refuses non-integer numbers outright, so the numeric cases where RFC 8785 implementations most often disagree cannot occur inside a CHAP envelope. The fixture test replays CHAP's hash chain with `rfc8785` alone, so a divergence on any committed envelope fails CI.

## Verifier obligations for this profile

Given a Trust Record and access to the CHAP workspace named in `resolver`:

1. Verify the Trust Record as usual. This step does not touch the reference, and an unresolvable reference is not a reason to reject the record (section 3.1.2, rule 3).
2. Resolve `id` to a log entry. If there is none, report the approval as unconfirmed.
3. Recompute the RFC 8785 SHA-256 of the entry's envelope and compare it with `digest`. A mismatch means the log no longer holds the approval the record pointed at.
4. Replay the chain and compare the head. A failed replay means the log was altered after export.
5. Check that `method` is `decide.approve`, or `decide.override` if overrides are acceptable to you. A `decide.reject` in the right place with the right digest is still not an approval.
6. Where the relying party holds the executed action, compare it with `approved_artefact_digest`. See the boundary below.

Steps 2 to 5 each have a fixture that fails exactly that step.

## Boundary

Composed this way, a Trust Record and a CHAP log establish that the record points at a specific decision envelope, that the envelope is unchanged, that it sits in a log that replays to its exported head, and whether it is an approval. They do not establish:

- **That the approval was checked before the action ran.** A Trust Record is issued per execution, so it cannot carry a commitment someone needs to check beforehand (section 3.1.2). The component that executes the action has to enforce the approval, for example a policy gate that refuses the call until a matching `decide.approve` exists. The record then points back at the approval it acted under.
- **That the executed action is the approved draft.** `approved_artefact_digest` binds the decision to the draft under review. Binding the draft to what executed is the same gate's job, by comparing the call it is about to make with that digest.
- **Who wrote the log.** These fixtures run without CHAP's `security-signed/1.0`, so envelopes carry no Ed25519 signatures, and the chain proves consistency with an exported head, not authorship. Deployments that need attributable approvals should enable `security-signed/1.0` and `audit-scitt/1.0` receipts. The fixtures do not exercise either.

## Conformance fixtures

Four records and two CHAP logs in [`examples/chap-approval-outcome/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/chap-approval-outcome/), produced by `chap-coordinator` 0.2.13: approval confirmed, approval altered after the record was issued, a rejection in place of an approval, and an unresolvable reference. [`tests/test_chap_approval_outcome_fixtures.py`](https://github.com/agentrust-io/trace-spec/blob/main/tests/test_chap_approval_outcome_fixtures.py) re-verifies all of them in CI with this repository's own dependencies.

## References

- TRACE v0.2 specification, section 3.1.2 (`references`): [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md)
- CHAP repository: <https://github.com/BrightbeamAI/chap>
- CHAP `review/1.0` profile: <https://github.com/BrightbeamAI/chap/blob/main/profiles/review.md>
- CHAP `audit-scitt/1.0` profile: <https://github.com/BrightbeamAI/chap/blob/main/profiles/audit-scitt.md>
- CHAP CEP-001, signature-covered `approved_artefact_digest`: <https://github.com/BrightbeamAI/chap/blob/main/ceps/CEP-001.md>
- RFC 8785, JSON Canonicalization Scheme: <https://www.rfc-editor.org/rfc/rfc8785>
