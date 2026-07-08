# Acta Decision Receipts Cross-walk

> **Non-normative.** This document is informative only. Nothing here changes TRACE v0.1 schema fields, wire formats, required claims, or conformance requirements. References to "TRACE" mean the TRACE v0.1 Trust Record as defined in [`spec/trace-v0.1.md`](../../spec/trace-v0.1.md). References to "Acta" mean the receipt format specified in [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) (revision 02).

---

## Purpose

[Spec section 3.3.2](../../spec/trace-v0.1.md#332-action-receipts-for-embodied-workflows-informative) describes action receipts as evidence that sits below a Trust Record: a per-action signed statement, bound to a call or session, that a verifier checks independently of the core record. The [embodied-workflow fixtures](../../examples/action-receipts/README.md) show one profile of that pattern, for a physical controller (a robot arm, a safety monitor) signing an assertion about a physical action.

This cross-walk describes a second profile of the same pattern: an **Acta decision receipt**, evidencing a software decision (an AI agent's tool call, decided by a local policy gate before it runs) rather than a physical one. The verification pattern in 3.3.2 is deliberately domain-agnostic; the intent here is to show it composes with an existing, independently specified receipt format without a wire-format change to either side.

This follows the acceptance bar raised on [trace-spec#97](https://github.com/agentrust-io/trace-spec/issues/97): carry Acta as external evidence by digest/chain head and issuer/key metadata rather than embedding a second receipt schema into the Trust Record; state exactly which Acta fields satisfy the action-receipt verifier obligations; and keep the physical/software boundary explicit.

---

## What an Acta decision receipt is

An Acta decision receipt is an envelope signed at the moment a policy gate decides a proposed tool call:

```json
{
  "v": 2,
  "type": "decision_receipt",
  "algorithm": "ed25519",
  "kid": "acta-demo-2026q3",
  "issuer": "did:web:legate.scopeblind.com",
  "issued_at": "2026-07-08T09:00:01.000Z",
  "payload": {
    "tool": "run_shell",
    "decision": "allow",
    "reason_code": "policy_permit",
    "policy_digest": "sha256:...",
    "scope": "call-7f31",
    "session_id": "trace-session-2026-07-08T09:00:00Z",
    "request_id": "call-7f31",
    "spec": "draft-farley-acta-signed-receipts-02",
    "parent_receipt_hash": null
  },
  "signature": "..."
}
```

`signature` is an Ed25519 signature over the JCS-canonical (RFC 8785) serialization of `payload`, with `signature` itself excluded from what is signed. `decision` is `allow` or `deny`; a `deny` receipt is signed with the same rigor as an `allow`, which is the property [trace-spec#95](https://github.com/agentrust-io/trace-spec/issues/95)'s "valid negative controller outcome" case and this profile's `02-valid-denied.json` fixture both exercise. `parent_receipt_hash` chains each receipt to its predecessor, giving the profile the same ordered-evidence property a hash-chained embodied profile would have.

Working fixtures: [`examples/action-receipts/acta/`](../../examples/action-receipts/acta/).

## Field mapping

Field names on the left are exact TRACE terms as used in [spec section 3.3.2](../../spec/trace-v0.1.md#332-action-receipts-for-embodied-workflows-informative) and the [embodied fixture shape](../../examples/action-receipts/README.md#shared-receipt-shape). Field names on the right are exact Acta envelope fields as shown above.

| TRACE action-receipt obligation | Acta field(s) | Notes |
|---|---|---|
| `receipt.issuer` | `issuer` | Both are an identity string for the signing authority; Acta does not require a DID specifically, though one composes cleanly (see example above). |
| `receipt.issuer_key_id` | `kid` | Resolved the same way 3.3.2 describes: through a pinned, manifest-bound, or otherwise trusted key set, not carried in the receipt as a public key. |
| `receipt.linked_call_id` / `session_id` | `payload.request_id` (or `payload.scope`) / `payload.session_id` | Acta does not mandate these specific key names; a TRACE-composing deployment binds them to the call/session identifiers a cMCP or A2A instrumentation layer already assigns. |
| `receipt.evidence_type` | `type` + `payload.spec` | `type` names the artifact class (`decision_receipt`); `payload.spec` pins the exact draft revision the envelope conforms to, which a verifier can use to select decoding/verification rules across revisions. |
| `receipt.evidence_hash` | *(the canonical preimage itself)* | Acta does not detach the hash from the signed content; a verifier recomputes the JCS-canonical bytes of `payload` directly and verifies `signature` against that digest, which serves the same purpose 3.3.2 describes for `evidence_hash`. |
| `receipt.previous_receipt_hash` | `payload.parent_receipt_hash` | Included inside the signed payload rather than alongside it, so a tampered chain pointer and a tampered signature collapse to the same failure (see `04-broken-chain.json`). |
| `receipt.decision` | `payload.decision` (+ `payload.reason_code`) | Acta's `reason_code` additionally names which specific rule produced the decision (e.g. `policy_forbid:destructive_action`), beyond the bare allow/deny outcome. |
| `receipt.signature` | `signature` | Ed25519, as 3.3.2 specifies. |
| *(no TRACE equivalent)* | `payload.policy_digest` | The digest of the policy bundle in force when the decision was made. Signature validity does not imply this digest is still current; see `05-stale-policy-digest.json` and the freshness discussion below. |

## Verifier obligations, restated for this profile

Following the same five checks [the embodied fixture README](../../examples/action-receipts/README.md#shared-receipt-shape) lists:

1. Recompute the JCS-canonical preimage from `payload` (with `signature` absent).
2. Resolve `kid` through a pinned or manifest-bound key set, not a key carried inside the receipt.
3. Verify `signature` against that preimage and the resolved key.
4. If the deployment binds `request_id`/`session_id` to an external call or session identifier, verify that binding.
5. If the profile uses hash-chained ordering, verify `payload.parent_receipt_hash` against the prior receipt in the chain, exactly as a signature check (see the note on `04` above: a broken chain pointer is a broken signature in this envelope shape, not a separate check).

A sixth check this profile adds, distinct from all five above: compare `payload.policy_digest` against the policy bundle actually in force at verification time. A receipt can pass every signature and chain check and still be **stale** if the policy changed after it was issued. `05-stale-policy-digest.json` is a genuinely, cryptographically valid receipt (step 3 passes) whose policy binding is nonetheless out of date; a verifier that stops at step 3 accepts an authorization basis that no longer exists. This is the same distinction raised independently in the [Composable Trust Evidence Format discussion](https://github.com/a2aproject/A2A/discussions/1734) as `policy_digest` / `policy_or_verdict_id`: cryptographic integrity and authorization freshness are different properties, and a conformant verifier checks both.

## Boundary

An Acta decision receipt proves that a specific policy decision, over a specific proposed tool call, was signed by the issuing gate at a specific time, and that the payload has not been altered since. Composed with TRACE per this cross-walk, it does **not** prove:

- that the decided tool call's real-world side effect was safe, correct, or reversible (out of scope for both Acta and TRACE);
- that the policy binding is still current at verification time, if only the signature was checked (see `05` above; this is a distinct, deliberately non-cryptographic check);
- physical completion or functional-safety certification of any kind, which is the boundary [spec section 2.4](../../spec/trace-v0.1.md#24-permanent-scope-boundaries) and the [external-execution-evidence decision on trace-spec#34](https://github.com/agentrust-io/trace-spec/issues/34) already state for the embodied case, and which applies identically here.

## Conformance fixtures

Five real fixtures, generated (not hand-typed) by an actual Ed25519 signer, covering the negative cases raised in [trace-spec#97](https://github.com/agentrust-io/trace-spec/issues/97) and [trace-spec#95](https://github.com/agentrust-io/trace-spec/issues/95): valid accepted, valid denied (negative controller-equivalent outcome), signature/key mismatch, broken chain, and stale policy digest. Details, the generator script, and independent-verification instructions: [`examples/action-receipts/acta/README.md`](../../examples/action-receipts/acta/README.md).

## References

- TRACE v0.1 specification, section 3.3.2: [`spec/trace-v0.1.md`](../../spec/trace-v0.1.md#332-action-receipts-for-embodied-workflows-informative)
- TRACE v0.1 specification, section 2.4 (permanent scope boundaries): [`spec/trace-v0.1.md`](../../spec/trace-v0.1.md#24-permanent-scope-boundaries)
- trace-spec#34 (external execution evidence, closed): <https://github.com/agentrust-io/trace-spec/issues/34>
- trace-spec#66 (verification depth + action_receipts): <https://github.com/agentrust-io/trace-spec/issues/66>
- trace-spec#95 (action receipt conformance cases): <https://github.com/agentrust-io/trace-spec/issues/95>
- trace-spec#97 (this cross-walk's origin issue): <https://github.com/agentrust-io/trace-spec/issues/97>
- draft-farley-acta-signed-receipts (revision 02): <https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/>
- Shared conformance suite for Acta implementations: <https://github.com/ScopeBlind/agent-governance-testvectors>
