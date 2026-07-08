# Acta Decision Receipts Cross-walk

> **Non-normative.** This document is informative only. Nothing here changes TRACE v0.1 schema fields, wire formats, required claims, or conformance requirements. References to "TRACE" mean the TRACE v0.1 Trust Record as defined in [`spec/trace-v0.1.md`](../../spec/trace-v0.1.md). References to "Acta" mean the receipt format specified in [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) (revision 02); section references of the form "Acta s2.1" are to that draft.

---

## Purpose

[Spec section 3.3.2](../../spec/trace-v0.1.md#332-action-receipts-for-embodied-workflows-informative) describes action receipts as evidence that sits below a Trust Record: a per-action signed statement, bound to a call or session, that a verifier checks independently of the core record. The [embodied-workflow fixtures](../../examples/action-receipts/README.md) show one profile of that pattern, for a physical controller (a robot arm, a safety monitor) signing an assertion about a physical action.

This cross-walk describes a second profile of the same pattern: an **Acta decision receipt**, evidencing a software decision (an AI agent's tool call, decided by a local policy gate before it runs) rather than a physical one. The verification pattern in 3.3.2 is deliberately domain-agnostic; the intent here is to show it composes with an existing, independently specified receipt format without a wire-format change to either side.

This follows the acceptance bar raised on [trace-spec#97](https://github.com/agentrust-io/trace-spec/issues/97): carry Acta as external evidence by digest/chain head and issuer/key metadata rather than embedding a second receipt schema into the Trust Record; state exactly which Acta fields satisfy the action-receipt verifier obligations; and keep the physical/software boundary explicit.

---

## What an Acta decision receipt is

Per Acta s2.1, a receipt is a two-field envelope: a `payload` and a `signature` object. The access-decision payload type (Acta s3.1) records the outcome of a policy evaluation for a tool invocation. Fixture `01-valid-accepted.json` in full:

```json
{
  "payload": {
    "type": "protectmcp:decision",
    "tool_name": "run_shell",
    "decision": "allow",
    "policy_digest": "sha256:b5af974ae7e1c6e4a656c9637c68ec0755a6cffa7861e196c0aaa2d6a7874cb5",
    "session_id": "ses_8f31ab",
    "issued_at": "2026-07-08T09:00:01.000Z",
    "issuer_id": "sb:issuer:QUGuJV1P6e6c"
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "sb:issuer:QUGuJV1P6e6c",
    "sig": "d709be9e8d907c14bd2005df05cc960b070d388a665964074a19a355a2eabb3d..."
  }
}
```

Signature semantics (Acta s5.6): `signature.sig` is a PureEdDSA (Ed25519) signature directly over the JCS-canonical (RFC 8785) bytes of `payload`, with no intermediate hash. `payload.issuer_id` MUST match `signature.kid` (Acta s2.2); the RECOMMENDED `kid` format is `sb:issuer:<first 12 Base58 characters of the public key>` (Acta s2.1.1), and the key is resolved out of band, never carried in the receipt.

Chain semantics (Acta s5.7): `previousReceiptHash` is the bare lowercase hex SHA-256 of the JCS bytes of the predecessor's **entire signed envelope, signature included**. Including the signature binds the chain to specific signed bytes, so re-signing an identical payload produces a distinct chain link.

`decision` is `allow`, `deny`, or `rate_limit`; a `deny` receipt is signed with the same rigor as an `allow`, which is the property [trace-spec#95](https://github.com/agentrust-io/trace-spec/issues/95)'s "valid negative controller outcome" case and this profile's `02-valid-denied.json` fixture both exercise.

Working fixtures: [`examples/action-receipts/acta/`](../../examples/action-receipts/acta/).

## Field mapping

Field names on the left are exact TRACE terms as used in [spec section 3.3.2](../../spec/trace-v0.1.md#332-action-receipts-for-embodied-workflows-informative) and the [embodied fixture shape](../../examples/action-receipts/README.md#shared-receipt-shape). Field names on the right are exact Acta draft-02 fields.

| TRACE action-receipt obligation | Acta field(s) | Notes |
|---|---|---|
| `receipt.issuer` | `payload.issuer_id` | REQUIRED common field (Acta s2.2); MUST match `signature.kid`, so issuer identity and key identity cannot silently diverge inside one receipt. |
| `receipt.issuer_key_id` | `signature.kid` | Resolved the same way 3.3.2 describes: through a pinned, manifest-bound, or otherwise trusted key set, not carried in the receipt as a public key. |
| `receipt.linked_call_id` / `session_id` | `payload.session_id` | Acta s3.1 binds at session level; `session_id` is OPTIONAL, and when present MUST NOT contain PII or be correlatable across sessions unless the operator explicitly configures session binding. Acta has no per-call identifier field; a TRACE-composing deployment gets call-level binding by carrying the tool input's digest in `payload_digest` (below) or by a deployment extension field, and should say which. |
| `receipt.evidence_type` | `payload.type` | Namespaced receipt type (Acta s2.2), here `protectmcp:decision`. |
| `receipt.evidence_hash` | `payload.payload_digest` | OPTIONAL common field (Acta s2.2): `{hash, size, preview?}` over associated data (tool input/output) too large to embed. Serves exactly the external-evidence-by-digest role 3.3.2 describes. |
| `receipt.previous_receipt_hash` | `payload.previousReceiptHash` | Bare lowercase hex over the predecessor's full envelope including its signature (Acta s5.7). Note the deliberate difference from formats that hash payload only: re-signing an identical payload yields a distinct chain link. |
| `receipt.decision` | `payload.decision` (+ `payload.reason`) | `reason` (OPTIONAL) names the machine-readable cause, e.g. `policy_block`, `tier_insufficient`, beyond the bare outcome. |
| `receipt.signature` | `signature.sig` (with `signature.alg`) | `EdDSA` is mandatory-to-implement; `ES256` optional, `ML-DSA-65` recommended for new deployments (Acta s5.8). |
| *(no TRACE equivalent)* | `payload.policy_digest` | The digest of the policy bundle in force when the decision was made. Signature validity does not imply this digest is still current; see `05-stale-policy-digest.json` and the freshness discussion below. |

## Referencing an Acta chain from a Trust Record

Per the direction set on [trace-spec#97](https://github.com/agentrust-io/trace-spec/issues/97) and the closed decision on [trace-spec#34](https://github.com/agentrust-io/trace-spec/issues/34), a Trust Record references external evidence by digest plus issuer/key metadata; it does not embed the evidence or its schema. For an Acta chain, the natural reference is the **chain head**: the same digest construction Acta s5.7 already uses for `previousReceiptHash` (SHA-256 over the JCS bytes of the latest receipt's entire signed envelope), so a verifier holding the referenced receipts can recompute it with no additional convention. An illustrative (non-normative; field names shown are descriptive, not proposed schema additions) evidence entry for the two-receipt fixture chain in this profile:

```json
{
  "evidence_type": "acta/decision-receipt-chain",
  "chain_head": "99c36f17af17d48c2e6aab51ca21d9a08c53dcffbbb1f5b847c76fda9bf098bd",
  "receipt_count": 2,
  "issuer_key_id": "sb:issuer:QUGuJV1P6e6c"
}
```

The `chain_head` value above is real: it is the recomputable s5.7 envelope hash of [`02-valid-denied.json`](../../examples/action-receipts/acta/02-valid-denied.json), the latest receipt in the fixture chain. A verifier resolves `issuer_key_id` through its trusted key set (never a key carried in the evidence), fetches or is handed the referenced receipts out of band, walks the chain from the head, and runs the per-receipt checks below. The Trust Record itself stays small and schema-stable regardless of how many receipts the chain contains.

## Verifier obligations, restated for this profile

Following the same checks [the embodied fixture README](../../examples/action-receipts/README.md#shared-receipt-shape) lists:

1. Extract `payload` and compute its JCS-canonical bytes (Acta s4.1).
2. Resolve `signature.kid` through a pinned or manifest-bound key set, not a key carried in the receipt, and check `payload.issuer_id` matches `signature.kid`.
3. Verify `signature.sig` as PureEdDSA directly over those bytes (`03-signature-key-mismatch.json` fails exactly here: a real signature by a different, committed key under the same claimed `kid`).
4. If the deployment binds `session_id` (or a call identifier carried via `payload_digest` or extension) to the surrounding TRACE/cMCP context, verify that binding (`06-session-binding-mismatch.json` is validly signed and fails exactly this check).
5. Chain check, distinct from the signature check: recompute SHA-256 over the JCS bytes of the predecessor's entire envelope and compare to `payload.previousReceiptHash` (Acta s5.7). `04-broken-chain.json` is validly signed by the correct key and fails exactly here; a dishonest or buggy issuer can sign a wrong chain pointer, and only recomputation against the actual predecessor detects reordering or omission.

A sixth check this profile adds: compare `payload.policy_digest` against the policy bundle actually in force at verification time. `05-stale-policy-digest.json` is a genuinely, cryptographically valid receipt (step 3 passes) whose policy binding is out of date; a verifier that stops at step 3 accepts an authorization basis that no longer exists. This is the same distinction raised independently in the [Composable Trust Evidence Format discussion](https://github.com/a2aproject/A2A/discussions/1734) as `policy_digest` / `policy_or_verdict_id`: cryptographic integrity and authorization freshness are different properties, and a conformant verifier checks both.

## Boundary

An Acta decision receipt proves that a specific policy decision, over a specific proposed tool call, was signed by the issuing gate at a specific time, and that the payload has not been altered since. Composed with TRACE per this cross-walk, it does **not** prove:

- that the decided tool call's real-world side effect was safe, correct, or reversible (out of scope for both Acta and TRACE);
- that the receipt occupies the chain position it claims, that its policy binding is still current, or that it is being presented under the session it was issued for, if only the signature was checked (fixtures `04`, `05`, `06` respectively; each is validly signed and fails exactly one non-signature check);
- physical completion or functional-safety certification of any kind, which is the boundary [spec section 2.4](../../spec/trace-v0.1.md#24-permanent-scope-boundaries) and the [external-execution-evidence decision on trace-spec#34](https://github.com/agentrust-io/trace-spec/issues/34) already state for the embodied case, and which applies identically here.

## Conformance fixtures

Six real fixtures in [`examples/action-receipts/acta/`](../../examples/action-receipts/acta/), generated by an actual Ed25519 signer (generator committed alongside), covering the negative cases raised in [trace-spec#97](https://github.com/agentrust-io/trace-spec/issues/97) and [trace-spec#95](https://github.com/agentrust-io/trace-spec/issues/95): valid accepted, valid denied (negative controller-equivalent outcome), signature/key mismatch (mismatched key committed), broken chain (validly signed, wrong predecessor hash), stale policy digest, and mismatched session binding. Expected outcomes are machine-readable in `expected.json`, and [`tests/test_acta_fixtures.py`](../../tests/test_acta_fixtures.py) re-verifies every fixture in CI against the draft-02 envelope and the declared positive/negative results, using this repository's existing `rfc8785` and `cryptography` dependencies, so fixture or envelope drift fails the build.

## References

- TRACE v0.1 specification, section 3.3.2: [`spec/trace-v0.1.md`](../../spec/trace-v0.1.md#332-action-receipts-for-embodied-workflows-informative)
- TRACE v0.1 specification, section 2.4 (permanent scope boundaries): [`spec/trace-v0.1.md`](../../spec/trace-v0.1.md#24-permanent-scope-boundaries)
- trace-spec#34 (external execution evidence, closed): <https://github.com/agentrust-io/trace-spec/issues/34>
- trace-spec#66 (verification depth + action_receipts): <https://github.com/agentrust-io/trace-spec/issues/66>
- trace-spec#95 (action receipt conformance cases): <https://github.com/agentrust-io/trace-spec/issues/95>
- trace-spec#97 (this cross-walk's origin issue): <https://github.com/agentrust-io/trace-spec/issues/97>
- draft-farley-acta-signed-receipts (revision 02): <https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/>
- Shared conformance suite for Acta implementations: <https://github.com/ScopeBlind/agent-governance-testvectors>
