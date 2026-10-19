# Acta Decision Receipts Cross-walk

Acta is an IETF draft format for signed receipts that record whether an AI agent's tool call was allowed before it ran. This page shows how such a receipt can travel next to a TRACE record as supporting evidence, and which Acta fields a TRACE verifier checks. It is for teams that already produce Acta receipts; neither format changes.

> **Non-normative.** This document is informative only. Nothing here changes TRACE v0.2 schema fields, wire formats, required claims, or conformance requirements. References to "TRACE" mean the TRACE v0.2 Trust Record as defined in [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md). References to "Acta" mean the receipt format specified in [draft-farley-acta-signed-receipts-03](https://datatracker.ietf.org/doc/html/draft-farley-acta-signed-receipts-03) (revision 03); section references of the form "Acta s2.1" are to that revision. Revision 03 moved the signing and chain rules from s5.6 and s5.7 to s6.6 and s6.7. Fixtures `01` to `06` predate it, and the two of them that link to a predecessor (`02` and `04`) carry revision 02's bare-hex link, which revision 03 still accepts on read (see the chain semantics below); fixtures `07` to `11` are revision 03 receipts.

---

## Purpose

[Spec section 3.3.3](../../spec/trace-v0.2.md#333-action-receipts-for-embodied-workflows-informative) describes action receipts as evidence that sits below a Trust Record: a per-action signed statement, bound to a call or session, that a verifier checks independently of the core record. The [embodied-workflow fixtures](https://github.com/agentrust-io/trace-spec/blob/main/examples/action-receipts/README.md) show one profile of that pattern, for a physical controller (a robot arm, a safety monitor) signing an assertion about a physical action.

This cross-walk describes a second profile of the same pattern: an **Acta decision receipt**, evidencing a software decision (an AI agent's tool call, decided by a local policy gate before it runs) rather than a physical one. The verification pattern in 3.3.3 is deliberately domain-agnostic; the intent here is to show it composes with an existing, independently specified receipt format without a wire-format change to either side.

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
    "policy_digest": "sha256:bda8d8f60c90afe5c05fc7f3b1b53d4715a0f7ba72ec8d4b82ad7aba70d9609b",
    "session_id": "ses_8f31ab",
    "issued_at": "2026-07-08T09:00:01.000Z",
    "issuer_id": "sb:issuer:QUGuJV1P6e6c"
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "sb:issuer:QUGuJV1P6e6c",
    "sig": "cf4665db8613b3b8b398fae6c1bacf88e4963d300af63cf709a2be1e8a6bda69..."
  }
}
```

Signature semantics (Acta s6.6): `signature.sig` is a PureEdDSA (Ed25519) signature directly over the JCS-canonical (RFC 8785) bytes of `payload`, with no intermediate hash. The payload MUST NOT itself contain a `signature` member, not even as `null` or an empty string, and the `alg` and `kid` members are outside the signed bytes, so a verifier does not treat them as attested content. `payload.issuer_id` MUST match `signature.kid` (Acta s2.2); the RECOMMENDED `kid` format is `sb:issuer:<first 12 Base58 characters of the public key>` (Acta s2.1.1), and the key is resolved out of band, never carried in the receipt.

Chain semantics (Acta s6.7): `previousReceiptHash` is `"sha256:"` followed by the lowercase hex SHA-256 of the JCS bytes of the predecessor's **entire signed receipt, signature included**. Including the signature binds the chain to specific signed bytes, so re-signing an identical payload produces a distinct chain link. A verifier refuses a prefix naming an algorithm it does not implement. The bare hex digest of revision 02, which fixtures `02` and `04` carry, MAY still be accepted but MUST NOT be emitted. The first receipt in a chain omits the member entirely (Acta s2.2): `null` or an empty string would change the JCS bytes and therefore the signature.

`decision` is one of `allow`, `deny`, `rate_limit`, or `require_approval` (Acta s3.1.1). Revision 03 added `require_approval`: it records that the action was held pending human approval at decision time, and if the held action later executes, its terminal outcome is recorded in a subsequent receipt, so a `require_approval` receipt is not evidence that anything ran (Acta s9.8). The fixtures use only `allow` and `deny`. A `deny` receipt is signed with the same rigor as an `allow`, which is the property [trace-spec#95](https://github.com/agentrust-io/trace-spec/issues/95)'s "valid negative controller outcome" case and this profile's `02-valid-denied.json` fixture both exercise.

Working fixtures: [`examples/action-receipts/acta/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/action-receipts/acta/).

## Field mapping

Field names on the left are exact TRACE terms as used in [spec section 3.3.3](../../spec/trace-v0.2.md#333-action-receipts-for-embodied-workflows-informative) and the [embodied fixture shape](https://github.com/agentrust-io/trace-spec/blob/main/examples/action-receipts/README.md#shared-receipt-shape). Field names on the right are exact Acta revision 03 fields; the revision 02 envelopes of fixtures `01` to `06` carry the same names.

| TRACE action-receipt obligation | Acta field(s) | Notes |
|---|---|---|
| `receipt.issuer` | `payload.issuer_id` | REQUIRED common field (Acta s2.2); MUST match `signature.kid`, so issuer identity and key identity cannot silently diverge inside one receipt. |
| `receipt.issuer_key_id` | `signature.kid` | Resolved the same way 3.3.3 describes: through a pinned, manifest-bound, or otherwise trusted key set, not carried in the receipt as a public key. |
| `receipt.linked_call_id` / `session_id` | `payload.session_id` | Acta s3.1 binds at session level; `session_id` is OPTIONAL, and when present MUST NOT contain PII or be correlatable across sessions unless the operator explicitly configures session binding. Acta has no per-call identifier field; a TRACE-composing deployment gets call-level binding by carrying the tool input's digest in `payload_digest` (below) or by a deployment extension field, and should say which. |
| `receipt.evidence_type` | `payload.type` | Namespaced receipt type (Acta s2.2), here `protectmcp:decision`. |
| `receipt.evidence_hash` | `payload.payload_digest` | OPTIONAL common field (Acta s2.2): `{hash, size, preview?}` over associated data (tool input/output) too large to embed. Serves exactly the external-evidence-by-digest role 3.3.3 describes. |
| `receipt.previous_receipt_hash` | `payload.previousReceiptHash` | `"sha256:"` plus lowercase hex over the predecessor's full signed receipt including its signature, omitted on the first receipt (Acta s6.7). Note the deliberate difference from formats that hash payload only: re-signing an identical payload yields a distinct chain link. |
| `receipt.decision` | `payload.decision` (+ `payload.reason`) | `reason` (OPTIONAL) names the machine-readable cause, e.g. `policy_block`, `tier_insufficient`, beyond the bare outcome. |
| `receipt.signature` | `signature.sig` (with `signature.alg`) | `EdDSA` is mandatory-to-implement; `ES256` optional, `ML-DSA-65` recommended for new deployments (Acta s6.9). |
| *(no TRACE equivalent)* | `payload.policy_digest` | The digest of the policy bundle in force when the decision was made. Signature validity does not imply this digest is still current; see `05-stale-policy-digest.json` and the freshness discussion below. |

## Referencing an Acta chain from a Trust Record

Per the direction set on [trace-spec#97](https://github.com/agentrust-io/trace-spec/issues/97) and the closed decision on [trace-spec#34](https://github.com/agentrust-io/trace-spec/issues/34), a Trust Record references external evidence by digest plus issuer/key metadata; it does not embed the evidence or its schema. For an Acta chain, the natural reference is the **chain head**: the same digest construction Acta s6.7 already uses for `previousReceiptHash` (SHA-256 over the JCS bytes of the latest receipt's entire signed envelope), so a verifier holding the referenced receipts can recompute it with no additional convention. An illustrative (non-normative; field names shown are descriptive, not proposed schema additions) evidence entry for the two-receipt chain of fixtures `01` and `02`:

```json
{
  "evidence_type": "acta/decision-receipt-chain",
  "chain_head": "ddf7efb089f7504bbe880a623976b34be04b0bd4a991cdec12288841030229e4",
  "receipt_count": 2,
  "issuer_key_id": "sb:issuer:QUGuJV1P6e6c"
}
```

The `chain_head` value above is real: it is the recomputable s6.7 hash of [`02-valid-denied.json`](../../examples/action-receipts/acta/02-valid-denied.json), the latest receipt in that chain. A verifier resolves `issuer_key_id` through its trusted key set (never a key carried in the evidence), fetches or is handed the referenced receipts out of band, walks the chain from the head, and runs the per-receipt checks below. The Trust Record itself stays small and schema-stable regardless of how many receipts the chain contains.

## Verifier obligations, restated for this profile

Following the same checks [the embodied fixture README](https://github.com/agentrust-io/trace-spec/blob/main/examples/action-receipts/README.md#shared-receipt-shape) lists:

1. Extract `payload` and compute its JCS-canonical bytes (Acta s6.6), refusing a payload that itself carries a `signature` member (`10-signature-member-in-payload.json` is validly signed over such a payload and fails exactly here).
2. Resolve `signature.kid` through a pinned or manifest-bound key set, not a key carried in the receipt, and check `payload.issuer_id` matches `signature.kid`. If the key set gives that key a validity window (`valid_from`, `valid_until`), check that `payload.issued_at` falls inside it (Acta s9.2, a SHOULD that names no time to compare; the fixtures compare `issued_at`, and `11-outside-key-window.json`, validly signed by the right key, fails exactly here).
3. Verify `signature.sig` as PureEdDSA directly over those bytes (`03-signature-key-mismatch.json` fails exactly here: a real signature by a different, committed key under the same claimed `kid`).
4. If the deployment binds `session_id` (or a call identifier carried via `payload_digest` or extension) to the surrounding TRACE/cMCP context, verify that binding (`06-session-binding-mismatch.json` is validly signed and fails exactly this check).
5. Chain check, distinct from the signature check: recompute SHA-256 over the JCS bytes of the predecessor's entire signed receipt and compare it with `payload.previousReceiptHash` (Acta s6.7), which carries it as `sha256:<hex>` or, in receipts made under revision 02, as the bare hex; refuse a prefix naming any other algorithm. `04-broken-chain.json` is validly signed by the correct key and fails exactly here; a dishonest or buggy issuer can sign a wrong chain pointer, and only recomputation against the actual predecessor detects reordering or omission. `09-payload-only-chain-link.json` fails here too: its well-formed `sha256:` link is the hash of the predecessor's payload alone, which only recomputation over the whole signed receipt rules out.

A sixth check this profile adds: compare `payload.policy_digest` against the policy bundle actually in force at verification time. `05-stale-policy-digest.json` is a genuinely, cryptographically valid receipt (step 3 passes) whose policy binding is out of date; a verifier that stops at step 3 accepts an authorization basis that no longer exists. This is the same distinction raised independently in the [Composable Trust Evidence Format discussion](https://github.com/a2aproject/A2A/discussions/1734) as `policy_digest` / `policy_or_verdict_id`: cryptographic integrity and authorization freshness are different properties, and a conformant verifier checks both.

## Boundary

An Acta decision receipt proves that a specific policy decision, over a specific proposed tool call, was signed by the issuing gate at a specific time, and that the payload has not been altered since. Composed with TRACE per this cross-walk, it does **not** prove:

- that the decided tool call's real-world side effect was safe, correct, or reversible (out of scope for both Acta and TRACE);
- that the receipt occupies the chain position it claims, that its policy binding is still current, or that it is being presented under the session it was issued for, if only the signature was checked (fixtures `04`, `05`, `06` respectively; each is validly signed and fails exactly one non-signature check);
- physical completion or functional-safety certification of any kind, which is the boundary [spec section 2.4](../../spec/trace-v0.2.md#24-permanent-scope-boundaries) and the [external-execution-evidence decision on trace-spec#34](https://github.com/agentrust-io/trace-spec/issues/34) already state for the embodied case, and which applies identically here.

## Conformance fixtures

Eleven real fixtures in [`examples/action-receipts/acta/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/action-receipts/acta/), generated by an actual Ed25519 signer (generator committed alongside). Six revision 02 envelopes cover the negative cases raised in [trace-spec#97](https://github.com/agentrust-io/trace-spec/issues/97) and [trace-spec#95](https://github.com/agentrust-io/trace-spec/issues/95): valid accepted, valid denied (negative controller-equivalent outcome), signature/key mismatch (mismatched key committed), broken chain (validly signed, wrong predecessor hash), stale policy digest, and mismatched session binding. Five revision 03 receipts add a receipt inside the signer key's validity window, a `sha256:` link, and one negative for each of three rules as revision 03 states them: a link over the predecessor's payload alone (s6.7), a `signature` member in the payload (s6.6), and a receipt dated before the key's `valid_from` (s9.2). Each of these three is a valid fixture with one payload member changed. All eleven fixtures are checked under the key and validity window that `acta-keys.json` publishes, and only `11` falls outside the window. In every fixture `policy_digest` is an illustrative value, not the s6.8 manifest digest. Expected outcomes are machine-readable in `expected.json`. Two test modules check them in CI, using this repository's existing `rfc8785` and `cryptography` dependencies, so fixture or envelope drift fails the build:

- [`tests/test_acta_fixtures.py`](https://github.com/agentrust-io/trace-spec/blob/main/tests/test_acta_fixtures.py) checks each fixture's envelope structure, its signature, and (where `expected.json` names a predecessor) its chain link against the declared results. It uses the `signature_verifies` and `chain_link_matches` helpers it shares with [`tools/acta_receipt_verifier.py`](https://github.com/agentrust-io/trace-spec/blob/main/tools/acta_receipt_verifier.py), not the verifier's full envelope path, and passes them no key validity window. It makes the other comparisons itself: the s6.6 rule, `issued_at` against the window in `acta-keys.json`, the `sha256:` form of the revision 03 links, and the two caller-side comparisons, `policy_digest` against the current digest `expected.json` declares (fixture `05`) and `session_id` against the expected session (fixture `06`). It also checks that each revision 03 negative changes one payload member of a valid fixture and fails only the column that member breaks.
- [`tests/test_acta_receipt_verifier.py`](https://github.com/agentrust-io/trace-spec/blob/main/tests/test_acta_receipt_verifier.py) runs the full envelope path (`verify_envelope`) over every fixture, under the key and validity window that `acta-keys.json` publishes for the fixture's `kid`, and checks the verdict and code that the fixture's `expected.json` columns imply, the two caller-side comparisons aside; it also runs the command line against that key set. Its synthetic receipts, signed with a fixed test key, cover the cases the fixtures do not: the key validity window boundaries (s9.2), a `signature` member that is the empty string or a hex string (s6.6), and other-algorithm, malformed and missing chain links (s6.7).

Policy freshness and session binding are comparisons the caller makes against its own context (check 4 and the sixth check above), not rules the receipt verifier applies.

## References

- TRACE v0.2 specification, section 3.3.3: [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md#333-action-receipts-for-embodied-workflows-informative)
- TRACE v0.2 specification, section 2.4 (permanent scope boundaries): [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md#24-permanent-scope-boundaries)
- trace-spec#34 (external execution evidence, closed): <https://github.com/agentrust-io/trace-spec/issues/34>
- trace-spec#66 (verification depth + action_receipts): <https://github.com/agentrust-io/trace-spec/issues/66>
- trace-spec#95 (action receipt conformance cases): <https://github.com/agentrust-io/trace-spec/issues/95>
- trace-spec#97 (this cross-walk's origin issue): <https://github.com/agentrust-io/trace-spec/issues/97>
- draft-farley-acta-signed-receipts-03: <https://datatracker.ietf.org/doc/html/draft-farley-acta-signed-receipts-03>
- Shared conformance suite for Acta implementations: <https://github.com/ScopeBlind/agent-governance-testvectors>
