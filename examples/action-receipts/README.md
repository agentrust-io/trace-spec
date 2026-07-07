# Action receipt verification examples

These examples describe the fixture shapes used by embodied-action profiles
that attach per-action receipts below a TRACE Trust Record. They are informative
only: the JSON snippets are not TRACE Trust Records and are not validated by
`schema/trace-claim.json`.

The examples exercise the boundary from
[spec section 3.3.2](../../spec/trace-v0.1.md#332-action-receipts-for-embodied-workflows-informative):

1. session evidence verifies the Trust Record and committed transcript;
2. action issuance evidence verifies that a consequential action request was
   signed, ordered, and bound to the session or call; and
3. outcome evidence reports what an external controller or monitor decided.

## Shared receipt shape

An action receipt profile can represent each externally consequential action as
a transcript entry plus a detached receipt:

```json
{
  "call_id": "call-7f31",
  "session_id": "trace-session-2026-07-05T09:42:11Z",
  "action_ref": "sha256:...",
  "controller_target": "did:web:factory.example:cell-a:robot-arm-2",
  "requested_scope": "cell-a.pick.place",
  "receipt": {
    "issuer": "did:web:factory.example:safety-controller",
    "issuer_key_id": "did:web:factory.example:safety-controller#ed25519-2026q3",
    "linked_call_id": "call-7f31",
    "session_id": "trace-session-2026-07-05T09:42:11Z",
    "evidence_type": "application/vnd.agentrust.action-receipt+json",
    "evidence_hash": "sha256:...",
    "previous_receipt_hash": "sha256:...",
    "decision": "accepted",
    "signature": "base64url..."
  }
}
```

The verifier checks the receipt independently of the core Trust Record:

- recompute `action_ref` or `evidence_hash` from the canonical action preimage;
- resolve `issuer_key_id` through a pinned, manifest-bound, or otherwise trusted
  key set;
- verify the signature with `signature` removed from the canonical receipt;
- verify `linked_call_id` and `session_id` match the expected transcript entry;
- verify `previous_receipt_hash` when the profile uses hash-chain ordering; and
- report the receipt result separately from the controller decision.

## Fixture cases

| Case | Receipt verification result | Controller outcome | Interpretation |
|---|---|---|---|
| Valid accepted action | `receipt_valid_accepted` | `accepted` | The action request was well evidenced and accepted by the controller. |
| Missing required receipt | `receipt_missing_required` | unknown | The profile required action evidence, but the consequential action had no receipt. |
| Signature or key mismatch | `receipt_invalid` | unknown | The receipt cannot be trusted, even if its payload claims success. |
| Valid controller rejection | `receipt_valid_rejected` | `rejected` | The downstream authority rejected the action; this is valid negative evidence, not malformed evidence. |

## Boundary

A valid action receipt proves that a trusted issuer signed a statement about a
specific action request under a specific session or call binding. It does not,
by itself, prove that the physical action completed, that the real world changed
as intended, or that a functional-safety standard was satisfied.

Profiles that need stronger outcome claims should define the external issuer,
certification basis, and verifier trust anchor for those claims explicitly,
without making them part of base TRACE validity.
