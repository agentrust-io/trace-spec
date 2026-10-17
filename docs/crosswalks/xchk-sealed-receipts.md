# xChk Sealed Receipts Cross-walk

xChk is a registry that licenses AI agents under a verified person and seals a record of each gated act, with the person's own passkey assertion on the acts they answered. This page shows how a TRACE record points at one of those receipts, so a reader can find the approval, check who gave it and against what, and do so offline. It is for teams whose runtime emits Trust Records and whose approvals go through an xChk registry.

> **Non-normative.** This document is informative only. Nothing here changes TRACE v0.2 schema fields, wire formats, required claims, or conformance requirements. "TRACE" means the Trust Record defined in [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md).

---

## Purpose

TRACE records the runtime side: what ran, where, under which policy, which tools were called. An xChk registry records the authority side: for each act an agent proposed, what the gate decided, and when a person was asked, who answered, how they proved it was them, and what exactly they answered. A runtime that produces its own Trust Record and an xChk registry are different parties in different places; in the fixtures here the registry is also the producer, so one key signs the Trust Record, the seal and the binding, and what the fixtures show is one party pointing at its own receipt and the receipt verifying on its own terms. The `references` block (spec section 3.1.2) registers `rel: "approval-outcome"` for "an attributable human approval attached to a step-up or defer decision". This cross-walk shows an xChk sealed receipt as that referenced object, and what a relying party may establish from one.

The [CHAP cross-walk](chap-review-decisions.md) does the same for a review log and names, in its boundary, what a log without signatures cannot show: who wrote it. The receipt here is the case where that is answered: the approval carries the approver's WebAuthn assertion over the record it answered, and the registry's signature binding that credential to a named, identity-proofed person.

## What an xChk sealed receipt is

A **record** is the gate's account of one act: plate, sequence, time, tool, a summary of the command, a digest of its parameters, the decision (`allow`, `attest`, `forbid`, and for an answered ask `approved`, `denied` or `expired`), and for a ceremony the approver's email and method. `approved` and `denied` are the answers a person gave; `expired` is an ask nobody answered within its life, and it is on the record too. Its hash is `sha256` over its canonical form (keys sorted by UTF-16 code unit, no whitespace, JSON scalars with integers only among numbers), which for these records is byte for byte RFC 8785.

The **record** is the referenced object; its hash is the reference's `id` and `digest`. A **bundle** is the carrier the registry serves for it at `/api/receipt/<hash>/bundle`: the record; the Merkle path from its hash to the **seal** the registry wrote over that window of the plate's chain; the seal's fields and hash; the registry's signatures over the seal hash (Ed25519, and ML-DSA-65 where the registry runs hybrid); the published public keys those check against; when the seal has been anchored, the raw Ravencoin transaction carrying the seal hash and the Merkle block that places it; and, when a person answered, the **approver block**:

- `assertion`: the passkey's `clientDataJSON`, `authenticatorData` and ECDSA P-256 signature from the ceremony that answered;
- `publicKey`: the credential's public key as an uncompressed P-256 point;
- `credentialId`, `email`, `authLevel` (the identity proofing behind the credential), `authMethod`, `verifiedAt`;
- `binding`: the registry's signature over `{recordHash, attestationId, credentialId, publicKey, approverEmail, authLevel, authMethod, verifiedAt}`, tying that credential to that person for that record.

Beside it, `basis` (the rule that made the gate ask) and `decision` (the ask as the person saw it and the answer as they gave it, including an amendment when they approved with changes). The bundle carries its own `howToVerify` steps, and the registry publishes a standard-library-only verifier, `verify_receipt.py`, that runs them with no network.

## Field mapping

| TRACE `references` field | Value for an xChk receipt | Notes |
|---|---|---|
| `rel` | `approval-outcome` | Registered value. The registry belongs in `resolver`, not in a vendor `rel`. |
| `id` | the record hash, 64 hex | Unique and stable in the registry; the bundle is served under it. |
| `resolver` | the registry origin, e.g. `https://in.xchk.io` | The party obliged to keep `id` resolvable. |
| `retention` | the registry's undertaking | Optional. A sealed and anchored record is kept for the life of the plate's chain; the registry's legal-hold rules can extend it. Nothing in either specification enforces it. |
| `digest` | `sha256:` + the record hash | Over the record, not the bundle. The record's canonical form is RFC 8785 for these records, so `rfc8785.dumps(bundle.record)` hashed equals both the registry's `recordHash` and this digest. One number, recomputable on either side. |

The producer in the fixtures is the registry itself, minting a software-only Trust Record per run (`origin` absent: the gate is in the execution path): one `approval-outcome` per act a person was asked about, approved or not. Each fixture record is cut from that to a single reference, so that one case fails one step; the run's own record carries them all. A runtime producing its own Trust Record would carry the same entries, taken from the gate's answers.

## Verifier obligations for this profile

Given a Trust Record and access to the registry named in `resolver`:

1. Verify the Trust Record as usual. This step does not touch the reference, and an unresolvable reference is not a reason to reject the record (section 3.1.2, rule 3).
2. Resolve `id` at `<resolver>/api/receipt/<id>/bundle`. If there is no such receipt, report the approval as unconfirmed.
3. Recompute `sha256` over the RFC 8785 form of `bundle.record` and compare it with `digest`. A mismatch means the registry no longer serves the record the Trust Record pointed at.
4. Run the bundle's offline checks: the record hash; the Merkle path to the seal root; the seal hash; the registry's signatures over it; the approver's assertion (ECDSA P-256 over `authenticatorData || sha256(clientDataJSON)`, a `webauthn.get` ceremony, the user-verified flag set); the registry's binding, and that the binding names this record hash, this credential, and **this public key** (the bundle's own `howToVerify` and `approver.rules` state the same); the anchor when present. Any failure contradicts the approval. Two honest limits of the offline run: the registry keys the script checks against are the ones the bundle carries, pinned to `/.well-known/xchk-keys.json` only when online (the bundle's SLH-DSA root statement lists them and needs a FIPS 205 implementation the script does not ship); and the ML-DSA-65 half of each hybrid signature needs `dilithium-py`, without which the script reports that half as pending, never as passed. In this repository's test only the Ed25519 half is verified.
5. Read `record.disposition`. `approved` is an approval. `denied` and `expired` (asked, no answer within the ask's life) are not, and both are on the record. When `decision.amendment` is present, the approval covers the amended command and nothing else.
6. Where the relying party holds the executed call, compare it with `record.paramsHash` (the digest the gate took over the tool and its parameters), or with the amendment's command.
7. Apply your own floor to `approver.authLevel`: it names the identity proofing the registry did for that credential, and the relying party trusts the registry for it as it trusts any issuer.

Every step from 2 to 5 has a fixture that fails at that step.

## Boundary

Composed this way, a Trust Record and an xChk receipt establish that the record points at a specific sealed act, that the act is unchanged and sits in a chain the registry signed (and anchored, once the seal's anchor has confirmed; the fixtures' seals had not), that a named person whose credential the registry bound answered it with a user-verified passkey, and what they answered. They do not establish:

- **That the approval was checked before the act ran.** A Trust Record is issued per execution, so it cannot carry a commitment someone needs to check beforehand. In xChk the gate holds the act until the ask is answered and the receipt is the gate's own record of that order, but the Trust Record does not carry the gate's ordering claim; `authorized-intent`, through the PIC/TRACE bridge, is the relation for a pre-execution authorization, and is the natural next profile for these receipts.
- **That the executed act is the approved one.** `record.paramsHash` binds the ask to the parameters the gate saw; binding that to what the runtime executed is the runtime's job, by comparing the call it made with that digest.
- **That the policy was right or the person was the right person.** `basis` says which rule asked and `authLevel` says how the person was proofed; whether either suffices is the relying party's policy.

## Conformance fixtures

Seven records and six bundles in [`examples/xchk-approval-outcome/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/xchk-approval-outcome/), minted by the registry at `in.xchk.io` for one run of one plate: approval confirmed; the bundle altered after issue; a declined ask; an ask nobody answered; a reference to no receipt; an impersonated approver, whose assertion verifies with the key the bundle offers while the registry's binding names another; and an approval with changes, where the approval covers the amended command. [`tests/test_xchk_approval_outcome_fixtures.py`](../../tests/test_xchk_approval_outcome_fixtures.py) recomputes every verdict from the committed bytes.

## References

- TRACE v0.2 specification, section 3.1.2 (`references`): [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md)
- xChk registry: <https://in.xchk.io>; receipt endpoint `/api/receipt/<hash>/bundle`; published keys `/.well-known/xchk-keys.json`
- `verify_receipt.py`, the registry's offline verifier (MIT), as the registry serves it: <https://in.xchk.io/verify/verify_receipt.py>
- The fixture generator, `scripts/trace-fixtures.js`, is part of the registry's own code, which is not public; regeneration is the registry operator's
- RFC 8785, JSON Canonicalization Scheme: <https://www.rfc-editor.org/rfc/rfc8785>
- WebAuthn Level 3, assertion signature: <https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion>
