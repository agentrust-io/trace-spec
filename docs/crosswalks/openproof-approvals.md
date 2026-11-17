# OpenProof Approvals Cross-walk

OpenProof records what a document owner approved for an AI agent to change, and the receipt its receiver signs when the change is applied. This page shows how an OpenProof approval links to the TRACE record of the agent run that acted under it, so a reader can find the approval, check who signed it, and check what was executed under it. Neither specification changes.

> **Non-normative.** This document is informative only. Nothing here changes TRACE v0.2 schema fields, wire formats, required claims, or conformance requirements. "TRACE" means the Trust Record defined in [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md). "OpenProof" means [antagoninc/openproof](https://github.com/antagoninc/openproof) at commit `d85c24a`, version 0.9.0 of its `openproof-witness` binary.

---

## Purpose

An agent that changes a document under an owner's approval produces two records. OpenProof holds the approval and what the receiver did with it. TRACE holds what ran, where, and under which policy. A relying party reading the Trust Record needs to find the approval and check it.

TRACE already has the slot. The `references` block (spec section 3.1.2) registers `rel: "approval-outcome"` for "an attributable human approval attached to a step-up or defer decision". This cross-walk shows an OpenProof approval filling it, as [`chap-review-decisions.md`](chap-review-decisions.md) does for a CHAP decision.

## What an OpenProof approval is

OpenProof has four roles: an owner who approves, an authority key that signs approvals, a receiver that applies changes, and a witness that keeps an ordered history of the receiver's receipts. A root key signs a *trust* object that names the authority, receiver and witness keys and, when one is set up, the owner's passkey.

- **Approval.** A signed object that names the document, the expected current version, the SHA-256 of the exact new content, the receiver, a validity window and a nonce. The authority key signs it with Ed25519.
- **Request.** What the receiver is given: the signed approval, the exact content, and, when the trust names a passkey, the owner's WebAuthn assertion over the approval digest.
- **Receipt.** What the receiver signs when it applies a change. It names the approval digest, the document, the new version, the content hash and its own sequence number.
- **Checkpoint.** What the witness signs over the receiver's history: the receiver, the count of receipts and the head hash.

OpenProof signs every object with Ed25519 over its own canonical binary form, OPEC-1, behind a domain-separation prefix such as `OpenProof/v1/document-approval/1`. The *approval digest* is the SHA-256 of those signing bytes.

## Field mapping

| TRACE `references` field | Value for an OpenProof approval | Notes |
|---|---|---|
| `rel` | `approval-outcome` | Registered value. Do not use an OpenProof-specific `rel`; the producer belongs in `resolver`. |
| `id` | `openproof/approval/<approval digest>` | Derived from the approval's own signing bytes. Step 4 below rejects an entry filed under the id of a different approval. |
| `resolver` | the owner's evidence store, as a URI | The party obliged to keep the entry resolvable. |
| `retention` | the store's retention undertaking | Optional. Nothing in either specification enforces it. |
| `digest` | `sha256:` over the RFC 8785 form of the request | The request is the signed approval, the exact content and, when there is one, the owner's assertion, so the digest covers all of them. |

OpenProof itself defines the approval, request, receipt, checkpoint and trust. How a resolver stores them for lookup by `id` is not defined by OpenProof: the fixtures use one JSON object per store, holding the signed trust and, per `id`, the request, the receipt and the checkpoint. Treat that layout as this cross-walk's, not as an OpenProof format.

## Canonicalization

Two canonical forms are in play, and they do different jobs. OPEC-1 is what OpenProof signs, and the `id` is derived from it. RFC 8785 is what the TRACE `digest` covers, computed over the request as stored. The producer and the fixture test both compute it with the `rfc8785` package, so these fixtures measure no agreement between two RFC 8785 implementations, unlike the CHAP fixtures. Every number in the requests here is a non-negative integer below 2^53, and every string is ASCII; the fixture test checks the numbers. A producer whose approved content is non-ASCII text depends on its RFC 8785 implementation agreeing with the verifier's on that text.

## Verifier obligations for this profile

Given a Trust Record, access to the store named in `resolver`, and an OpenProof root key obtained separately from that store:

1. Verify the Trust Record as usual. This step does not touch the reference, and an unresolvable reference is not a reason to reject the record (section 3.1.2, rule 3).
2. Resolve `id` to an entry. If there is none, report the approval as unconfirmed.
3. Recompute the RFC 8785 SHA-256 of the entry's request and compare it with `digest`. A mismatch means the store no longer holds what the record pointed at.
4. Verify the trust under the root key. Then check that `id` is the approval digest, that the approval is signed by an authority the trust names and has not revoked, that the content hashes to the approved `content_sha256`, and that the approval names the trust's receiver. Then apply OpenProof's owner-passkey rule, which depends on where the request sits in the receiver's history:
    - The trust names a passkey, and the entry's receipt, verified under the trust's receiver key, has a sequence number at or after the passkey's `from_sequence`. The request must carry an assertion: a WebAuthn ES256 signature over the approval digest, made with user presence and user verification, for that passkey's relying party and origin.
    - The receipt's sequence number is before `from_sequence`, or the trust names no passkey. The request must carry no assertion.
    - The entry has no receipt, or has one the receiver did not sign. Nothing then places the request in the history. If the trust names a passkey, an assertion is required, because the receiver admits a new request under a passkey only with one. This is stricter than OpenProof for one input: an approval from before the passkey that was never executed is reported as not attributable.
5. If the entry has a receipt, verify it under the trust's receiver key and check that it names this approval, this document, the next version and the same content hash. No receipt means approved but not executed, and the verifier stops here.
6. Only if the entry has a receipt: verify the checkpoint under the trust's witness key, and check that it names the same receiver, that its count equals the receipt's sequence number, and that its head is the SHA-256 of the receipt's signing bytes. This profile keeps with each entry the checkpoint the witness signed at that receipt. A later checkpoint cannot be tied to the receipt without the receipts between them, so this profile reports it as not witnessed.

### What the fixture test shows

Steps 2, 3 and 4 each have a committed fixture that fails exactly that step: `04`, `02` and `05`. Case `03` takes the no-receipt branch of step 5, where step 6 does not run.

The fixture test gives each of its 34 comparisons a name. It rebuilds case `01` under keys it generates at run time, makes one change and signs again: 39 single defects, each reported with the verdict of its step. For each defect it then turns off the one comparison named for it, leaves the others on, and expects the defect to pass. So each comparison is seen to fail, and seen to be the one that catches its defect. Four more rebuilt histories are ones OpenProof accepts at the edge of the passkey rule: an assertion at `from_sequence` and after it, none before it, and none when the trust names no passkey. Five kinds of malformed client data fail in the parse, before any named comparison.

These tests run the Python in the fixture test, which the author of this cross-walk wrote. They do not run OpenProof's Rust or Go verifier, which this repository does not hold. They show that the test's checks do what this page says. That the test agrees with OpenProof rests on a reading of `passkey.rs` and `lib.rs` at the pinned commit, and on the five committed cases, whose OpenProof objects came from the OpenProof binary. This repository holds no differential run against OpenProof's verifier.

### The passkey assertion as stored

The assertion check follows `verify_assertion` in OpenProof's `passkey.rs`:

- The assertion has exactly three fields. Each is base64url with no padding and no unused bit set in its last character.
- The authenticator data is at most 1024 bytes, the client data at most 2048, and the signature at most 80.
- The client data is UTF-8 JSON holding one object. A top-level member that appears twice is refused, because a parser that keeps the last value reads different client data from a parser that keeps the first.
- The type is `webauthn.get`, the challenge is the approval digest, the origin is the trust's, and `crossOrigin` is absent or false.
- The authenticator data is at least 37 bytes, opens with the SHA-256 of the relying party id, and has the user-present and user-verified flags set.

One thing here is stricter than OpenProof: client data nested more than 8 levels deep is refused, where OpenProof's JSON parser has a limit of 128. Python's parser has no limit that matters at this size, so the lower one is there to keep depth from making this check accept client data OpenProof refuses. For the same reason a string holding half of a surrogate pair is refused: OpenProof's parser refuses it, and Python's alone would not. Two limits are not seen failing alone: an empty field, which also fails a later comparison, and a signature over 80 bytes, which no P-256 signature reaches.

## Boundary

Composed this way, a Trust Record and an OpenProof store establish that the record points at a specific request, that the request is unchanged, that a key the owner's root trusts signed the approval, that the owner's passkey signed its digest where OpenProof's rule requires that, and, when a receipt is present, that the receiver signed for executing that approval with that content. They do not establish:

- **That the approval was checked before the action ran.** A Trust Record is issued per execution, so it cannot carry a commitment someone needs to check beforehand (section 3.1.2). In OpenProof the receiver is the component that enforces the approval: it applies a change only under a matching approval and signs a receipt that names it. The record then points back at the approval the run acted under.
- **That nothing else executed.** A receipt shows the receiver signed for this execution. That the receiver applies a change only for the exact content, version and receiver approved, once, before the approval expires, is OpenProof's guarantee G1, which holds under conditions its README states: a passkey on a key no host process can read, and a receiver under its own account. The fixtures meet neither condition (see the last bullet), and they do not exercise the refusal side. Case `03` is a second approval of the same version that the receiver refused because the first had executed, and all the store shows of it is the absence of a receipt.
- **That the witness's history is complete or unforked.** Step 6 shows that the witness key signed a checkpoint whose head is this receipt. It does not replay the receipts before it, and it does not compare the checkpoint with one the relying party pinned separately, as OpenProof's own assessment does. Detecting omission, reordering or a fork is OpenProof's separate Go verifier, run over an exported history. The verdict `approval-confirmed-and-executed` and the finding `witnessed` mean no more than step 6 checks.
- **The validity window, the trust's expiry, or that the nonce was used once.** Steps 4 and 5 do not compare times or replay the history.
- **Who the person is.** The passkey assertion shows the holder of an enrolled authenticator approved with user verification. Binding that authenticator to a named person is outside both specifications.
- **Independence of the roles.** The fixtures were produced with the receiver and witness on one computer under one host account, and the passkey is a software P-256 key standing in for a platform authenticator.

A resolved approval is not attested evidence in TRACE's sense, and it does not change whether the Trust Record verifies (section 3.1.2, rule 3).

## Conformance fixtures

Five records and two stores in [`examples/openproof-approval-outcome/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/openproof-approval-outcome/): an approval executed and witnessed, the same approval altered in the store after the record was issued, an approval that was never executed, an unresolvable reference, and an approval signed by a key the owner's trust does not name. The approvals, receipt, checkpoint and trust come from the OpenProof binary, all but case `05`'s approval from one OpenProof home; the generator makes the Trust Records, the passkey assertions, the store layout and the altered store. [`tests/test_openproof_approval_outcome_fixtures.py`](https://github.com/agentrust-io/trace-spec/blob/main/tests/test_openproof_approval_outcome_fixtures.py) re-verifies them in CI with this repository's own dependencies, including OpenProof's Ed25519 signatures over OPEC-1 and the passkey assertions of cases `01` and `03`. The generator is [`integrations/trace/generate_examples.py`](https://github.com/antagoninc/openproof/blob/d85c24a1ec9228de7c4876904f260a0093312b70/integrations/trace/generate_examples.py) in the OpenProof repository, which needs the OpenProof binary and is not run here.

## References

- TRACE v0.2 specification, section 3.1.2 (`references`): [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md)
- OpenProof repository: <https://github.com/antagoninc/openproof>
- OpenProof guarantees G1 to G3 and their conditions: <https://github.com/antagoninc/openproof#what-openproof-guarantees>
- OPEC-1 encoding, in OpenProof's Python reference: <https://github.com/antagoninc/openproof/blob/d85c24a1ec9228de7c4876904f260a0093312b70/reference/python/openproof_ref.py>
- Signing domains `document-approval/1`, `receiver-receipt/1` and `witness-checkpoint/1`: <https://github.com/antagoninc/openproof/blob/d85c24a1ec9228de7c4876904f260a0093312b70/crates/openproof-witness/src/lib.rs>; `witness-trust/1`: <https://github.com/antagoninc/openproof/blob/d85c24a1ec9228de7c4876904f260a0093312b70/crates/openproof-witness/src/verifier.rs>
- Owner passkey and `from_sequence`: <https://github.com/antagoninc/openproof/blob/d85c24a1ec9228de7c4876904f260a0093312b70/crates/openproof-witness/src/passkey.rs>
- Web Authentication Level 2, assertion signature: <https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion>
- RFC 8785, JSON Canonicalization Scheme: <https://www.rfc-editor.org/rfc/rfc8785>
