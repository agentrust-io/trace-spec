# Small current-contract PIC/TRACE successor boundary corpus

Twelve deterministic synthetic examples against the separately signed successor
artifact introduced by #432, using `schema/pic-trace-successor-v1.json`.
This is a smaller contribution invited in the closing comment on #363 and relates
to #206. It preserves the case-003 distinction developed by Corey Shaffer and the
bare-hex boundary cases recommended by Fabio. It does not reuse, replace, regenerate,
or certify Corey's held 105-fixture corpus or its independent verifier.

These examples use published test-only seeded Ed25519 keys. Their signatures verify
cryptographically but are illustrative, with no production issuer or hardware claim.
The PIC intent and argument digests are synthetic caller-supplied PIC verifier outputs.
No PIC verifier is run here, so `authorization_bound` means the TRACE bridge accepted
these supplied values, never independent verification of PIC policy or canonicalization.

| Cases | Authorization | Successor binding | Outcome |
|---|---|---|---|
| 003 | bound | bound | established |
| 003a, missing envelope fields | bound | refused | not evaluated |
| 003b/003c, complete envelope with empty/unrelated observation | bound | bound | not-established |
| 004, affirmative contradictory observation | bound | bound | contradicted |
| Four 005 signed/supplied bare-hex cases | refused | not evaluated | not evaluated |
| 006 wrong authorization link, 007 substituted envelope, 008 invalid observer signature | bound | refused | not evaluated |

The exact pre-execution authorization is identical for 003/003a/003b/003c. No successor
digest is put into that authorization. Each successor is separately signed over its
own authorization ID and observation digest. For 003a the original signed artifact is
retained while the envelope becomes `{}`; the reference refuses missing fields before
evaluating the digest. 003b/003c instead have correctly signed, matching successor
artifacts but observations that cannot decide the transition predicate.

Native PIC emits bare lowercase hex. The TRACE bridge surface carries `sha256:<hex>`.
The four bare-hex vectors test that representation boundary only. Both signed cases
are re-signed after changing the digest, and the tests independently verify their
Ed25519 signatures before asserting the reference's digest-syntax failure.

`independent.py` is a bounded checker of these published vectors, not a general PIC,
TRACE, or hardware verifier. It imports no reference-library code. It shares RFC 8785,
Ed25519 primitives, and committed schemas, so those dependencies are not independent.
The reference adapter and bounded checker compare all three result fields for every
JSON vector. Case labels describe local test conditions; no global reason-code registry
or normative requirement is added.

Run from the repository root:

```
python -m pytest tests/test_pic_successor_boundaries.py tests/test_adequacy_all_sets.py
python examples/pic-successor-boundaries/generate.py
```

The tests regenerate into an empty temporary directory and compare every byte. They
also check the signed/supplied digest cases reach the intended boundary, and pair
valid authorization/link/signature controls with invalid ones. This is bounded
regression evidence, not full-corpus certification or release acceptance.

The bounded checker uses fixed verification time 160, maximum observation age 30,
executor `executor-1`, trusted observer `observer-1`, and the Boolean `reachable`
predicate. It makes no claim about other identities, policies, shapes or time settings.
Its guards use explicit exceptions, including under optimized Python.
