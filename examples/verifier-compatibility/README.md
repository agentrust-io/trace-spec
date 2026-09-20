# Verifier-compatibility vectors (proposed, not accepted)

> These fixtures encode the obligations proposed in
> [agentrust-io/trace-spec#116](https://github.com/agentrust-io/trace-spec/issues/116).
> **No normative text for them has been accepted.** Do not read a passing vector here
> as a conformance requirement.

Compliance evidence is verified years after it is issued, so the artifact routinely
outlives the verifier build that reads it. Nothing in `docs/verification.md` currently
says what a verifier must do about version skew, which leaves two failure modes open:
a revision silently orphans existing evidence, or a verifier "helpfully" accepts an
artifact under semantics it does not implement.

The proposal is four obligations: records carry an explicit profile, a verifier
declares the set it supports and refuses anything outside it, the verification
statement names the profile it ran under, and any fallback is disclosed rather than
silent.

## The vectors

| Fixture | Outcome | What it pins down |
|---|---|---|
| `01-known-version-verified.json` | verified | The statement names the profile verification ran under. |
| `02-unknown-version-refused.json` | refused | A future profile is refused, not best-effort verified. |
| `04-unschemaed-profile-refused.json` | refused | A verifier declaring a profile it carries no schema for, given an ordinary v0.2 record. The record is innocent; the configuration is the defect, which is what makes this vector separate at all. It read `verified, downgraded` until the set was measured. Carries a `preconditions` block: see below. |
| `05-downgrade-silent-is-impossible.json` | refused | The same record where the older profile was never declared. Silent fallback has no outcome. |
| `06-empty-accepted-set-refused.json` | refused | An empty set means "nothing", never "anything". |
| `07-profile-absent-refused.json` | refused | A missing profile cannot be supplied by assumption. |
| `09-unschemaed-profile-first-in-set-refused.json` | refused | The same defect as 04 with the unusable entry first in the declared set. Every declared profile has to be checked, not one of them; an implementation reading only the head or only the tail agrees with one of the pair and not the other. Carries the same `preconditions` block. |
| `11-empty-profile-string-refused.json` | refused | The profile claim is present and empty. 07 removes the member outright, so an implementation testing `"eat_profile" not in record` passes 07 and reads this as an unrecognised profile, or as absent and therefore current. A claim that is present and says nothing is not a claim. |

**Every record in the set is correctly signed.** These vectors never ask whether a
signature checks out; they ask whether a verifier implements the semantics the record
was written under. A vector that failed because its signature was malformed would
silently stop testing the thing it names, so `tests/test_verifier_compatibility_fixtures.py`
re-verifies the signature of every record the v0.2 record schema admits, with the accepted
set widened so that only the signature can fail. The four records carrying another profile
are refused by that schema before the signature is read, so this repository does not check
them a second time; an adapter that wants that check runs its own verifier over them.

## Format

Nothing in a fixture names a language or an API:

```jsonc
{
  "verifier": {
    "accepted_profiles": ["tag:agentrust-io.com,2026:trace-v0.2"],
    "verification_time": 1785000100,
    "check_freshness": false     // version skew is the property under test
  },
  "trusted_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "record":      { "eat_profile": "...", "signature": "..." },
  "expected": {
    "outcome":   "verified" | "refused",
    // informative, see "What `failure` is and is not" below
    "failure":   null | "profile_not_accepted" | "profile_absent" | "no_accepted_profiles"
               | "unschemaed_profile_in_accepted_set",
    "statement": null | { "profile": "...", "accepted_profiles": [...] }
  },
  // Present on 04 and 09 only. See "What two vectors assume about you" below.
  "preconditions": { "unschemaed_for_the_verifier_under_test": ["..."], "why": "..." }
}
```

The statement carried a third key, `downgraded`, until 2026-09-12. It was removed
rather than implemented. Disclosure of a downgrade is obligation 4 of #116, which is
deferred there as unobservable, and no result type in this package carries such a
field; the adapter was deriving the value from the two keys above and comparing it
against the vector's own declaration, so the assertion held for every implementation
and could not fail. A key no implementation reports, tested by an assertion that
cannot fail, is a claim to test obligation 4 that this set does not make good on.

`failure` names **which rule refused**, not a wire format or a message, and it is
informative: see the next section. Nothing in the portable adapter reads it. This
repository maps it to its own messages in `tests/test_verifier_compatibility_diagnostics.py`,
which is about this implementation and not about conformance.

## What `failure` is and is not

**`failure` is informative.** It names the rule this set believes refused the record, and
no conformance assertion is made on it. A verifier that applies every rule agreed here and
reports one generic refusal for all of them conforms, and two controls hold that open:
`test_a_generic_refusal_passes_this_set` in the adapter, and
`test_a_generic_refusal_is_separated_by_nothing` in the separation module. Both fail the
day an assertion on the refusal's cause comes back.

This was settled on review, and the set was stricter than its text until it was. The draft
normative text for #116, held for a maintainer to carry and not part of this change, says
a verifier SHOULD report refusal-for-an-unimplemented-profile distinguishably from a
verification failure, which is coarser than a rule name and is a SHOULD, and it declines
to mandate any field name. Asserting the label was this set asking more of a foreign
implementation than the text it encodes.

The label stays in the JSON because it tells a reader what each vector is for. This
library's own refusal messages are pinned separately, in
`tests/test_verifier_compatibility_diagnostics.py`, which is about this implementation and
is not part of the portable contract.

`tests/test_verifier_compatibility_fixtures.py` is the adapter that runs these against
`agentrust_trace`. Another implementation writes its own adapter and runs the same JSON;
that is the point of keeping the expectations out of the test code.

## What two vectors assume about you

Six of the eight are self-contained: the record and the declared set are both in the
file, and the conformant outcome follows from those two alone. Vectors 04 and 09 are
not, and until 2026-09-12 they did not say so.

Both expect `unschemaed_profile_in_accepted_set`. That is a refusal because the verifier
carries no schema for `tag:example.com,2025:trace-v0.0`, a fact about the implementation
reading the vector rather than about the JSON. It is true of this build and need not be true of
yours. Measured, packaging a schema whose `eat_profile` const is that identifier: both
vectors fail with `DID NOT RAISE`, which reads as a non-conformance when what happened
is that the verifier grew a capability and the vector's premise lapsed.

So the premise is now written in the file, and the adapter checks it before the outcome.
An implementation that can check that identifier has not failed these vectors: it
substitutes one it cannot check. The rule under test is unchanged, and it is the rule,
not the identifier: a verifier refuses a declared set naming a profile whose shape it
cannot check, with an innocent record.

The adapter fails rather than skips when a premise lapses, because a lapsed premise
means the rule stopped being tested and a set that quietly stops testing a rule still
reports green.

## Regenerating

`gen_vectors.py` rebuilds the set. The signing key is derived from a published seed, so
the fixtures reproduce byte-for-byte and only public JWKs appear in them. They are
deliberately deterministic test keys, not keys with any standing.

```bash
python gen_vectors.py   # writes into examples/verifier-compatibility/
```

## Boundary

Passing these vectors shows a verifier refuses what it does not implement and says what
it verified under. It does not show the verifier implements any particular profile
correctly, and it makes no claim about freshness, revocation, or anchoring, each of
which fails independently.
