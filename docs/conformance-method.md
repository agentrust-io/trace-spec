# How the conformance vectors are built, and how the set is checked for holes

*Informative. This page describes method, not requirements, and carries no RFC 2119
keywords.*

A conformance suite makes a promise: an implementation that passes it has done the
things the specification asks for. That promise is only as good as the suite's
coverage, and coverage is usually assumed rather than established. A suite that never
exercises a rule certifies implementations that skip that rule entirely — silently,
and with a green badge.

This page describes how the action-receipt vectors in
`examples/action-receipts/conformance/`
are built, and how the set itself is checked. The checking part found seven rules in
the receipt verifier with no vector behind them.

## 1. Vectors are data, not tests

Each vector is a JSON file stating the inputs, the trust anchors, and the outcome any
conformant verifier must produce:

```jsonc
{
  "context":  { /* what the verifier is told: session, call, freshness policy */ },
  "action":   { /* the action and its canonical reference */ },
  "trusted_issuer_keys": { /* the pinned key set — nothing self-authenticates */ },
  "receipt":  { /* the artifact under test, genuinely signed */ },
  "expected": { "status": "...", "failures": [...], "warnings": [...] }
}
```

Nothing in a vector names a language, a function, or an API. An implementation writes a
small adapter that feeds the JSON to its own verifier and compares against `expected`;
the vectors themselves are portable.

This is worth stating because it is easy to get wrong. One set I wrote began as tests
against a single library's function signature. Those tests were correct, and they were
not conformance vectors: no second implementation could run them. The shape matters
more than the assertions, and the two are easy to confuse while the assertions are
passing.

**Every artifact in a vector is genuinely signed, including in the negative cases.**
A vector that expects a rejection must reject for the reason it names. If its signature
were malformed, the rejection would come from the signature check instead, the vector
would pass, and it would have stopped testing the rule in its own filename.

## 2. The set is checked against the verifier, automatically

The interesting question is not whether the vectors pass. It is whether they cover
what the verifier does. Three questions, in increasing strength:

**Are there dead expectations?** A vector naming a failure code that nothing can emit
holds an assertion that can never fail. Usually it means a rule was renamed or removed
and the vector was left behind.

**Is every rule exercised?** For each code the verifier can emit, is there a vector that
expects it? A rule with no vector is a check an implementation can omit while passing.

**Is every rule load-bearing — twice?** The strongest form: *delete the rule and count
the vectors that notice.* A rule can be named by a vector and still not be load-bearing —
if another rule fires on the same input, removing it changes no outcome and nothing
distinguishes an implementation that performs the check from one that skips it. And one
load-bearing vector is existence, not margin: any change that weakens or retires that
single vector silently removes the rule's coverage. So the floor is two
([#124](https://github.com/agentrust-io/trace-spec/issues/124)), and a ratchet keeps
anything above the floor from quietly decaying back toward it.

**Are the two vectors different tests, or two copies?** Two identical vectors have
margin two and prove nothing extra. #124's definition: vectors are independent if a
single implementation defect causes one to pass and the other to fail. That is made
executable by declaring, for every rule, at least one *weakened* variant of its check —
a plausible implementation shortcut: comparing digest prefixes, case-normalising
identifiers, granting clock tolerance, validating signature structure without
cryptography. The suite fails unless some declared defect deviates one of the rule's
vectors while leaving another undisturbed. The declaration is itself fail-closed: a
rule with no declared defect fails, so "what bug would your second vector catch that
your first would not?" is answered when the rule is added.

The strong criteria subsume the first two questions, which are kept because they are
cheap and their failure messages are more direct.

### The inventory is the registry the verifier consumes

The obvious implementation is a list of rules kept next to the tests. That list is
guaranteed to drift: it is correct only until someone adds a rule and forgets it, and
the failure is silent in exactly the direction that matters.

The first replacement recovered the inventory from the verifier's source with `ast` —
every string literal appended to a failure or warning list. The
[#124 review](https://github.com/agentrust-io/trace-spec/issues/124) identified that
this has the mirror failure mode: a rule written as `extend([...])`, `+=`, an f-string
or a named constant is invisible to the walk, and the suite reports complete coverage
over an inventory that is quietly missing entries.

The resolution, from the same review: the verifier itself consumes an explicit registry
of named rules, and the registry *is* the inventory. A check that is not registered
never runs, so it cannot exist outside the inventory; a residual guard fails on any
code that would emit around the registry. Mutation follows the same principle — a rule
is deleted by rebuilding the registry without its entry, or weakened by substituting
its check, never by pattern-matching source text. If no vector's outcome changes under
a deletion, that rule has no vector standing behind it.

## 3. Fixtures and their checker cannot vouch for each other

A green run proves the vectors and the verifier agree. Both are usually written by the
same person in the same sitting, so agreement is close to guaranteed and says little.
The failure it cannot see: a shared helper that canonicalizes or decodes incorrectly,
used both to generate the fixtures and to check them. Everything agrees, and agrees with
nothing else in the world.

So every signature is re-derived through a path that shares no code with either: it
imports nothing from the library, reuses no helper from the vector modules, and
reconstructs each signing input from the JSON directly. Any vector whose signature is
not re-derived by that path is a failure unless it is explicitly declared
signature-free with a reason — the "missing receipt" case is the only one, since the
absence of a receipt is the thing it tests.

## 4. What this found

Seven rules in the receipt verifier had no vector at all:

| Rule | What an implementation could have skipped |
|---|---|
| `action_ref_invalid` | Recomputing the action reference instead of trusting the declared value |
| `call_id_mismatch` | Checking that the receipt is bound to *this* call |
| `session_id_mismatch` | Checking that it is bound to *this* session |
| `evidence_hash_mismatch` | Recomputing the evidence digest, so a swapped evidence body passes |
| `issuer_key_unknown` | Consulting the pinned key set at all |
| `receipt_from_future` | Rejecting a receipt issued after the verification time |
| `decision_invalid` | Refusing to read an unrecognised decision verb as accept or reject |

Each is a check a conforming implementation could have omitted entirely while passing
the published suite. Two are load-bearing for the trust model rather than merely tidy:
without `issuer_key_unknown` a receipt authenticates itself — a signature verifies
against whatever key it names, and only the pinned set says which keys the verifier can
check, so a receipt under an unpinned key is surfaced as unverified rather than valid or
invalid — and without `evidence_hash_mismatch` the signature covers a digest whose
document may have been replaced.

## 5. The checker's own false positives

Three of its first findings were bugs in the checker, not in the suite. They are
recorded because a completeness checker that reports the wrong thing is worse than
none: it converts attention into noise, and the next person stops reading it.

| Symptom | Cause |
|---|---|
| Every rule reported as non-load-bearing | Mutants were executed into a bare namespace, so `@dataclass` raised before a single vector ran. It read as "every rule matters" while testing nothing. |
| A real outcome reported as unreachable | The scanner walked an entire conditional expression and collected the literal being *compared against* as if it were an outcome. |
| A real warning reported as emitted by no rule | It scanned inline `failures=[...]` arguments but not `warnings=[...]`. |

The pattern in all three: the check failed *open* — it reported a problem where there
was none, which is survivable, rather than passing where there was one, which is not.
That direction was not designed in, and a checker of this kind should be built so that
its own breakage is loud. Hence the guard that asserts the inventory was non-empty
before any conclusion is drawn from it.

## 6. What this does not establish

- **Not that the rules are right.** Completeness is a property of the vectors relative
  to the verifier. If the verifier implements the wrong rule, a complete set pins the
  wrong rule down precisely.
- **Not that the specification is complete.** A rule absent from both the verifier and
  the vectors is invisible to this method. Only reading the specification finds it.
- **Not that an implementation is correct.** Passing shows it agrees on these inputs.
  Behaviour on inputs no vector describes is unconstrained.
- **Not that the vectors are adversarial enough.** Two independent vectors per rule is
  a floor, not a proof of adversarial coverage: independence is demonstrated against
  the *declared* defects, and a shortcut nobody thought to declare is a shortcut the
  pair may still share. The declaration requirement makes the blind spot enumerable,
  not empty.

The method answers one question — *could an implementation skip this check and still
pass?* — and answers it mechanically. That is narrower than "is the suite good", and it
is the part that was previously left to assumption.

## Reproducing

```bash
pip install -e ".[dev]"
pytest tests/test_vector_completeness.py -v          # the completeness checks
pytest tests/test_fixture_signatures_independent.py  # the independent signature path
```

Signing keys are derived from published seeds, so every vector set regenerates
byte-for-byte and only public JWKs appear in the files. They are deliberately
deterministic test keys with no standing.
