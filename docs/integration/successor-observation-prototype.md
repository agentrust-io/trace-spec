# Successor-observation prototype for PIC/TRACE (#338)

Status: experimental review artifact. This is not part of the PIC/TRACE bridge v1 wire format.

## Purpose

The current bridge requires `transcript.after` to be an object but does not bind its
identity or define what a verifier may conclude from it. Issue #338 proposes separating
two questions:

1. **Integrity:** is this the exact successor envelope (observation, observer, and time) that the profile bound?
2. **Sufficiency:** is that observation trusted, fresh, independent when required, and
   decisive under the transition predicate?

This prototype exists to make those conclusion rules executable before choosing a schema.

## Prototype boundary

`evaluate_successor_observation()` receives an `expected_successor_digest` from its
caller. That parameter deliberately stands in for the future binding mechanism. The
prototype does not decide whether the digest belongs in the signed authorization,
`transcript.after`, or a detached successor-observation artifact.

The successor envelope is deliberately small:

~~~json
{
  "observation": {"application": "defined"},
  "observer": "observer-identity",
  "observed_at": 1750000000
}
~~~

The verifier separately supplies:

- the expected RFC 8785 / SHA-256 digest of the complete successor envelope;
- its trusted observer set;
- the executor identity, if known;
- whether observer independence is required;
- freshness policy;
- an application-defined predicate.

## Outcomes

The evaluator returns exactly one of:

- `established`: trusted, bound evidence satisfies the predicate;
- `contradicted`: trusted, bound evidence falsifies the predicate;
- `not-established`: the evidence is absent or insufficient to justify either result.

Malformed artifacts and binding failures are errors rather than a fourth evidence result.

The important rule is that a successful digest check binds observation content, observer identity, and observation time and is necessary for integrity but is
never sufficient for `established`.

## Counterexample from #332

If an executor performs a Git push and then supplies the only observation saying the
repository reached the intended commit, the observation can be byte-perfect and still be
self-certified. With `independence_required=True`, the prototype therefore returns
`not-established` when `observer == executor_id`.

The same evidence can establish a transition when policy does not require independence.
The prototype intentionally does not make independence universal.

## Non-goals

This prototype does not define:

- the final bridge schema;
- a universal transition-predicate language;
- replay or one-shot authorization semantics;
- application-state storage in TRACE;
- a repository-wide status enum;
- proof of a real-world outcome merely from a bound transcript.

It is intended to be falsified before any of those choices are made.
