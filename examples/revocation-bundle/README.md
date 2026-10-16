# Revocation-bundle conformance vectors

Conformance material for the consumer side of
[spec section 3.2.3](../../spec/trace-v0.2.md): a verifier holding a
`TraceRevocationBundle/1.0` and a trusted record-signing key, deciding what it may
report. The bundle format is normative and merged; these vectors pin the three
states 3.2.3 requires a verifier to distinguish, and the precedence rule settled on
[#190](https://github.com/agentrust-io/trace-spec/issues/190) between the two age
bounds that govern whether a bundle is still evidence.

The vectors score `agentrust_trace.verify_record`. To score another implementation,
read them directly; each is self-contained.

## Running them

```
python -m pytest tests/test_revocation_bundle.py tests/test_adequacy_all_sets.py
```

## What a vector is

One JSON file, one scenario:

| Field | |
|---|---|
| `id` | `TRACE-RBUN-NNN`, stable, never reused |
| `context.now` | the verification moment, Unix seconds; every age is measured from here, never from the clock |
| `context.max_bundle_age_seconds` | the deployment's bound, measured from the bundle's `issued_at` |
| `context.max_future_skew_seconds` | tolerated clock skew for `issued_at` |
| `context.trusted_key` | the JWK the verifier trusts for the record's signature; carries a `kid` so a statement can name the key either way |
| `context.trusted_bundle_keys` | JWKs whose signatures the verifier accepts on a bundle |
| `context.bundle` | the bundle under test, or `null` |
| `records` | one signed record |
| `expected` | `rejected`, `outcome`, `cause`, `codes`, and the `evidence` fields a second verifier must find |

`expected.evidence` is a subset: every listed field must be present with that value
in what the verifier retains. It is not an exhaustive list of what the verifier
retains, since error message text is not something two implementations agree on.

## The three states, and a fourth

| `outcome` | 3.2.3 says | vectors |
|---|---|---|
| `verified` | "verified against revocation bundle valid at T" | 01, 02, 03, 10, 13 |
| `unverified_for_revocation` | "MUST report the record as unverified for revocation rather than as verified" | 04 to 09, 15 to 24 |
| `no_check_performed` | "MUST report that it performed no revocation check" | 14, 25 |
| `rejected` | the key is named by a statement on the bundle's log; no entry ID is available, so the 3.2.3 fallback applies | 11, 12, 26, 27, 28 |

None of the first three is an appraisal. Which `appraisal.status` value the second
and third carry is the question #190 holds open, and nothing here answers it.

## Precedence, and why there are four age rows with margin

Two bounds govern bundle age: the issuer's `valid_until`, inside the signed bytes,
and the deployment's maximum, supplied per call. Tighter governs. Five
implementations of "too old" are plausible (`min`, `issuer`, `deploy`, `max`,
`none`), and vectors 01, 04, 06 and 08 are the complete truth table of the two
booleans every candidate is a function of. Vector 04 alone separates `min` from
`issuer`; 06 alone separates `min` from `deploy`; without 08, `max` and `none`
give identical answers to every other row. Each boundary is carried by a second
vector one second past it (05, 07, 09): a shortcut that gives either bound a
minute of grace survives every wide row and fails that bound's one-second row,
which the stub table in the tests shows. Vectors 02 and 03 sit
exactly on the two bounds and must verify: the bounds are inclusive on the valid
side.

`tests/test_revocation_bundle.py` implements the five rules as stubs and shows the
four rows reject all but `min`.

## A statement outlives its carrier

The two age bounds say what a bundle's *silence* is worth: an absent statement
means "none known as of `issued_at`", which is informative only while
`issued_at` is recent. A *present* statement was authenticated with the bundle's
signature, has no expiry of its own in 3.2.3 or in the schema, and is read
before either time check. Vectors 26, 27 and 28 carry the same statement as 11
inside bundles that are stale by each bound and dated in the future; all three
reject, where their statement-free counterparts 07, 05 and 24 report unverified.
This ordering was raised in review of the pull request that added the consumer
and chosen there rather than inherited from the shape of the procedure.

## What is not here

- **A bundle that could not be obtained.** A bundle is bytes in hand. What a
  verifier does when the reference cannot be resolved depends on the state of the
  world at that moment and cannot be serialised as a record; it is a harness
  question. Every vector here is offline-decidable.
- **Statement-level signatures.** The bundle signature authenticates the set and
  its horizon. Whether each statement's signer sits above the compromised key in
  the 3.2.1 hierarchy is a separate check that needs the hierarchy, and this set
  does not carry one.
- **Entry-ID scoping.** No SCITT inclusion entry ID reaches `verify_record`, so a
  named key rejects every record it signed. That is 3.2.3's fallback and the
  existing behaviour of the `revocation` store.

## Regenerating

`gen_revocation_vectors.py` derives every key from one published seed and writes
each file as bytes with LF line endings, so regeneration does not depend on the
platform's text-mode convention. It has been held byte-identical on Windows and
on CI's Linux.
`tests/test_generators_reproduce_fixtures.py` holds it to that.
