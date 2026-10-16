# Reproducibility-claim vectors

Spec section 3.1.4 puts a claim on the record, `reproducibility`, and its result in the
appraisal, `appraisal.method: "re-execution"` with `appraisal.re_execution`. It states
rules about their shape that `schema/trace-claim.json` holds, and these vectors pin each
of them: two per rule, so a shortcut that happens to reject one vector does not pass the
rule (#124), and five accepting records, so a verifier that rejects everything does not
pass the set either.

Each file is a test-vector envelope. The Trust Record is under `record` and is signed;
`expected` carries the verdict and the failure codes; `context`, where present, carries
the JSON values the claim's digests are taken over, so they can be recomputed from the
vector alone. `spec` names the section. The generator is
[`gen_reproducibility_vectors.py`](gen_reproducibility_vectors.py) and
[`tests/test_reproducibility_claim_vectors.py`](../../tests/test_reproducibility_claim_vectors.py)
holds the set to what it says.

## What is real and what is a placeholder

`transcript_digest` and every closure `digest` are SHA-256 over the RFC 8785 bytes of the
values under `context.closure` and `context.transcript`. Vector `03`'s `observed_digest`
is the same computation over `context.observed_transcript`, which differs from the
transcript in one decision. That is the preimage rule the section fixes, and a verifier
can check it here.

`code_identity` and `verifier_code_identity` are derived from the fixture seed. No
implementation artifact exists behind them: these vectors pin the shape of the claim and
of its result, not the re-execution, which needs a function and a closure from a producer
that has both. That corpus belongs beside the annex that describes the function.

Every record is signed, the rejected ones included. The subject of each rejection is the
schema, not the signature: a verifier that reached the signature check on `06` would find
it valid, and the vector says the record is refused before that.

## Vectors

| # | Verdict | Code | Pins |
|---|---|---|---|
| 01 | accept | | The claim with no result; `status: none` is true here |
| 02 | accept | | `reproduced`, with `code_resolver` exercised |
| 03 | accept | | `diverged` carrying the verifier's digest |
| 04 | accept | | `not-attempted`: a closure entry did not resolve |
| 05 | accept | | `not-attempted`: the function read beyond the closure |
| 06 | reject | `re_execution_without_method` | A result under no method |
| 07 | reject | `re_execution_without_method` | Same, on a complete `not-attempted` result |
| 08 | reject | `method_without_re_execution` | A method with no result |
| 09 | reject | `method_without_re_execution` | Same, with `status: none` |
| 10 | reject | `diverged_without_observed_digest` | `diverged` with no digest to compare |
| 11 | reject | `diverged_without_observed_digest` | A `reason` does not substitute for it |
| 12 | reject | `not_attempted_without_reason` | `not-attempted` with the finding discarded |
| 13 | reject | `not_attempted_without_reason` | An `observed_digest` does not substitute for it |
| 14 | reject | `closure_entry_incomplete` | An entry without `digest` |
| 15 | reject | `closure_entry_incomplete` | An entry without `resolver` |
| 16 | reject | `unknown_method` | A method outside the closed set |
| 17 | reject | `unknown_method` | The member's spelling as the value, beside a complete result |
| 18 | reject | `unknown_outcome` | A fourth outcome |
| 19 | reject | `unknown_outcome` | An outcome with the wrong case |
| 20 | reject | `claim_incomplete` | A claim without `transcript_digest` |
| 21 | reject | `claim_incomplete` | A claim without `function` |

Rules the section states that a schema cannot hold are not here: that a closure omitting
an input makes the claim malformed is decided at re-execution, and that `not-attempted` is
never reported as either other outcome binds the verifier, not the record.
