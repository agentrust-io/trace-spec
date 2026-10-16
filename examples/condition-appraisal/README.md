# An independent check's finding as a `condition-appraisal` reference

A TRACE Trust Record can point at what an independent check found when it held a
deliverable against a stated condition: a test run, a schema validation, a contract
check, a reviewer's signed verdict. These fixtures show that composition. Each record
carries one `references` entry with `rel: "condition-appraisal"`, and its `digest` is
the SHA-256 of the RFC 8785 canonical form of the appraisal object as the resolver
retains it.

The relation is defined in [`docs/references-registry.md`](../../docs/references-registry.md).
What a relying party may establish from a resolved reference is bounded to the object:
that the resolved bytes are the cited bytes, and, under an issuer key it holds, that the
named issuer signed them. Neither reaches the record: under §3.1.2 rule 3 it verifies the
same whether the reference resolves or not, and nothing in the object becomes attested
evidence. A `pass` is not attested evidence that the condition held, and a `fail` is not
a finding against the record. Cases `01` and `03` are the same record shape citing a
pass and a fail, and they verify identically.

Everything here derives from one published seed through
[`gen_condition_appraisal_vectors.py`](gen_condition_appraisal_vectors.py), so the set
regenerates byte for byte; the issuer, the condition and the deliverable are
illustrative, and every digest and signature recomputes from the committed files.
[`tests/test_condition_appraisal_fixtures.py`](../../tests/test_condition_appraisal_fixtures.py)
recomputes every verdict from those bytes rather than reading it from `expected.json`,
and re-runs the generator against the committed files.

## The referenced object

`appraisal-store.json` holds three appraisal objects by identifier. Each one carries:

| Member | What it is |
|---|---|
| `type` | `condition-appraisal` |
| `issuer`, `issuer_key_id` | The party that performed the check, and the RFC 7638 thumbprint of its Ed25519 key |
| `condition.id`, `condition.digest` | The criteria the subject was held against; the digest is over the RFC 8785 form of the value in `context.json` |
| `subject.id`, `subject.digest` | The deliverable that was checked; the digest is over the RFC 8785 form of its manifest in `context.json` |
| `outcome.status`, `outcome.vocabulary`, `outcome.detail` | The finding, in the issuer's own closed vocabulary, which the object names |
| `issued_at` | When the issuer signed |
| `signature` | Ed25519 over the RFC 8785 canonical form of the object without this member |

## Fixture cases

Expected results are machine-readable in [`expected.json`](expected.json). Every record
verifies as a TRACE record; what differs is what the reference resolves to. Resolution,
digest match and signature verification are three separate findings, each reported in
its own column and its own field. The verdict names the state of the referenced
appraisal, not the condition it reports on: a verified appraisal does not establish
that the condition held, and a digest mismatch does not establish that it did not.

| Record | Store | Reference | Digest | Issuer key held | Issuer signature | Outcome | Verdict |
|---|---|---|---|---|---|---|---|
| `01-appraisal-verified.json` | `appraisal-store.json` | resolves | matches | yes | verifies | `pass` | appraisal verified |
| `02-appraisal-altered-after-issue.json` | `appraisal-store-altered.json` | resolves | **differs** | yes | **fails** | `pass` | appraisal digest mismatch |
| `03-outcome-is-a-fail.json` | `appraisal-store.json` | resolves | matches | yes | verifies | **`fail`** | appraisal verified |
| `04-reference-unresolvable.json` | `appraisal-store.json` | **no such entry** | n/a | n/a | n/a | n/a | appraisal unresolved |
| `05-issuer-key-not-configured.json` | `appraisal-store.json` | resolves | matches | **no** | not checked | `pass` | appraisal unverified |

`02` is `appraisal/2`, issued as a `fail`, rewritten in the stored copy as a `pass` after
the record was issued. Both checks catch it independently: the record's digest no
longer matches, and the issuer's signature no longer verifies over the rewritten bytes.
Both findings are about the stored copy; neither says whether the deliverable met the
condition. A signature that fails over bytes whose digest does match is reported as
appraisal signature invalid, a separate verdict the tests exercise.

`03` cites the same `appraisal/2` from the unaltered store. The finding is a `fail`, the
record verifies exactly as `01` does, and the relying party reports the outcome without
promoting it in either direction.

`04` is what §3.1.2 rule 3 requires: a verifier must not reject a record because a
reference cannot be resolved. The record verifies, and the appraisal it points at is
reported as unresolved, which is a different answer from "no appraisal".

`05` cites an appraisal signed by an issuer whose key this relying party does not hold.
The rule §3.3.2 gives receipts applies: unverified, not invalid. The cited bytes are
the cited bytes; whether the named issuer signed them is not established.

## Running the checks

```
python -m pytest tests/test_condition_appraisal_fixtures.py
```

To regenerate, run the generator with no arguments. It is deterministic, so the
committed files only change when the generator does.
