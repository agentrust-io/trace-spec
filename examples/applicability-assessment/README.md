# An assessor's statement of legal applicability as an `applicability-assessment` reference

A TRACE Trust Record can point at an assessor's statement of whether a stated legal
provision applies to a stated party: the party and its role in the instrument's own
term, the jurisdiction, the provision and the date of the text read, the basis, and the
outcome in a closed vocabulary the object names. These fixtures show that composition.
Each record carries one `references` entry with `rel: "applicability-assessment"`, and
its `digest` is the SHA-256 of the RFC 8785 canonical form of the assessment object as
the resolver retains it.

The relation is defined in [`docs/references-registry.md`](../../docs/references-registry.md).
What a relying party may establish from a resolved reference is bounded to the object:
that the resolved bytes are the cited bytes, and, under an issuer key it holds, that the
named issuer signed them. Neither reaches the record: under §3.1.2 rule 3 it verifies the
same whether the reference resolves or not, and nothing in the object becomes attested
evidence. An `applies` outcome is the assessor's claim and nothing more: it is not
attested evidence that the provision applies in law, and it is never evidence that the
duty was met. A `does-not-apply` or `undetermined` outcome is not a finding for or
against the record. Cases `01`, `03`, and `04` are the same record shape citing an
`applies`, a `does-not-apply`, and an `undetermined` assessment, and they verify
identically.

Everything here derives from one published seed through
[`gen_applicability_assessment_vectors.py`](gen_applicability_assessment_vectors.py), so
the set regenerates byte for byte; the issuer, the party, and the assessment details are
illustrative, and every digest and signature recomputes from the committed files.
[`tests/test_applicability_assessment_fixtures.py`](../../tests/test_applicability_assessment_fixtures.py)
recomputes every verdict from those bytes rather than reading it from `expected.json`,
and re-runs the generator against the committed files.

## The referenced object

`assessment-store.json` holds four assessment objects by identifier, including one
`applies`, one `does-not-apply`, and one `undetermined` object under the configured
issuer key, plus one `applies` object signed by a second issuer. Each one carries:

| Member | What it is |
|---|---|
| `type` | `applicability-assessment` |
| `issuer`, `issuer_key_id` | The party that performed the assessment, and the RFC 7638 thumbprint of its Ed25519 key |
| `party.id`, `party.role` | The party assessed and its role in the instrument's own term (`deployer`) |
| `jurisdiction` | The legal system under which the provision is read (`EU`) |
| `provision.instrument`, `provision.article`, `provision.text_as_of` | The official ELI URI (`http://data.europa.eu/eli/reg/2024/1689/oj`), the article (`26(6)`), and the date of the text read (`2026-09-30`) |
| `basis` | The provisions on which the outcome rests, including the scope rule, classification rule, and any amending provision |
| `outcome.status`, `outcome.vocabulary`, `outcome.detail`, `outcome.applies_from` | The assessor's claim (`applies`, `does-not-apply`, or `undetermined`) in the closed vocabulary the object names, with optional `applies_from` stating the application date independently of any Trust Record |
| `issued_at` | When the issuer signed |
| `signature` | Ed25519 over the RFC 8785 canonical form of the object without this member |

## Fixture cases

Expected results are machine-readable in [`expected.json`](expected.json). Every record
verifies as a TRACE record; what differs is what the reference resolves to. Resolution,
digest match, and signature verification are three separate findings, each reported in
its own column and its own field. The verdict names the state of the referenced
assessment, not whether the legal duty applies or was met: a verified assessment does
not establish that the provision applies in law, and a digest mismatch does not
establish that it does not.

| Record | Store | Reference | Digest | Issuer key held | Issuer signature | Outcome | Verdict |
|---|---|---|---|---|---|---|---|
| `01-assessment-applies-verified.json` | `assessment-store.json` | resolves | matches | yes | verifies | `applies` | assessment verified |
| `02-assessment-altered-after-issue.json` | `assessment-store-altered.json` | resolves | **differs** | yes | **fails** | `applies` | assessment digest mismatch |
| `03-outcome-is-does-not-apply.json` | `assessment-store.json` | resolves | matches | yes | verifies | **`does-not-apply`** | assessment verified |
| `04-outcome-is-undetermined.json` | `assessment-store.json` | resolves | matches | yes | verifies | **`undetermined`** | assessment verified |
| `05-reference-unresolvable.json` | `assessment-store.json` | **no such entry** | n/a | n/a | n/a | n/a | assessment unresolved |
| `06-issuer-key-not-configured.json` | `assessment-store.json` | resolves | matches | **no** | not checked | `applies` | assessment unverified |

`02` is `assessment/2`, issued as `does-not-apply`, rewritten in the stored copy as
`applies` after the record was issued. Both checks catch it independently: the record's
digest no longer matches, and the issuer's signature no longer verifies over the
rewritten bytes. Both findings are about the stored copy; neither says whether the
provision applies. A signature that fails over bytes whose digest does match is reported
as assessment signature invalid, a separate verdict the tests exercise.

`03` and `04` cite `assessment/2` (`does-not-apply`) and `assessment/3` (`undetermined`)
from the unaltered store. Both records verify identically to `01` (`applies`), and the
relying party reports each outcome as the assessor's claim without promoting it in any
direction.

`05` is what §3.1.2 rule 3 requires: a verifier must not reject a record because a
reference cannot be resolved. The record verifies, and the assessment it points at is
reported as unresolved, which is a different answer from "no assessment".

`06` cites an assessment signed by an issuer whose key this relying party does not hold.
The rule §3.3.2 gives receipts applies: unverified, not invalid. The cited bytes are
the cited bytes; whether the named issuer signed them is not established.

If the optional reference digest is absent, the example assessment helper reports
`assessment-digest-unavailable` and `digest_matches: null`: a signature can still
verify, but identity with the bytes cited by the record has not been established.
This helper reports findings about the external object; it is not an assessment
resolver invoked by `verify_record`.

## Running the checks

```
python -m pytest tests/test_applicability_assessment_fixtures.py
```

To regenerate, run the generator with no arguments. It is deterministic, so the
committed files only change when the generator does.
