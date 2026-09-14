# CHAP review decisions as `approval-outcome` references

A TRACE Trust Record can point at the human decision a run was taken under. These
fixtures show that composition with review decisions recorded by the
[Collaborative Human-Agent Protocol (CHAP)](https://github.com/BrightbeamAI/chap): the
record carries a `references` entry with `rel: "approval-outcome"`, and its `digest`
is the SHA-256 of the RFC 8785 canonical form of the CHAP `decide.approve` envelope.

Full mapping and rationale: [`docs/crosswalks/chap-review-decisions.md`](../../docs/crosswalks/chap-review-decisions.md).

Every CHAP envelope here was produced by `chap-coordinator` 0.2.13, CHAP's Python
reference coordinator, running a workspace with `core/1.0`, `review/1.0` and
`audit-scitt/1.0`: one refund draft approved, one rejected. CHAP verified its own
chain before export. [`generate_with_chap.py`](generate_with_chap.py) produced every
file and is not run by CI, because CHAP is not a dependency of this repository.
[`tests/test_chap_approval_outcome_fixtures.py`](../../tests/test_chap_approval_outcome_fixtures.py)
re-verifies all of it on every run without importing CHAP: the TRACE signatures, each
reference digest recomputed with `rfc8785`, and the CHAP hash chain replayed from the
exported envelopes.

## Fixture cases

Expected results are machine-readable in [`expected.json`](expected.json). Every
record verifies as a TRACE record; what differs is what the reference resolves to.

| Record | CHAP log | Reference | Digest | Decision | Chain | Verdict |
|---|---|---|---|---|---|---|
| `01-approval-confirmed.json` | `chap-audit-log.json` | resolves | matches | `decide.approve` | replays | approval confirmed |
| `02-approval-altered-after-issue.json` | `chap-audit-log-altered.json` | resolves | **differs** | `decide.approve` | **fails** | approval contradicted |
| `03-decision-is-a-rejection.json` | `chap-audit-log.json` | resolves | matches | **`decide.reject`** | replays | not an approval |
| `04-reference-unresolvable.json` | `chap-audit-log.json` | **no such entry** | n/a | n/a | replays | approval unconfirmed |

`02` is the same approval with its comment rewritten in the stored log after the
record was issued. Both checks catch it independently: the record's digest no longer
matches, and the replayed chain no longer reaches the exported head.

`04` is what spec section 3.1.2 rule 3 requires: a verifier must not reject a record
because a reference cannot be resolved. The record verifies, and the approval it
points at is reported as unconfirmed, which is a different answer from "no approval".

## Running the checks

```
python -m pytest tests/test_chap_approval_outcome_fixtures.py
```

To regenerate, install `chap-coordinator==0.2.13` and `agentrust-trace`, then run the
generator. A new run issues a new signing key and new CHAP identifiers, so it replaces
every file here.
