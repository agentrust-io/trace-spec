# OpenProof approvals as `approval-outcome` references

A TRACE Trust Record can point at the human approval a run was taken under. These
fixtures show that composition with approvals recorded by
[OpenProof](https://github.com/antagoninc/openproof): the record carries a `references`
entry with `rel: "approval-outcome"`, its `id` is derived from the approval's own
signing bytes, and its `digest` is the SHA-256 of the RFC 8785 canonical form of the
approved request (the signed approval, the exact content and the owner's passkey
assertion).

Full mapping and rationale: [`docs/crosswalks/openproof-approvals.md`](../../docs/crosswalks/openproof-approvals.md).

The OpenProof objects here (the signed trust, the approvals, the receipt and the
checkpoint) were made by version 0.9.0 of the `openproof-witness` binary. All but one
came from a single OpenProof home: an owner passkey, two approvals of the same document
version, the first executed and witnessed, the second refused by the receiver because
the document had moved on. The exception is case `05`'s approval, which the same binary
signed with a key outside the owner's trust. The generator made the rest in Python: the
Trust Records, the passkey assertions (from a software P-256 key standing in for a
platform authenticator), the store layout, and the altered store.

The generator is
[`integrations/trace/generate_examples.py`](https://github.com/antagoninc/openproof/blob/d85c24a1ec9228de7c4876904f260a0093312b70/integrations/trace/generate_examples.py)
in the OpenProof repository, and the JSON files here are byte-identical to its output
committed there. It is not run here, because OpenProof is not a dependency of this
repository.
[`tests/test_openproof_approval_outcome_fixtures.py`](../../tests/test_openproof_approval_outcome_fixtures.py)
re-verifies all of it on every run without importing OpenProof: the TRACE signatures,
each reference digest recomputed with `rfc8785`, the Ed25519 signatures OpenProof made
over its OPEC-1 bytes, and the passkey assertions of cases `01` and `03`.

## Fixture cases

Expected results are machine-readable in [`expected.json`](expected.json). Every
record verifies as a TRACE record; what differs is what the reference resolves to.

| Record | Store | Reference | Digest | Attributable | Executed | Witnessed | Verdict |
|---|---|---|---|---|---|---|---|
| `01-approval-executed.json` | `openproof-approvals.json` | resolves | matches | yes | yes | yes | approval confirmed and executed |
| `02-approval-altered-after-issue.json` | `openproof-approvals-altered.json` | resolves | **differs** | n/a | n/a | n/a | approval contradicted |
| `03-approved-not-executed.json` | `openproof-approvals.json` | resolves | matches | yes | **no receipt** | n/a | approved, not executed |
| `04-reference-unresolvable.json` | `openproof-approvals.json` | **no such entry** | n/a | n/a | n/a | n/a | approval unconfirmed |
| `05-approval-outside-trust.json` | `openproof-approvals.json` | resolves | matches | **no** | n/a | n/a | approval not attributable |

`02` is the same approval with its content rewritten in the store after the record was
issued. The record's digest no longer matches, and the content would no longer hash to
the approved `content_sha256` either.

`03` is a second approval of the same document version. The receiver refused it because
the first approval executed first, so the store holds no receipt for it.

`04` is what spec section 3.1.2 rule 3 requires: a verifier must not reject a record
because a reference cannot be resolved. The record verifies, and the approval it
points at is reported as unconfirmed, which is a different answer from "no approval".

`05` is an approval signed by a key the owner's trust does not name, carrying another
approval's passkey assertion. Its digest matches, because the store holds exactly what
the record cited. It fails on the authority check, before its passkey assertion is
read.

## Running the checks

```
python -m pytest tests/test_openproof_approval_outcome_fixtures.py
```

To regenerate, run that script from a checkout of `antagoninc/openproof` with `--out`
pointing at an empty directory, then copy its JSON files here. The script deletes and
recreates its `--out` directory, so do not point it at this one, which also holds this
README. A new run makes new keys and identifiers, so it replaces every JSON file here.
