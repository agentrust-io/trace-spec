# runtime-evidence vectors

Conformance material for [`docs/rfcs/runtime-evidence-profile.md`](../../docs/rfcs/runtime-evidence-profile.md).
Informative. Binds nothing until that proposal is adopted.

## What makes this corpus different

Every vector is built around a **genuine Intel TDX v4 quote**, captured from a GCP C3
confidential VM on 2026-07-21 and committed at
`agentrust-io/agent-manifest:python/tests/fixtures/hardware/gcp-tdx-2026-07-21/`.
Nothing here is minted.

That matters more than it sounds. A synthetic quote is built to the parser's own idea
of the layout, so a corpus of them measures a parser against itself. It also would not
have found the limit in §7.1 of the proposal, because minted quotes would have been
given different measurements and the substitution vector would have passed.

The quote verification is `agent-manifest`'s, imported unmodified. TRACE does not
implement attestation, and the proposal does not start.

## Running it

```bash
python generate.py            # run the rules, print the table
python generate.py --out vectors   # also write each record as JSON
pytest test_appraisal.py           # the same rules, asserted
```

Needs `pytest`, `rfc8785`, `jsonschema`, `cryptography>=42,<51`, `cbor2`, and a checkout of
`agent-manifest` beside this repository. The cryptography range matches the imported
verifier's declared dependency; older releases do not expose `not_valid_before_utc`.
Override the two locations with `AGENT_MANIFEST_SRC` and `TDX_CAPTURE` if it lives
elsewhere.

Every committed vector declares `tag:agentrust-io.com,2026:trace-v0.3`. A v0.2
validator is expected to refuse vectors carrying `runtime.evidence`; treating these
examples as v0.2 would erase the version boundary the new member requires.

Records are signed with a fixed published test key, so regeneration is byte-identical
and `--out` produces no diff unless something actually changed. The key signs nothing
outside this directory and protects nothing.

## What CI measures, and where

Two jobs, because the two halves have different dependencies.

`tests/test_runtime_evidence_vectors.py` runs in the ordinary suite on every push and
asserts the half this repository can check on its own: schema validity against the
draft, signature validity, evidence shape, the corpus count, and the pinned fact that
no vector reaches the top grade. It never imports `agent-manifest`.

`test_appraisal.py` runs in the dedicated `runtime-evidence` job, which checks out
`agent-manifest` at a pinned commit and runs the real TDX verifier over the committed
quotes. It asserts each vector's grade, the specific reason for each rejection, and
that regenerating the corpus reproduces the committed bytes. Nothing in it is mocked,
and a missing verifier or a missing capture fails the job instead of skipping it, which
is what a skipped test would have looked like: coverage that is none.

## The vectors

| Vector | Outcome | What it holds |
|---|---|---|
| `accept-real-quote-platform-attested` | `platform-attested` | the happy path, and note it is not the top grade |
| `accept-collateral-omitted` | `platform-attested` | `collateral` is optional, and omitting it changes nothing |
| `reject-collateral-required` | reject | `required` contradicts a format that carries its own chain |
| `downgrade-evidence-absent` | `unattested` | no evidence is not a rejection; every v0.2 record is this |
| `downgrade-evidence-by-reference` | `unattested` | a URI is not evidence held |
| `downgrade-unsupported-format` | `unattested` | the verifier's coverage gap is not the record's defect |
| `reject-forged-quote` | reject | one byte flipped inside the signed TD report body |
| `reject-measurement-mismatch` | reject | genuine quote, measurement claimed from elsewhere |
| `limit-substituted-quote-from-the-same-td` | `platform-attested` | **a documented limit, not a success.** See below |
| `reject-evidence-swapped-after-signing` | reject | the record signature is what refuses it |
| `reject-platform-not-the-evidence` | reject | `amd-sev-snp` claimed over a TDX quote |
| `advisory-binds-cannot-raise-a-claim` | `platform-attested` | declares a binding it does not have; model claim stays self-reported |
| `commitment-cannot-attest-model` | `platform-attested` | a recomputable `REPORT_DATA` match is a commitment, not model evidence |

Each vector asserts the record grade **and** the model-claim grade. The profile's §6.1
is a claim about how those two relate, so a corpus checking only the first would not
test it.

## The limit

`limit-substituted-quote-from-the-same-td` was written to be a rejection and is not one.

Both captures come from one TD, so they share an MRTD and differ only in what they bind
in `REPORT_DATA`. Swapping one for the other leaves the measurement rule satisfied, and
the swap passes.

It is kept, named as a limit, and left failing-by-design rather than deleted or
"fixed". The rule binds a record to a measurement and never to a quote, so two quotes
from one TD are interchangeable under it. That is why the profile's middle grade means
"genuine silicon reporting this measurement" and never "this execution", and it is the
argument for the top grade existing at all.

A corpus that only confirms its own rules has not measured them.
