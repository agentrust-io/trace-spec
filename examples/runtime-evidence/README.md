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
```

Needs `rfc8785`, `jsonschema`, `cryptography`, `cbor2`, and a checkout of
`agent-manifest` beside this repository. Override the two locations with
`AGENT_MANIFEST_SRC` and `TDX_CAPTURE` if it lives elsewhere.

## The vectors

| Vector | Outcome | What it holds |
|---|---|---|
| `accept-real-quote-platform-attested` | `platform-attested` | the happy path, and note it is not the top grade |
| `downgrade-evidence-absent` | `unattested` | no evidence is not a rejection; every v0.2 record is this |
| `downgrade-evidence-by-reference` | `unattested` | a URI is not evidence held |
| `reject-forged-quote` | reject | one byte flipped inside the signed TD report body |
| `reject-measurement-mismatch` | reject | genuine quote, measurement claimed from elsewhere |
| `limit-substituted-quote-from-the-same-td` | `platform-attested` | **a documented limit, not a success.** See below |
| `reject-evidence-swapped-after-signing` | reject | the record signature is what refuses it |
| `reject-platform-not-the-evidence` | reject | `amd-sev-snp` claimed over a TDX quote |

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
