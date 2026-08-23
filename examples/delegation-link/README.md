# Delegation-link conformance vectors

Conformance material for the profile proposed in
[`docs/rfcs/a2a-delegation-profile.md`](../../docs/rfcs/a2a-delegation-profile.md).
The `delegation` block is normative in v0.2; the rules for verifying a chain of them are
not, and these vectors exist so the proposal can be argued against executable material.

Nothing here binds an implementation. It scores one.

## Running them

```
python -m pytest tests/test_delegation_vectors.py tests/test_delegation_completeness.py
```

To score an implementation that is not this one, read the vectors directly — each is
self-contained and needs nothing from this repository.

## What a vector is

One JSON file, one scenario:

| Field | |
|---|---|
| `id` | `TRACE-DELEG-NNN`, stable, never reused |
| `context.leaf` | digest of the record under appraisal |
| `context.trusted_root_keys` | JWKs the verifier anchors on |
| `context.credentials` | the delegation credential registry, held out of band |
| `context.data_class_lattice` | least sensitive first; `data_class` is an open string in the schema, so the ordering has to be supplied |
| `context.max_depth` | links the verifier will follow |
| `context.supported_digest_algorithms` | what this verifier can compute |
| `records` | the record set, **emitted leaf-first** |
| `expected` | classification and codes |

`records` is a set, not a sequence. It is emitted leaf-first precisely so that an
implementation reading `records[0]` as the root fails immediately rather than passing until
its first shuffled input. `tests/test_delegation_vectors.py` re-runs every vector under two
further permutations.

Every record validates against `schema/trace-claim.json`, including the ones built to fail.

## Classifications

Three outcomes, and collapsing any two of them is the nonconformance the split exists to
name:

- `provenance-invalid` — the chain's structure or signatures are broken
- `authorization-invalid` — the chain is sound and the authority it claims is not
- `unverifiable` — a link this verifier could not read; not a finding against the chain
- `verified`

## Reproducing them

```
python examples/delegation-link/gen_delegation_vectors.py
```

Keys derive from one published seed by role label — no secret, fully reissuable by anyone.
`tests/test_generators_reproduce_fixtures.py` regenerates the set into an emptied directory
and compares bytes on every run, with no entry in its `NOT_GENERATED` ledger.

## Coverage

Ten rules, two load-bearing vectors each, and for every rule at least one declared
implementation defect that one of its vectors catches and the other misses.
`tests/test_delegation_completeness.py` enforces all three, and records the margins so they
cannot silently thin.

The pairs are not two views of the same mistake. They are built around a specific shortcut a
real implementation takes — verifying the leaf only, anchoring on any trusted key it finds,
an off-by-one bound, case-insensitive lookup of an opaque identifier, issuer and holder
compared to the wrong ends of the hop, half a validity window, narrowing checked at one hop,
the link algorithm read once and assumed uniform.

Vector 05 is the one to read first. It is a complete, correctly signed chain whose only
defect is which bytes its link was computed over, and it is the whole of the difference
between two readings of one sentence in `docs/schema.md`.
