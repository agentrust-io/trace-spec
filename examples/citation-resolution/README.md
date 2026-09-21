# Citation-resolution conformance vectors

Sixteen vectors for the consumer in `agentrust_trace.citation`, which `verify_record`
runs last, after the signature verifies. Each vector is a signed v0.2 Trust Record, the
verification context, and the `citations` mapping a conformant consumer reports for
it. The spec anchor is [section 3.1.2](../../spec/trace-v0.2.md): the three fields this
set exercises are record members, not `references[]` entries, and the anchor names the
discipline the consumer mirrors, rule 3 on what a reference may never do to a record
and the paragraph explaining why TR-POL-003 takes its resolver from the caller, not
the block it describes.

The consumer records one thing: whether a caller-supplied resolver produced bytes for
the URI the record cites, and what those bytes hashed to. It asserts nothing about
what a resolved object binds; that is the question
[agentrust-io/trace-spec#280](https://github.com/agentrust-io/trace-spec/issues/280)
holds. The outcome names are not accepted normative text
([agentrust-io/trace-spec#279](https://github.com/agentrust-io/trace-spec/issues/279)).

## The surfaces

| Surface | Consumed | Written by |
|---|---|---|
| `appraisal.policy_ref` | yes | the AGT and sandbox adapters |
| `runtime.rim_uri` | yes | the sandbox adapter |
| `model.aibom_uri` | yes | nothing under `src/`; the records here are hand-built |
| `transparency` | deferred | the AGT and sandbox adapters |

`transparency` appears in every record and every expected block shows it
`not_attempted` with cause `surface_deferred`: its resolution is coordinated in
[agentrust-io/trace-tests#92](https://github.com/agentrust-io/trace-tests/issues/92)
and held by section 7 open question 3 of the specification. A consumer that reads it
fails every vector in this set.

## Vector fields

| Field | Meaning |
|---|---|
| `id`, `name`, `description` | `TRACE-CRES-nnn`, the file stem, and what the vector shows |
| `spec` | the section 3.1.2 anchor |
| `context.now` | the fixed verification moment; the record is issued one hour before it |
| `context.max_age_seconds`, `context.max_future_skew_seconds` | with `context.now`, these bound the record itself, as the revocation vectors bound the bundle with `max_bundle_age_seconds` |
| `context.trusted_key` | the JWK `verify_record` trusts; every record is signed under it |
| `context.resolutions` | the URIs the harness can resolve, each to `{"bytes_base64": ...}`; absent when the harness supplies no resolver |
| `records` | one signed record |
| `expected.rejected`, `expected.codes` | `false` and `[]` in every vector: no citation outcome rejects a record |
| `expected.citations` | one row per surface, in the consumer's order: `outcome`, `cause`, `evidence` |

`expected.citations[*].evidence` is a subset: a consumer may report more keys, never
different values for these.

**Bytes in hand**, as the revocation and delegation-link sets already do with their
bundles and credentials; a resolver that reaches the network is a harness question and
lives in `tests/`, not here. The harness resolver is a plain function: base64-decode
the entry for the URI, and raise `KeyError` when there is none. The cited objects are
small ASCII documents (a policy stub, a RIM stub, an AIBOM stub) so a reader can decode
them. Their content is irrelevant to the consumer, which hashes what it is handed and
reads none of it.

## Outcomes and the vectors that carry them

Per consumed surface, five vectors; `policy-ref` is 01 to 05, `rim-uri` 06 to 10,
`aibom-uri` 11 to 15.

| Case | Outcome, cause | Evidence |
|---|---|---|
| no resolver: `resolutions` absent | `not_attempted`, `no_resolver` | none |
| resolver lacks the URI | `unresolvable`, `resolver_raised` | `uri`, `exception: "KeyError"` |
| resolver has the URI | `resolved` | `uri`, `sha256` over exactly the returned bytes, `bytes` |
| field absent from the record | `not_attempted`, `field_absent` | none |
| field present, resolver lacks it, record still verifies | `unresolvable`, `resolver_raised` | `uri`, `exception` |

Vector 16 cites all three surfaces and resolves all three at once.

The fourth and fifth cases look alike from the outcome column and differ in what they
witness. Field absent is not unresolvable: nothing was cited, and a consumer that
reports it as a failure to resolve invents a citation. The fifth case holds
`verify_record` to returning a result: inability to resolve is not evidence of a
defect in the record, so it is recorded, never raised.

## What the set discriminates

Each row is a consumer defect; the vectors or tests in the right column go red on it.

| Defect | Caught by |
|---|---|
| no-resolver path reports `resolved` | 01, 06, 11 |
| `resolver_raised` collapsed into `not_attempted` | 02, 05, 07, 10, 12, 15 |
| resolver exception re-raised | the same six; `verify_record` no longer returns |
| `references[]` read and resolved | `test_I3b_I4` in `tests/test_citation_resolution.py` |
| resolver taken from the record | `test_I3a` |
| `resolved` moves the revocation outcome | `test_I2` |
| digest over the URI instead of the bytes | 03, 08, 13, 16 |
| field absent reported as `unresolvable` | 04, 09, 14 |
| `transparency` consumed instead of deferred | every vector |
| a network library imported by the consumer | the import sweep in `tests/test_revocation_bundle.py` |
| a non-callable resolver accepted | `test_I10` |
| the exception object placed in evidence | `test_I6` |
| `model.aibom_uri` dropped from the surfaces | 11 to 15, and every vector's surface list |
| the resolver called before the signature verifies | `test_I11` |

## What is not here

- **A raising or non-bytes resolver.** A fixture cannot carry a function. Both live
  in `tests/test_citation_resolution.py`, where the outcome, the cause, and the fact
  that only a class name reaches the evidence, the exception's or the returned
  value's, are held.
- **A resolved object that binds the record.** Resolution is recorded, not appraised.
  Whether a policy the record points at was in force, and which `appraisal.status` an
  unresolvable citation carries, are open on
  [agentrust-io/trace-spec#190](https://github.com/agentrust-io/trace-spec/issues/190)
  and [agentrust-io/trace-spec#280](https://github.com/agentrust-io/trace-spec/issues/280).
- **`references[]`.** No vector carries the block. A consumer that reads it fails the
  test named above, and section 3.1.2 rule 3 is why it must not.

## Regenerating

```
PYTHONPATH=src python examples/citation-resolution/gen_citation_vectors.py
```

from the repository root. The key derives from a published seed and `now` is fixed,
so the output is byte-identical on every run and every platform; files are written as
bytes with LF endings. `tests/test_generators_reproduce_fixtures.py` regenerates the
set in a copy of the tree and fails if a committed file differs.
