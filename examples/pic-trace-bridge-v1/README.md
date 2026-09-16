# PIC/TRACE bridge conformance corpus v1

**September 15 review status:** case 003 now uses the separately versioned
[case-003 reconciliation contract](CASE003-REVIEW.md). Its old empty-after
positive credit is withdrawn. Run `run_bridge_vectors.py --case-003` for the
bounded review. The remaining text describes the frozen corpus baseline;
full-corpus certification and the original 45-rule mutation claim remain held.

*Informative and non-normative.* This corpus exercises the optional PIC/TRACE
authorization bridge described in
[`docs/integration/pic-trace-bridge-v1.md`](../../docs/integration/pic-trace-bridge-v1.md).
It changes no TRACE schema, bridge implementation, wire format, or specification
requirement. Nothing here binds another implementation.

The corpus keeps four outcomes separate:

```text
Schema-invalid
!= Semantically invalid
!= Authorization denied
!= Authorization/execution mismatch
```

It also tests a narrower assurance claim: rejection is not enough when a case is
intended to exercise one particular rule. Each negative case names an exact
classification and semantic reason code so a rejection reached through an earlier,
unrelated check does not count as agreement.

## Three validity layers

Every case records three results independently:

1. `expected.case_schema` states whether the portable case envelope conforms to
   [`contract/case-v1.schema.json`](contract/case-v1.schema.json). Every committed
   case records `valid` here.
2. `expected.bridge_schema` records whether `inputs.bridge` conforms to
   [`schema/pic-trace-bridge-v1.json`](../../schema/pic-trace-bridge-v1.json). A
   bridge may intentionally be schema-invalid while its case envelope remains valid.
3. `expected.conformant_runtime` records the portable semantic result as the exact
   `{classification, codes, result}` object.

Schema checking and runtime scoring are separate operations. Bridge-schema
prevalidation does not mask the runtime rule a case is designed to reach.

## Case status and known defects

`conformance.status` distinguishes ordinary conformance expectations from pinned
reference-implementation defects:

- `conformant` cases are counted in conformance, adequacy, and mutation margins. The
  reference and independent result paths are compared with
  `expected.conformant_runtime`.
- `known_defect` cases carry the exact tracker
  [trace-spec issue #247](https://github.com/agentrust-io/trace-spec/issues/247),
  `counted_as_conformance: false`, and a `reference` observation bound to an
  implementation name and baseline commit. Their portable target remains under
  `expected.conformant_runtime`; current reference behavior is recorded separately
  under `conformance.reference.runtime`.

Known-defect rows do not contribute to conformance totals or load-bearing margins.
They are checked as a closed defect ledger: if the reference result changes, the row
is reviewed and either updated against the tracker or promoted to `conformant`.

The two issue-247 defect families are:

- schema-invalid signature representations accepted by the permissive reference
  decoder; permissive acceptance is recorded as an observation, not as correct
  behavior;
- exact-valued JSON numbers such as `100.0`, which JSON Schema treats as integers
  while the Python reference requires an `int` instance.

Two other measured divergences are represented as conformant diagnostic or coverage
cases: a signed timestamp outside the JCS safe-integer domain currently collapses into
`authorization_unverifiable`, and transcript `after` is checked only for object shape,
so an empty object is accepted. Neither case invents a finer diagnostic or additional
transcript-result members.

## Portable case shape

Each sibling JSON file is one self-contained scenario:

| Field | Meaning |
|---|---|
| `id`, `name`, `description`, `profile` | Stable identity and corpus version. |
| `conformance` | `conformant` or a machine-readable `known_defect` record. |
| `inputs` | Bridge, trusted JWK, declaration, PIC verifier outputs, tool call, transcript, and fixed verification time. |
| `reproducibility` | Canonical preimages and hashes where they exist, or an explicit non-applicable reason. |
| `coverage` | Rule, vector variant, and the declared implementation defect that separates its pair. |
| `expected` | Independent case-schema, bridge-schema, and conformant-runtime expectations. |

The input members are deliberately open to any JSON value inside the otherwise closed
case envelope. Wrong types and malformed objects are inputs under test, not malformed
case metadata.

An accepted runtime result contains the authorization ID, selected tool, selected
impact, and whether transcript evidence was bound. Non-accepted results carry `null`
and at least one exact code. The complete ordered code registry is
[`contract/reason-codes-v1.json`](contract/reason-codes-v1.json).

## Reproducibility and test keys

The generator derives its Ed25519 fixture key from a published, fixed test seed using
a stable role label. The seed is intentionally public, has no production standing,
and exists only so another implementation can reproduce every signature. Fixtures
contain public JWK material only.

Verification time is explicit in every case. Generation does not read the wall clock.
Where canonical material exists, the generator records the base64url encoding of the
RFC 8785 bytes and their `sha256:` digest alongside the generated artifact. Where the
input has no canonical preimage, the case records `applicable: false` and a stable
reason instead of inventing bytes.

Regenerate the flat fixture set from the repository root:

```bash
python examples/pic-trace-bridge-v1/gen_bridge_vectors.py
```

Score every case through the independent and reference result paths:

```bash
python examples/pic-trace-bridge-v1/run_bridge_vectors.py
```

Run the corpus, completeness, and byte-reproduction checks:

```bash
python -m pytest tests/test_pic_trace_bridge_vectors.py tests/test_pic_trace_bridge_completeness.py tests/test_generators_reproduce_fixtures.py -v
```

`tests/test_generators_reproduce_fixtures.py` discovers the colocated
`gen_bridge_vectors.py`, removes only its sibling fixture JSON files in a temporary
copy, regenerates them, and compares names and bytes. The hand-authored contract files
remain under `contract/`, outside that generated-file ownership boundary.

## Independence and claim ceiling

The generator and independent verifier use standards libraries directly and do not
import `agentrust_trace.intent_bridge` or its private helpers. The reference adapter is
a separate, narrow path that calls the current implementation and maps only its closed
class/message signals. It does not inspect a case's expected answer to choose a code.

Agreement on this corpus shows agreement for these inputs, classifications, codes, and
normalized results. It does not establish that the informative bridge rules are
normative, that the rule inventory is complete relative to an external specification,
that an execution occurred, that its real-world outcome was correct, or that a TRACE
attestation is valid. Completeness is measured only against the explicit rule registry
and declared mutations carried by this corpus.
