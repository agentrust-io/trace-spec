# Platform-measurement conformance vectors

Sixteen vectors for the consumer in `agentrust_trace.platform_measurement`, which
`verify_record` runs last, after the signature verifies and after the citation
resolver. Each vector is a signed v0.2 Trust Record, the verification context, and the
`platform_measurement` field a conformant consumer reports for it. They are the
platform-measurement row of
[agentrust-io/trace-spec#279](https://github.com/agentrust-io/trace-spec/issues/279),
raised in [#431](https://github.com/agentrust-io/trace-spec/issues/431).

`verify_record` never sees a quote, an event log or reference values: it has
`runtime.platform` and one digest, `runtime.measurement`. For a measured-boot platform
that digest is a composite over many layers, and a match says nothing about which
layers were measured, which were appraised, or whether the evidence describes one boot.
The consumer records what a caller-supplied appraiser reported about the record's
measurement, per layer, and asserts nothing about the platform. The outcome and cause
names are not accepted normative text.

## Outcomes

The measurement as a whole:

| Outcome | Cause | Meaning |
|---|---|---|
| `appraised` | none | the appraiser returned a well-formed report about this measurement; `layers` carries it |
| `appraisal_rejected` | `appraiser_raised` | the appraiser raised; the exception class name is kept, never its message |
| `appraisal_rejected` | `appraiser_returned_invalid` | the report was not `{"measurement": ..., "layers": {...}}` with at least one layer and known statuses; a report naming no layer established nothing and is refused |
| `appraisal_rejected` | `measurement_mismatch` | the report is about another measurement, so it is not attached to this record |
| `not_attempted` | `no_appraiser` | no appraiser was supplied |
| `not_attempted` | `field_absent` | the record carries no `runtime.measurement` (unreachable through `verify_record`, which the schema already gates) |

Each reported layer, keyed by the appraiser's own name for it (`pcr:0` and so on):

| Status reported | Layer outcome | Cause |
|---|---|---|
| `established` | `established` | none |
| `layer_not_measured` | `not_established` | the layer was not measured |
| `measured_not_appraised` | `not_established` | measured, and nothing in the evidence shows it was appraised |
| `evidence_spans_multiple_boots` | `not_established` | the evidence does not describe a single boot |

No layer outcome is an `appraisal.status` value, and no outcome here moves
`revocation`, the thumbprint, `citations` or whether `verify_record` raises.

## Vector fields

| Field | Meaning |
|---|---|
| `id`, `name`, `description` | `TRACE-PMEAS-nnn`, the file stem, and what the vector shows |
| `spec` | the #279 tracker |
| `source` | present only where the measurement comes from published evidence: where that evidence and an offline checker for it are |
| `synthetic` | `true` on every vector without a `source`: the report is made up to exercise a cause, not taken from a platform |
| `twin_of` | on a twin: the vector whose cause it does not produce |
| `context.now`, `context.max_age_seconds`, `context.max_future_skew_seconds` | bound the record itself |
| `context.trusted_key` | the JWK `verify_record` trusts; every record is signed under it |
| `context.appraisals` | the reports the harness appraiser returns, keyed by measurement; absent when the harness supplies no appraiser |
| `records` | one signed record |
| `expected.rejected`, `expected.codes` | `false` and `[]` in every vector |
| `expected.platform_measurement` | `outcome`, `cause`, `evidence`, `layers` |

**Reports in hand.** The harness appraiser is a plain function in `tests/`: return the
report for the record's measurement, and raise `KeyError` when there is none. A report
whose `measurement` member differs from its key is how `07` expresses an appraiser that
appraised other evidence.

## Pairs

Every cause appears twice: in a vector that produces it, and in a twin that carries
the same signed record and the same context except the appraisal table, and differs
only in the one condition that produces the cause. `02`, `04`, `06` and `08` are the
twins of `01`, `03`, `05` and `07` (no appraiser, a raising appraiser, a report of the
wrong shape, a report about another measurement); `10`, `12` and `14` are the twins of
`09`, `11` and `13`, the three layer causes, each reported on `pcr:2` with every other
layer established. `not_attempted` is not a pass, and anything that summarises this
field keeps it distinct from `appraised`.

## Where the reports come from

`15` and `16` carry measurements from published quotes on a physical board with a
discrete TPM (TactiQ OS on Rock 5A, Infineon SLB9670): the v2.1.0-rc13 reference
composite over PCR 0 to 9, where PCR 2, 3, 5 and 7 hold a single separator; and a
cold-start quote over PCR 0 to 12 from a development image, where four IMA entries in
PCR 11 and 12 replay to the quoted values and the policy that leaves them unappraised
is not in the log. The evidence and an offline checker for each are at the URL in
`source`; nothing in this repository reads them. The two-boot cause exists only in the
synthetic pair `13` and `14`: that board resets its TPM before measuring, so it does
not produce a two-boot mix.

Regenerate with `PYTHONPATH=src python examples/platform-measurement/gen_platform_vectors.py`;
the set reproduces byte-for-byte.
