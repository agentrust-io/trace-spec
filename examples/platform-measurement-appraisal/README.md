# Platform-measurement appraisal vectors

Forty-four signed Trust Records for `appraisal.platform_measurement`, spec section 3.1.5,
raised in [#279](https://github.com/agentrust-io/trace-spec/issues/279). Each file is a
test-vector envelope: the record is under `record`, the verdict under `expected`.

## What is pinned

**Shape.** An accepting vector is a record the schema and the reference model both take.
A rejecting vector carries the one code of the rule it breaks:

| Code | Rule |
|---|---|
| `not_established_without_reason` | a `not-established` layer names one of the three reasons |
| `established_with_reason` | an `established` layer carries no reason |
| `layers_empty` | a result names at least one layer |
| `unknown_reason` | the reason is one of `layer-not-measured`, `measured-not-appraised`, `evidence-spans-multiple-boots`, and not `null` |
| `tpm_layer_name` | on `tpm2` a layer is `pcr:` and a register number from 0 to 23 in decimal without leading zeros |
| `measurement_mismatch` | `platform_measurement.measurement` equals `runtime.measurement` |
| `status_none_with_result` | a record carrying a result does not report `appraisal.status: none` |

`measurement_mismatch` compares two members of the record, which a JSON Schema cannot do.
Its vectors carry `"schema_sees": false`: the schema accepts them and the reference model
refuses them.

**Reading.** On every accepting vector `expected.reading` names, for each layer it asks
about, what a relying party takes from the record. A listed layer reads as its own
outcome; a layer the result does not list reads `not-established` with the reason
`not-listed`. `not-listed` is the reader's finding, not one of the record's reasons, and
a record carrying it is rejected (`unknown_reason`).

## Pairs

`02`, `04`, `06`, `08` and `24` are the twins of `01`, `03`, `05`, `07` and `23`: the same
record except one condition at `pcr:2` (a measured layer, an appraised layer, a single-boot
log, a listed layer, a result at all). `23` carries no `appraisal.platform_measurement`:
a record without the block establishes no layer. A reader that refuses everything fails
the twins; a reader that takes `appraisal.status` at its word fails the cases; a reader
that takes an unlisted layer as established fails `07` and `23`. Every pair is synthetic (`"synthetic": true`).

`05` carries `appraisal.status: "warning"`, not `contraindicated`: a replay mismatch the
verifier cannot attribute to one boot is not, on that basis alone, reported as tampering.

Every rejection, `11` to `22` and `25` to `28`, has an accepting twin, `29` to `44` in the
same order: the rejected record with the one member that breaks the rule put right, and
nothing else changed. A verifier that refuses everything fails all sixteen. `38`, the twin
of `20`, is the record on a non-TPM platform, with a layer named `rtmr:0`: the TPM naming
rule binds `tpm2` only.

## Where the real measurements come from

`09` and `10` carry the `pcrDigest` of published quotes on a physical board with a
discrete TPM (TactiQ OS on Rock 5A, Infineon SLB9670), with the evidence and an offline
checker at the URL in `source`: the v2.1.0-rc13 release reference, in which PCR 2, 3, 5
and 7 hold a single separator only, and a development-image cold-start quote, in which
IMA measurements in PCR 11 and 12 replay and nothing shows they were appraised. That
quote was taken by hand with `tpm2_quote` under the board's registered attestation key;
the image's attestation agent quotes PCR 0 to 9 only, so PCR 10 to 12 are not in its
envelope. Neither
has a twin, because a twin would state something untrue about that evidence. The two-boot
case exists only in the synthetic pair: the development loader on that board resets the
TPM before measuring, so the board did not produce the case.

Regenerate with
`PYTHONPATH=src python examples/platform-measurement-appraisal/gen_platform_measurement_appraisal_vectors.py`;
the set reproduces byte-for-byte.
