# Measurement appraisal retained-context acceptance : 2026-10-15

## Upstream trigger

[agentrust-io/trace-spec PR #524](https://github.com/agentrust-io/trace-spec/pull/524),
merged as `3202b4e0a5c81c4bcdb8f5c7c817f6ef46704a7b`, updates §3.1.5:
a measured layer may be established by a replaying event log or by a matching
per-layer reference value from a policy-trusted source. It names a matching
reference to an unmeasured layer `layer-not-measured`, a policy-required but
unproven prior appraisal `measured-not-appraised`, and a presented log that
fails to replay `evidence-spans-multiple-boots`. Upstream's
`45-rc14-established-by-reference.json` demonstrates an affirmative result
whose required-layer policy is not in the record.

## Implemented fork experiment

- `measurement_appraisal.py` separately checks *synthetic* RFC8785/JCS
  Ed25519-signed reference and quote evidence, exact pinned reference digest,
  trusted reference/quote signer keys, the record measurement binding, and
  required layers selected by effective verifier policy.
- `retained_evidence.freeze` stores exact signed reference and quote bytes in
  the same manifest as the TRACE record, policy, revocation and resolver bytes;
  absence of either is refused when the measurement contract is required.
- `replay_bundle.run` requires an externally provided manifest hash, validates
  evidence bytes, verifies the TRACE signature through both existing verifier
  paths, and then applies required-layer appraisal with effective policy and
  public keys retained in the pinned envelope. Non-affirming measurement results
  cannot produce a successful bundle decision.
- Adversarial cases demonstrate **the same signed record and matching signature**
  obtaining different appraisals when `required_layers` changes, reference bytes
  or signer trust change, a signed log conflicts, or the policy requires prior
  appraisal. These are distinct verifier-side inputs, not producer-signed claims.

## Verified execution

Prometheus (Python 3.13; isolated `uv`; `TMPDIR=/var/tmp/trace-edrg-temporary`),
source revision `01059cdb0869d0ebfe8a3340bfb89d18a13de3af`:

```
pytest -q tests experiments/verifier-context-replay
1137 passed, 1 skipped, 0 failed
```

One earlier run without the /var/tmp setting failed because the host's /tmp
per-user disk quota was exhausted; restoring the established test TMPDIR
removed those environmental failures.

## Explicit limitations

**This is not a TPM 2.0 quote or event-log cryptographic parser.** The source
and quote interchange implemented here is an experimental, signed test envelope,
not an industry hardware attestation format. Real TPM/TEE trust must validate
the attestation chain, nonce, quote signature/selection, boot provenance and
event-log replay through appropriate independent adapters.

**The fork's current TRACE v0.2 schema does not accept
`appraisal.platform_measurement` inside the signed record.** The experiment
therefore records the computed platform appraisal outside the producer-signed
record and does not weaken the schema validator. Upstream #524's example and
the fork schema must be reconciled separately before claiming full v0.2
compatibility.

A published, signed reference does not alone establish that its issuer was
authorized. Trust-root enrollment, key revocation, policy approval and source
provenance remain external acceptance requirements. A manifest checksum is
not an identity attestation unless it is obtained from an independent trusted
channel. Complete independent external observation remains OPEN.

**EDRG release status: experimental PASS for bounded retained-context replay;
production and upstream conformance BLOCKED.** VPS was offline at this
verification session; no new two-host claim is made for this revision.

## Terminology mapping

| Frequency / experimental term | Standard technical equivalent |
| --- | --- |
| Retained context | Verifier input provenance / decision-context snapshot |
| Replay envelope | Immutable verification-input manifest with out-of-band digest |
| Reference-value route | RFC 9334 appraisal against trusted reference values |
| Required-layer policy | Effective attestation appraisal policy / PCR selection |
| Independent verifier | Separate verification implementation / differential oracle |
| Not established | Indeterminate assurance result / insufficient evidence |
| EDRG | Evidence-backed release acceptance gate |

License, ownership, and authoritative schema remain those of their respective
upstream or fork sources. These experiment files do not amend TRACE normative
requirements.


## 2026-10-15 schema and two-host verification addendum

After this initial experiment, the fork's normative schema (`schema/trace-claim.json`),
packaged schema (`src/agentrust_trace/schema/trace-v0.2.json`), and Pydantic model
were updated to accept and validate `appraisal.platform_measurement`.
The layer result schema is based on the upstream v0.2 shape, with a typed
`patternProperties` map and `additionalProperties: false`, preserving the
fork's bounded-canonicalization guard. This is a **targeted alignment**, not
a wholesale claim of parity with the latest upstream main branch.

Reference `verify_record` and `TrustRecord.model_validate` now reject an
appraisal describing a measurement other than `runtime.measurement`, a
`none` appraisal status carrying a measurement result, and noncanonical TPM
PCR layer names. Signed-record positive and negative tests are included.

Both independent execution hosts tested revision
`afa4e48159044ab5a933e4212eff4241d338cec9` with clean worktrees:

| Host | Runtime | Passed | Skipped | Failed |
| --- | --- | ---: | ---: | ---: |
| Prometheus | Python 3.13 | 1141 | 1 | 0 |
| VPS | Python 3.14.4 | 1141 | 1 | 0 |

The earlier warning that `appraisal.platform_measurement` is rejected by
the fork's schema is superseded by this addendum. Full upstream parity,
hardware TPM/TEE attestation, and independently enrolled external trust
still require separate evidence.
