# Retained verifier-side appraisal context (informative)

TRACE's producer-signed Trust Record is not the verifier's policy or evidence
store. The reference verifier accepts an explicit `now` and a caller-provided
`platform_appraiser`; the caller decides which signed reference values,
resolver outputs, trust roots, revocation view and required measurement layers
its appraiser sees.

This is an informative test, not a new wire format or normative requirement.
`tests/test_retained_appraiser_context.py` uses the existing externally
sourced `15-rc13-layer-not-measured.json` example to demonstrate four
specific properties:

1. Two evaluations of **identical signed record bytes**, with the **same
   trusted key**, can report different `pcr:2` results when the appraiser's
   reference-value table changes. A valid signature cannot by itself
   reconstruct that table.
2. A missing appraiser reports `not_attempted/no_appraiser`, never an
   established measurement.
3. An identical record can be accepted or rejected under different
   verifier-supplied freshness times; the original effective `now` and
   age bounds must be available to reproduce that check.
4. A digest can detect substituted retained context only if the exact
   referenced context bytes are available; a bare hash cannot supply them.

For meaningful offline reproduction, an operator can separately retain the
exact effective verifier input bytes with content-addressed digests, approved
source identifiers and a trusted out-of-band manifest pin. Where a resolver or
appraiser makes a nondeterministic external request, its exact resolved bytes
and the decision-making configuration need retention as well. A later
independent verifier should distinguish “recreated from retained evidence”
from “reported by the original verifier but not reproducible.”

No verifier-created policy or resolver configuration is added to the
producer-signed Trust Record. No `appraisal.status` change or common
not-established enum is proposed. This example does not establish the
authenticity of external reference providers or implement hardware-backed
TPM/TEE attestation. Those are separate trust questions.

Links: upstream [#279](https://github.com/agentrust-io/trace-spec/issues/279),
[#431](https://github.com/agentrust-io/trace-spec/issues/431),
and [#524](https://github.com/agentrust-io/trace-spec/pull/524).
