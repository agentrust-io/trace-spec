# trace-verify-ts

A TypeScript verifier for TRACE v0.2 Trust Records.

It is a second implementation, written from [`spec/trace-v0.2.md`](../spec/trace-v0.2.md)
and the schemas in [`schema/`](../schema), and held against the Python implementation in
this repository by a differential harness. Two implementations that agree are evidence the
specification says what it means; where they disagree, the disagreement is written down
rather than smoothed over.

It runs on WebCrypto alone: no network, no filesystem, no platform module, no runtime
dependency. That is what a browser, an edge worker or a service mesh sidecar needs to check
a record without a Python runtime.

## Using it

```ts
import { verifyRecord } from "trace-verify-ts";

const result = await verifyRecord(record, {
  trustedKey: issuerJwk,          // an Ed25519 public JWK the caller already trusts
  maxAgeSeconds: 86400,           // section 3.2.2 default
  revocationBundle: bundle,       // optional, section 3.2.3
  trustedBundleKeys: [logJwk],
});

result.trustedKeyThumbprint;      // RFC 7638 thumbprint of the verifying key
result.revocation.outcome;        // "verified" | "unverified_for_revocation" | "no_check_performed"
```

A rejection is a `TraceVerificationError` carrying a stable `code`. A resolved result still
has to be read: `revocation.outcome` is the verifier's appraisal input, and section 3.2.3
states that `unverified_for_revocation` and `no_check_performed` MUST NOT be reported as an
affirming appraisal.

## What it checks, and where each rule comes from

| Check | Source |
|---|---|
| `eat_profile` is `tag:agentrust-io.com,2026:trace-v0.2`, and the v0.1 identifier is rejected rather than accepted | spec section 2, "the cutover is cutover, not coexistence" |
| The record conforms to `schema/trace-claim.json`, Draft 2020-12, with `pattern` read as ECMA-262 and `format: uri` asserted | schema, and JSON Schema 2020-12 section 7 |
| The signature is Ed25519 over the RFC 8785 form of the record with `signature` absent | spec section 3.2.2 |
| The signature is canonical unpadded base64url: no padding, unused trailing bits zero | RFC 4648 sections 5 and 3.5 |
| An integer outside the JCS safe range MUST be rejected rather than canonicalised | spec section 3.2.2, RFC 8785 Appendix B |
| `cnf.jwk` is an Ed25519 key whose RFC 7638 thumbprint is the verifying key's | spec section 3.2.2 |
| Freshness: `iat` is an integer, the record is not past `maxAgeSeconds` and not further ahead than `maxFutureSkewSeconds` | spec section 3.2.2 |
| Revocation is keyed on the trusted key and never on the record's own `cnf.jwk` | spec section 3.2.3 |
| A revocation bundle a verifier cannot ground an answer on is reported as `unverified_for_revocation`, which MUST NOT be read as an affirming appraisal | spec section 3.2.3 |
| A statement naming the key rejects the record whatever the bundle's age | spec section 3.2.3 |
| `delegation.parent_record_hash` is taken over the complete parent record, signature included | spec section 3.1.3 |
| A chain digest whose prefix names an unsupported algorithm MUST be rejected rather than computed with another | spec section 3.1.3 |

The check order inside `verifyRecord` is the Python implementation's, so both report the
same first failure for the same record. It is documented beside the function.

## What it does not do

- No chain walk. The `delegation` block is normative in v0.2 and what a verifier does with a
  chain of them is not, so this package ships one link (`verifyDelegationLink`) and leaves
  the policy to its caller. See [`docs/rfcs/a2a-delegation-profile.md`](../docs/rfcs/a2a-delegation-profile.md).
- No signing. A verifier that can sign is a verifier that can be made to sign.
- No key or bundle fetching. Both are passed in, which is what keeps the package offline.
- No ES256 or ES384 bundle signatures. The bundle schema admits them; a signature nobody
  checked grounds nothing, so they are reported as `bundle_signature_unsupported`.

## Building

```
npm ci
npm run build     # generates the validators from ../schema, then compiles
npm test
```

`npm run build` compiles the schemas ahead of time with ajv into
`src/generated/validators.js`, so nothing is evaluated or fetched at run time, and records
the SHA-256 of each schema file it read. A test compares those digests against `../schema`,
so a schema edit that is not rebuilt fails rather than passing quietly.

## The differential harness

```
python differential/generate_cases.py [--external <trace-tests>/tests/vectors]
python differential/oracle.py          # the Python implementation's verdicts
node differential/run.mjs              # this implementation's verdicts
python differential/compare.py
```

The corpus is one JSON file holding each record as *text*, because several cases exist to
probe a difference that only survives in text. Both runners parse the same bytes with their
own JSON parser. A case agrees when both sides reach the same verdict for the same stated
reason, and every disagreement is argued in
[`differential/known-divergences.json`](differential/known-divergences.json), matched on
both the case and the pair of reported reasons, so a new disagreement in a family already
listed is reported rather than absorbed.

Latest run, against agentrust-trace 0.10.0:

| Group | Cases | Identical |
|---|---:|---:|
| Signed record under 24 verifier configurations, 59 record mutations each | 1416 | 1053 |
| RFC 8785 canonicalization corpus | 34 | 33 |
| RFC 7638 thumbprints | 14 | 14 |
| Chain digests over the delegation corpus | 134 | 134 |
| This repository's conformance vectors | 34 | 34 |
| Published conformance vectors | 12 | 12 |
| **Total** | **1644** | **1280** |

Every published vector agrees. The 364 remaining cases are 13 documented divergence classes
in the adversarial matrix, each one appearing once per verifier configuration.
