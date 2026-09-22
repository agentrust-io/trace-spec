# @agentrust-io/trust-record-verify

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
import { verifyRecord } from "@agentrust-io/trust-record-verify";

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
so the validators in a build are known to come from exactly those bytes: a build made
against another schema directory (`TRACE_SCHEMA_DIR`) fails that test.

## The differential harness

```
python differential/generate_cases.py --external <trace-tests>/tests/vectors
python differential/oracle.py          # the Python implementation's verdicts
node differential/run.mjs              # this implementation's verdicts
python differential/compare.py --expect-external 12
```

`--external` is a checkout of the published conformance vectors; CI pins one and passes
`--expect-external` with the number of cases it must yield, so a checkout that did not
happen fails the run rather than shrinking the corpus. Without it the corpus is 1632 cases
and the published-vector row below is absent. `generate_cases.py` writes the SHA-256 of
every vector file it read to `build/manifest.json`, and `compare.py` prints the count and
the manifest digest.

The corpus is one JSON file holding each record as *text*, because several cases exist to
probe a difference that only survives in text. Both runners parse the same bytes with their
own JSON parser. A case agrees when both sides reach the same verdict for the same stated
reason, and every disagreement is argued in
[`differential/known-divergences.json`](differential/known-divergences.json), matched on
both the case and the pair of reported reasons, so a new disagreement in a family already
listed is reported rather than absorbed. The ledger holds in the other direction too: each
entry declares how many cases land on it, and an entry, a pair or a count the run does not
bear out fails it, so a divergence that stops happening on either side has to leave the
ledger rather than stay as a claim nothing checks.

Latest run, against this repository's implementation at the commit under test (its version string reads 0.10.0; #383, #386, #387, #388 and #390 landed after that release):

| Group | Cases | Identical |
|---|---:|---:|
| Signed record under 24 verifier configurations, 59 record mutations each | 1416 | 1281 |
| RFC 8785 canonicalization corpus | 34 | 33 |
| RFC 7638 thumbprints | 14 | 14 |
| Chain digests over the delegation corpus | 134 | 134 |
| This repository's conformance vectors | 34 | 34 |
| Published conformance vectors | 12 | 12 |
| **Total** | **1644** | **1508** |

Every published vector agrees. The 136 remaining cases are 7 documented divergence classes
in the adversarial matrix, each one appearing once per verifier configuration. Six classes
left the ledger when the reference stopped diverging: the lone-surrogate revocation bundle
(#382, fixed by #386), `subject` and `appraisal.verifier` under ECMA-262 pattern semantics
(#379, fixed by #388), the IPv4-in-IPv6 literal with a leading zero (#380, fixed by #387),
the non-ASCII nonce (#381, fixed by #383), and present falsy signatures
(#390). The TypeScript signature guard now also distinguishes absent members, null
values and empty strings in the same order as the Python reference. The harness reported each of them as an
entry no case reached, which is how a fixed divergence is meant to leave.

The differential compares verdicts, so it is silent on anything that does not change a
verdict. Whether `timingSafeEqual` is constant-time is not observable in a verdict at all,
and `codePointLength` cannot disagree with `value.length` on anything the current schema
constrains (no `maxLength`; every `minLength` is 1). Those rest on the unit tests and on
reading the code, not on the 1644.
