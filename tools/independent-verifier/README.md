# Independent verifier-token verifier (JavaScript)

A clean-room second implementation of the experimental TRACE verifier-token
and holder-proof verification described in
`docs/verifier-token-experimental.md`. It exists so that interoperability can
be claimed from two implementations that were written separately.

Node 24, built-ins only (`node:crypto` for SHA-256 and Ed25519). The CBOR
codec, RFC 8785 canonicalizer, JSON parser, COSE_Sign1 handling, schema
checks and Ed25519 point validation are written here.

```
node tools/independent-verifier/verify.mjs VECTOR.json [...]
```

Prints one JSON line per vector:
`{"id", "token": "valid"|code, "composite_status": status|null, "proof": null|"valid"|code}`.
Codes are those in `examples/verifier-token-conformance/codes.json`.
`tests/test_independent_verifier.py` runs every vector in
`examples/verifier-token-profile/` and `examples/verifier-token-conformance/vectors/`.

## Independence rules

The author of this code did not open, read, grep or import
`prototype/verifier_token.py`, `prototype/cmcp_gate.py`,
`examples/verifier-token-profile/gen_vectors.py`,
`tools/run_verifier_token_poc.py`, `tools/verifier_token_crypto_oracle.mjs`,
any Python test file, or any other generator code. Inputs were limited to the
profile document, the four experimental JSON schemas, the vector JSON files
and `codes.json`.

Stage 4 additions (delegated component appraisal and `same-evidence-v1`,
30 September 2026) were written from the document sections "Delegated
component appraisal" and "Relationship methods" and the existing code here,
not by porting the Python. They do not meet the clean-room rule above: the
same author also wrote the matching Python reference change and the vectors
in the same session. For these two features, agreement shows that the
document text is implementable as written; it is weaker evidence than the
original independent implementation.

Where the document is silent, the wire was taken from vector bytes
(for example the protected header layout, the key-ID derivation and the
binding digest preimage) or a reading was chosen and recorded below. Expected
codes were never used to tune a check.

## Modules

| File | Content |
| --- | --- |
| `cbor.mjs` | RFC 8949 deterministic decoder (shortest arguments and floats, definite lengths, bytewise sorted unique map keys, no trailing bytes, depth and item bounds) and a small encoder |
| `json.mjs` | RFC 8259 parser with duplicate-member detection; RFC 8785 serializer |
| `schema.mjs` | Closed validation of the token and holder-proof payloads from the JSON schemas |
| `cose.mjs` | COSE_Sign1 unpacking, exact protected header, Sig_structure, Ed25519 verify, RFC 8032 point decoding |
| `verifier.mjs` | Context construction, token verification, composite derivation, holder proof |
| `verify.mjs` | CLI over vector files (new and legacy formats) |

## What it implements

Token, in this order:

1. Clock input is a non-negative integer.
2. Envelope: at most 65536 bytes, canonical CBOR, tag 18, four elements, empty unprotected map, byte-string protected, payload and signature.
3. Protected header is exactly `{1: -19, 2: ["trace-profile"], 3: "application/trace-verifier-token+json", 4: kid (32 bytes), "trace-profile": profile}`; signature is 64 bytes.
4. Payload is UTF-8 JSON without duplicate members, byte-identical to its JCS form, and passes the closed schema.
5. Issuer is found only in the configured trust list by `(iss, kid)`, where kid is SHA-256 of the raw public key; `now` inside the issuer's `[valid_from, valid_until)`.
6. Ed25519 over `["Signature1", protected, h'', payload]`.
7. `cnf.x` is a canonical base64url, canonical Ed25519 point; it differs from the issuer key.
8. Lifetime (`iat < exp`, `exp - iat <= maximum_lifetime`), then `now` in `[iat, exp)`, then `exp` no later than issuer and manifest validity.
9. Audience, subject and instance, manifest digest (SHA-256 of exact manifest bytes) and id, context digest, appraisal policy.
10. Status: `unavailable` fails closed, anything but `active` is rejected.
11. Duplicate and undeclared components and bindings; per component: type, observation pin, instance, appraisal interval, age bound, evidence presence, evidence profile, then the delegated `appraisal` steps from the document (unexpected on an issuer-appraised component; strict base64url, envelope and closed `{profile, iss, component}` payload; configured appraiser by `(authority, kid)` and validity, else unverifiable; signature; signed `iss` and component equal to the carried ones; grant, else unverifiable).
12. Per binding: both endpoints present, same instance, digest `sha256(JCS({method, source: <source component>, target: <target component>}))`, freshness no later than either endpoint; for `same-evidence-v1`, at least one `evidence_refs` digest common to both endpoints.
13. `exp` no later than, and `now` before, the minimum `fresh_until` across required components and bindings.
14. Composite rederived and compared field by field.

Composite derivation: required components are the requirements marked
`required` plus both ends of every configured binding, sorted. A required
component that is absent is `missing`; one whose profile or authority is not
accepted, or whose authority is not the token issuer and has no accepted
delegated appraisal, is `unverifiable`;
otherwise its own status. Each configured binding contributes `missing` if
absent, else its own status. With `allow_warnings` false, `warning` counts as
`contraindicated`. The result is the worst by
`contraindicated > unverifiable > missing > not-appraised > warning > affirming`.
`fresh_until` is the minimum over present required components and bindings.

Holder proof (only when the token is valid): same envelope rules with profile
`urn:agentrust:trace:holder-proof:experimental-v1`, kid equal to SHA-256 of
the `cnf` key, signature under the `cnf` key, then nonce, token digest (SHA-256
of the exact token envelope bytes), token id, audience, session and action
digest, then challenge window and proof expiry no later than token `exp`.

## What it does not implement

Replay stores and nonce consumption (each vector is a single presentation),
the gateway decision receipt, Agent Manifest signature verification (the
manifest is compared by digest and configured id only), evidence resolution,
and anything about cMCP. Status is an input, not a live lookup.

## Ambiguities resolved

Each item is a place where the profile document does not determine the
behavior. These are findings for the spec.

1. **Binding digest preimage.** The document says only "a signed digest of the two component appraisal objects". The preimage `sha256(JCS({"method", "source": <component>, "target": <component>}))` was recovered by searching candidate shapes against the bytes of `01-valid.json`; `codes.json` later stated the same form.
2. **Binding digest over wire or normalized objects.** This verifier hashes the component objects exactly as they appear in the signed payload. The reference hashes a normalized model in which omitted optional members (`resolver`, likely also `observed_digest`) are filled with `null`. A token that omits `resolver` therefore verifies under one and fails under the other (COMP-EVID-003). The spec should either require optional members to be present or define the digest over the received JSON.
3. **Binding whose endpoint component is absent.** This verifier reports `binding_digest_mismatch`, because the signed digest cannot be checked without both appraisal objects. The reference reports `composite_inconsistent`. Both reject; the code differs (legacy 05, LEGACY-05, COMP-BIND-002, COMP-BIND-003, COMP-STAT-007).
4. **Key ID.** "Derived from the trusted public key" is not a definition. SHA-256 of the raw 32-byte key was read from the vector bytes.
5. **Protected header content.** The exact label set, the `-19` value, the crit array and the content types are not in the document. The token content type `application/trace-verifier-token+json` was read from vector bytes. The holder-proof content type `application/trace-holder-proof+json` was assumed by analogy; the proof vectors agreeing confirms it.
6. **Verification-context hash.** The document never defines its preimage, so a relying party cannot recompute it. It is treated as an opaque configured `question_digest` compared for equality.
7. **Check order.** Not specified. When one input breaks two rules, the code depends on order. Chosen differences from the order in which `codes.json` happens to list codes: `token_lifetime` is checked before `token_expired_or_future` (an empty or over-long interval is a property of the token, not the clock); for the holder proof, `key_id_mismatch` is checked before `signature_invalid`. No vector distinguishes either choice.
8. **Composite status precedence.** Not specified. Chosen, worst first: `contraindicated`, `unverifiable`, `missing`, `not-appraised`, `warning`, `affirming`. No vector combines two different non-affirming statuses, so this is untested.
9. **`allow_warnings`.** Not specified whether it changes the reported status or only admission. Chosen: when false, `warning` counts as `contraindicated` in the composite (COMP-WARN-003 agrees).
10. **Unaccepted profile or authority.** No reason code exists, so it lowers the component to `unverifiable` in the composite instead of rejecting the token. Authority must be in `accepted_authorities` and equal `iss`.
11. **Binding-only endpoints.** Both ends of a configured binding are required, but an end with no entry in `requirements.components` is then `undeclared_component` when present and `missing` when absent, so such a configuration can never be affirming. Context construction should probably reject it.
12. **Composite `fresh_until`.** Taken as the minimum over present required components and all present configured bindings, not bounded by issuer or manifest validity; 0 when nothing is present.
13. **Expiry bound.** `expiry_exceeds_evidence` and `component_expired` consider required components and bindings only; an optional component's freshness does not bound `exp`.
14. **"Canonical CBOR".** Undefined in the document. RFC 8949 section 4.2.1 (bytewise lexicographic key order) is used, not the RFC 7049 length-first order. They agree for the labels in use.
15. **Undecodable protected header bytes.** Reported as `malformed_envelope`, not `protected_headers`.
16. **Holder-proof audience.** Checked against both the challenge audience and the token `aud`.
17. **Holder key validity.** Rejects non-round-tripping base64url, `y >= p` and non-decodable points; small-order points are not rejected. The document says nothing.
18. **Large integers.** A JSON integer above 2^53 cannot round-trip through JCS and is reported as `noncanonical_payload`, before schema range checks.
19. **Legacy context.** The legacy vectors carry no question digest. The token's own `verification_context_hash` from `01-valid.json` is used, as instructed.

## Current agreement

Against 207 vectors (14 legacy, 193 conformance) on 2026-09-30: 201 agree,
6 disagree. All six are items 2 and 3 above.

After the stage 4 additions (2026-09-30): 225 vectors (14 legacy, 211
conformance), all 225 agree. The 18 new vectors are COMP-AUTH-006 to 017 and
COMP-BIND-015 to 020; see the independence note above for their weaker claim.

## Spec clarifications applied after the first run

The first run agreed on 201 of 207 vectors. The six disagreements were two spec gaps, now settled in `docs/verifier-token-experimental.md` and applied to both implementations:

1. A required binding whose source or target component is absent from the token evaluates as `missing`; its digest is not evaluated. This verifier originally rejected it with `binding_digest_mismatch`.
2. The binding digest preimage is each component exactly as signed, with no defaults filled in. The reference originally hashed its normalized model (`resolver: null` added), which a wire-level verifier cannot reproduce. That was a defect in the reference, fixed there.

3. The composite `fresh_until` includes the token `exp` in its minimum, and `missing` outranks `unverifiable`. This verifier originally read both the other way (ambiguities 8 and 12 above). No vector distinguished the readings until COMP-FRESH-009/010 and COMP-COMP-008/009, which this verifier failed before the change.
