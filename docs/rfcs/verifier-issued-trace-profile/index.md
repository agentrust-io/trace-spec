# RFC Proposal: a verifier-issued, holder-bound TRACE token

**Status:** Draft proposal. Binds nothing. Experimental wire, `urn:agentrust:trace:verifier-token:experimental-v1`. **Scope:** A new signed token in which an appraisal verifier signs the result and `cnf` names a different key, held by the agent that presents it; a holder proof; and a separately signed gateway decision receipt. Additive: every v0.2 record keeps its meaning, and a v0.2 verifier refuses the new token as an unsupported profile. **Target:** a new profile document next to `spec/trace-v0.2.md`, not an edit to it. **Conformance material:** [`examples/verifier-token-conformance/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/verifier-token-conformance): 215 vectors, the generator, `codes.json` (54 reason codes) and `coverage.json` (47 requirements). The 14 earlier vectors in [`examples/verifier-token-profile/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/verifier-token-profile). A second verifier in JavaScript at [`tools/independent-verifier/`](https://github.com/agentrust-io/trace-spec/tree/main/tools/independent-verifier). Both implementations return the expected outcome on all 229. **Draft schemas:** `schema/trace-token-experimental-v1.json`, `schema/trace-holder-proof-experimental-v1.json`, `schema/trace-requirements-experimental-v1.json`, `schema/trace-decision-receipt-experimental-v1.json`. **Companion:** composite components (what goes in `components`, `bindings` and `composite_appraisal`) are in the companion proposal, [`docs/rfcs/composite-component-appraisal.md`](https://trace.agentrust-io.com/docs/rfcs/composite-component-appraisal/index.md). This document covers the token around them.

Requirement keywords are lowercase throughout, deliberately, on the line `CONTRIBUTING.md` draws: normative text lives in `spec/`, informative text binds no implementation. If these rules are adopted they become uppercase there and this file becomes a pointer to where they went. The wire described here was built and tested before it was written down, and it is still experimental: nothing in it is registered, and every choice listed in §9 can change.

______________________________________________________________________

## 1. What exists today

A v0.2 Trust Record is signed by one key, and `cnf` names that same key.

`sign_record()` in [`src/agentrust_trace/sign.py`](https://github.com/agentrust-io/trace-spec/blob/main/src/agentrust_trace/sign.py) sets `cnf.jwk` to the public half of the signing key. `verify_record()` then refuses any record whose `cnf.jwk` thumbprint differs from the trusted key that verified the signature ("record cnf.jwk does not identify the trusted key that verifies its signature"). That is a sound check for what v0.2 is: a runtime record signed by the workload that produced it.

It cannot say three things a gateway in front of an agent needs to hear:

| Question at the gateway                          | v0.2 record                                                  |
| ------------------------------------------------ | ------------------------------------------------------------ |
| who appraised this agent, under which policy     | the signer, who is also the subject                          |
| is the party presenting it the agent it is about | `cnf` is the signer, so possession proves authorship again   |
| is it meant for me, and still valid              | no `aud`, no `exp`, no `jti`; `iat` plus a local maximum age |

A relying party can impose its own maximum age on `iat`. That is the relying party's rule. It is not the issuer saying how long its appraisal holds, and nothing stops a record appraised for one gateway being replayed at another.

So the token this proposal adds has three principals where v0.2 has one: the verifier that appraised the evidence and signs, the holder that presents the token and proves it has the `cnf` key, and the relying party that decides about one action.

## 2. The model

```
Signed Agent Manifest ----+
                          +--> appraisal verifier --> signed token  (issuer key != cnf key)
Component evidence -------+                                 |
                                                            v
holder: token + proof over (token, audience, session, action) --> relying party
                                                                        |
                                                   own policy: allow / deny
                                                                        |
                                                   signed decision receipt (separate object)
```

The token answers one question: what did a verifier the relying party already trusts establish about this subject, for this audience, under this appraisal policy, until when. The receipt answers a different one: what this gateway decided about this exact call. They are signed by different keys and neither is ever written inside the other.

An affirming token is an input to authorization. The relying party still runs its own policy on the requested action, and `TR-VT-AUTH-001` exists so that a passing token followed by a policy deny is a tested outcome.

## 3. The token

### 3.1 Envelope

COSE_Sign1 (CBOR tag 18), canonical CBOR, at most 65,536 bytes. The unprotected map is empty. The protected header is exactly:

```
{ 1: -19,                                   / alg: Ed25519, fully specified /
  2: ["trace-profile"],                     / crit /
  3: "application/trace-verifier-token+json",
  4: h'<32 bytes>',                         / kid: SHA-256 of the raw Ed25519 public key /
  "trace-profile": "urn:agentrust:trace:verifier-token:experimental-v1" }
```

The signature is Ed25519 over `["Signature1", protected, h'', payload]`. The payload is UTF-8 JSON that must be byte-identical to its own RFC 8785 (JCS) serialization, with no duplicate members.

Every one of those constraints has a vector that breaks it. An algorithm label copied into the unprotected map is `envelope_structure` (`VT-ENV-002`). A gateway decision appended to the unprotected header after signing is also `envelope_structure` (`VT-EXT-002`). A v0.2 payload inside a correctly headed envelope is `malformed_payload` (`VT-PROFILE-005`), and a future `experimental-v2` payload under a v1 header is refused the same way (`VT-PROFILE-007`). Nothing is ever read best-effort.

### 3.2 Payload

The schema is closed. All fifteen members are required:

| Member                                          | What it carries                                                                     |
| ----------------------------------------------- | ----------------------------------------------------------------------------------- |
| `profile`                                       | the exact profile URI, repeated inside the signed payload                           |
| `iss`                                           | the appraisal verifier                                                              |
| `sub`, `instance`                               | the appraised agent and the workload instance                                       |
| `iat`, `exp`                                    | signed integer seconds; valid for `iat <= now < exp`                                |
| `jti`                                           | token identifier                                                                    |
| `aud`                                           | one relying party, a single string                                                  |
| `cnf`                                           | the holder's public Ed25519 key (`kty`, `crv`, `x`; no `d`)                         |
| `manifest`                                      | `id`, `media_type` (`application/agent-manifest+cose`), `version` (`0.2`), `digest` |
| `verification_context_hash`                     | digest of the question the relying party asked                                      |
| `appraisal_policy`                              | `id`, `version`, `digest` of the policy the verifier applied                        |
| `components`, `bindings`, `composite_appraisal` | per-component results and their combination; the companion proposal                 |

Three of those are choices a reader could expect to go the other way. `aud` is one string, with no array and no wildcard; a wildcard fails the schema pattern (`VT-AUD-005`) and a case variant is `audience_mismatch` (`VT-AUD-004`). `instance` is always required, not only for tokens scoped to one instance. The manifest is digested as the exact COSE envelope bytes the verifier was given: a digest of the decoded JCS payload is `manifest_mismatch` (`VT-MAN-003`), and so is a one-byte change to the envelope (`VT-MAN-002`).

Raw evidence, prompts and tool arguments do not appear. Evidence is referenced by digest inside components.

## 4. What the relying party checks

The relying party supplies what no token can: a trust list of issuers keyed by `(iss, kid)` with a validity window each, its own audience, the expected subject and instance, the exact manifest bytes, the question digest, the appraisal policy it accepts, a status callback, a maximum lifetime, a clock, and its component requirements. In the reference the maximum lifetime defaults to 300 seconds and must be between 1 and 86,400.

In the order `tools/independent-verifier/README.md` documents (§9 item 7 is about why order matters):

1. **Envelope and payload** as §3.1, then the closed schema.
1. **Issuer from local trust only.** The `(iss, kid)` pair must be in the configured list and `now` inside that entry's window. A token signed by the key it names in `cnf` is `issuer_untrusted` (`VT-ISS-002`): key material inside the token is never a trust anchor.
1. **Signature** under that configured key.
1. **Holder key.** `cnf.x` must be a canonical base64url encoding of a valid Ed25519 point, and it must differ from the issuer key. `cnf` reusing the verifier key is `issuer_holder_same_key` (`VT-CNF-003`). A private member `d` fails the schema (`VT-PRIV-002`).
1. **Time.** `iat < exp` and `exp - iat` within the maximum lifetime, then `iat <= now < exp`. At exactly `exp` the token is expired (`VT-TIME-003`). The relying party may shorten the window and never extends it. `exp` may not be later than the issuer entry's validity or the manifest's.
1. **Audience, subject, instance, manifest, context, policy**, each by exact comparison.
1. **Status.** `active` passes. An unreachable status service fails closed with `status_unavailable` (`VT-REV-003`); any other state is `status_not_active`.
1. **Components and composite**, per the companion proposal, including the rule that `exp` is no later than the earliest freshness boundary of any required component or binding (`expiry_exceeds_evidence`, `VT-TIME-009`: one second over is enough).

A failed check yields exactly one code from `codes.json`. Of its 54 codes, 51 come from token or proof verification and 3 from refusing a bad relying-party configuration before any token is read.

## 5. Holder proof and decision receipt

A valid verifier signature does not let anyone present the token. The holder proof is a second COSE_Sign1 with profile `urn:agentrust:trace:holder-proof:experimental-v1`, the same envelope rules, a `kid` equal to SHA-256 of the `cnf` key, and a signature under the `cnf` key. Its closed payload binds `nonce`, `token_digest` (SHA-256 of the exact token envelope bytes), `token_id`, `audience`, `session_id`, `action_digest`, `issued_at` and `expires_at`. The proof may not outlive the token.

Proof verification runs only after the token verifies, so the vectors report the two outcomes separately. A proof made for another token and replayed with this one leaves the token `valid` and fails the proof with `holder_proof_binding` (`VT-CNF-007`). A substituted holder key fails with `signature_invalid` on the proof (`VT-CNF-002`). Single use of a challenge is a store property that a vector cannot express, so `TR-VT-CNF-001` and `TR-VT-CNF-002` also name gateway tests in `coverage.json`, including two gateway replicas refusing a proof replayed across them.

The gateway's decision receipt (`schema/trace-decision-receipt-experimental-v1.json`) is signed by the gateway's own key and binds `trace_digest`, `trace_jti`, `session_id`, `call_id`, `action_digest`, `policy_digest`, `decision`, `reason`, and optionally `previous_receipt_hash`. It never modifies the token. A gateway field copied into the token payload and re-signed by the issuer is `malformed_payload` (`VT-EXT-003`), because the payload schema is closed. An allow receipt records authorization; it does not say the call completed.

## 6. Conformance material

`coverage.json` maps every requirement to a positive vector, counterexamples and a causal test. The causal test first shows the unchanged verifier refusing each counterexample, then disables the one rule mapped to that requirement and shows the counterexample admitted. A requirement whose gate can be switched off without any vector noticing is not covered, however many vectors cite it.

For this proposal's 25 `TR-VT-*` requirements:

|                                                      | Count | Where                                              |
| ---------------------------------------------------- | ----- | -------------------------------------------------- |
| portable, covered by token vectors and a causal test | 22    | `coverage.json`                                    |
| gateway-only, covered by named gateway tests         | 3     | `TR-VT-MAN-003`, `TR-VT-AUTH-001`, `TR-VT-REC-001` |
| `VT-*` vectors                                       | 94    | 14 families, `VT-PROFILE` to `VT-EXT`              |

The three gateway-only rows are there because a token vector has nothing to say about them. Whether a Cedar policy denied the call, what a receipt bound, and whether a composition-only manifest was refused before any token existed all live in the gateway.

The corpus as a whole:

| Set                                                                          | Vectors |
| ---------------------------------------------------------------------------- | ------- |
| `VT-*`, this proposal                                                        | 94      |
| `COMP-*`, the companion proposal                                             | 107     |
| `LEGACY-*`, the 14 earlier vectors' exact bytes in the conformance format    | 14      |
| conformance total, `examples/verifier-token-conformance/vectors/`            | 215     |
| earlier vectors in their original format, `examples/verifier-token-profile/` | 14      |
| runs checked for agreement                                                   | 229     |

The generator, `gen_corpus.py`, does not import the reference verifier. It builds envelopes, digests and composite results from `cbor2`, `rfc8785` and Ed25519 primitives and the literal wire definitions, with test-only keys. A corpus signed by the code it tests measures that code against itself.

## 7. What the second implementation found

The JavaScript verifier in `tools/independent-verifier/` runs on Node 24 built-ins only and writes its own CBOR codec, JCS serializer, JSON parser with duplicate detection, COSE handling and Ed25519 point validation. Its author worked from the profile document, the four schemas, the vector files and `codes.json`, and did not open the reference verifier, the generators or any Python test.

Its first run agreed on 201 of 207 vectors. All six disagreements traced to two gaps in the text, and both are now settled in [`docs/verifier-token-experimental.md`](https://trace.agentrust-io.com/docs/verifier-token-experimental/index.md) and applied to both implementations:

1. **The binding digest covers components exactly as signed.** The digest is SHA-256 over the JCS form of `{"method", "source", "target"}`, where `source` and `target` are the two component objects as they appear in the signed payload. The reference had been hashing its own normalized model, which fills an omitted optional member such as `resolver` with `null`. A verifier reading the wire cannot reproduce that, so a token omitting `resolver` verified under one implementation and failed under the other. The defect was in the reference. No defaults are added now: a member absent from the wire is absent from the preimage.
1. **A binding with an absent endpoint evaluates as `missing`.** The second verifier had rejected it with `binding_digest_mismatch`, because the digest cannot be checked without both components; the reference had reported `composite_inconsistent`. The rule now is that a required binding whose source or target is absent is `missing`, its digest is not evaluated, the token stays well formed, and its composite cannot be affirming.

After those fixes and the later additions, both implementations return the expected outcome on all 229. That is checked by `tests/test_independent_verifier.py` (the JavaScript verifier, all 229), `tests/test_conformance_corpus.py` (the reference, the 215) and `tests/test_verifier_token_profile.py` (the reference, the 14 originals).

Two limits on that claim. The 18 vectors added last (`COMP-AUTH-006` to `017`, `COMP-BIND-015` to `020`) cover features whose JavaScript side was written by the author of the matching reference change, so for those agreement shows the text is implementable, which is weaker than independence. And the README records 19 places where the document did not determine behavior and the second verifier chose a reading. Several of them are in §9.

## 8. Decisions that had to be settled

**The token is a new profile, not new fields on v0.2.** Adding `aud`, `exp` and an issuer to the v0.2 JSON signature would change what an existing v0.2 signature means. A new profile URI in a protected, critical header means a verifier routes before it parses, and a v0.2 verifier refuses the token as unsupported. The original 14 vectors include the reverse case: a v0.2 record presented as a verifier token is refused at the header check (`LEGACY-14`, `protected_headers`).

**The verifier key and the `cnf` key must differ.** Enforced, with its own code, `issuer_holder_same_key`. A token where they match describes a self-signed record under a new name.

**Expiry is the issuer's, bounded from every side.** `exp` may not pass the issuer entry's validity, the manifest's validity, or the earliest required component or binding freshness. The relying party can shorten the window. The gateway prototype checks identity, action, policy, status and expiry again immediately before the call is forwarded, and a gateway test admits an expired call only when that recheck is disabled.

**Status fails closed.** An unreachable status service is a rejection, never a pass.

**Evidence resolvers are optional.** Evidence references must carry profile, media type and digest; `resolver` is an untrusted hint and may be omitted. This is the one recorded divergence from the requirements as first written, which had a missing resolver rejected under `TR-COMP-EVID-001` (vector `COMP-EVID-003`). It is listed in `coverage.json` under `divergences` and reopened in §9.

## 9. Open questions for review

These are the choices a reviewer is most likely to change, and the vectors will move with them.

1. **COSE_Sign1 with a JCS JSON payload, or CWT claims.** The payload is JSON, like every existing TRACE record and schema, and the envelope is COSE, like Agent Manifest v0.2. A CWT or EAT encoding would reuse registered claim keys for `iss`, `sub`, `aud`, `exp`, `iat`, `jti` and `cnf`, and would drop the second canonicalization (CBOR outside, JCS inside). It would also mean new schemas and a regenerated corpus.
1. **The private critical `trace-profile` header.** A text label listed in `crit` works, and it makes routing happen before parsing. It is also unregistered. The alternatives are the registered COSE `typ` parameter (RFC 9596) with a profile-specific media type, or a registered label if the profile is ever standardized.
1. **Key ID derivation.** `kid` is SHA-256 of the raw 32-byte Ed25519 key. The profile document said only "derived from the trusted public key", and the second verifier recovered the rule from vector bytes. A standard thumbprint (RFC 7638 over the JWK, or RFC 9679 over a COSE_Key) would let existing key tooling compute the same `kid`; the cost is canonicalizing a key object instead of hashing 32 bytes.
1. **The names `same-instance-v1` and `same-evidence-v1`.** `same-instance-v1` checks instance consistency and a signed digest of the two component results. It authenticates the issuer's statement that two components belong to one workload; it does not independently prove that. The name may promise more than the method does. Both names also need a home: a registry in the spec, or profile-local names.
1. **Evidence resolver optionality.** `TR-COMP-EVID-001` as first written had `resolver` required; the experimental profile makes it an optional, untrusted hint, because no relying party here fetches evidence yet. If resolution is added, required may be the right answer again.
1. **The verification-context preimage.** The token carries `verification_context_hash`, and both verifiers compare it with a digest the relying party configures. The fixtures build it from `{purpose, policy, requirements, audience}`, but the document does not define that preimage, so two relying parties cannot yet compute the same hash for the same question.
1. **Check order.** When one input breaks two rules, the reported code depends on order. Both implementations agree on every vector, and the README lists two orderings no vector distinguishes. The spec either fixes an order or states that any one applicable code is conformant.
1. **Whether `prototype/verifier_token.py` comes with this proposal.** The reference implementation, `prototype/verifier_token.py`, is not yet in the repository. The proposal PR could carry it outside the installed SDK package, as it sits now, or carry only the schemas, vectors, generator and second verifier and leave the reference out. That is a maintainer decision, and the answer changes what `tests/test_conformance_corpus.py` can import.

## 10. What this does not do

- **It does not change v0.2.** No field, signature rule or verification behavior of a v0.2 record changes. The new token is carried only under its own profile URI.
- **It does not authorize.** An affirming token is an input to the relying party's policy.
- **It does not fetch or re-appraise evidence.** References are digest-bound and never resolved by the relying party. Evidence resolution is the largest open piece of work behind this profile.
- **It does not define a distributed replay store.** Challenge consumption and `jti` collision records run in the gateway prototype on SQLite for one host, or on one shared store process for several replicas. That store is not replicated, so replicas fail closed while it is down.
- **It does not settle the wire.** Section 9 is the list, and nothing here is registered.

To run the corpus against both implementations from a checkout, with the prototype dependencies and Node 24 installed:

```
$env:PYTHONPATH="$PWD;$PWD/src"
python -m pytest -q tests/test_independent_verifier.py tests/test_conformance_corpus.py tests/test_verifier_token_profile.py
```
