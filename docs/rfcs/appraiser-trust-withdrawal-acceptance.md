# Appraiser trust withdrawal: informative acceptance profile

Status: proposed review criteria for [#442](https://github.com/agentrust-io/trace-spec/issues/442), against commit `53e347caadda536b34773349c38eb70fedfec761`, 20 October 2026. This is not a protocol extension, implemented status service or conformance requirement. Every pair below is planned and unexecuted.

## Existing contract and bounded proposal

The [composite component appraisal RFC](composite-component-appraisal.md) configures appraiser trust by authority and protected `kid`, accepted types/profiles and the half-open interval `[valid_from, valid_until)`. Missing or out-of-interval trust yields an unverifiable appraisal rather than token rejection. Encoding, signature and carried-component mismatch checks retain their separate meanings.

The first proposed slice concerns explicitly configured leaf appraisers. Transitive chains remain deferred until a concrete use case and maintainer decision justify them. A valid appraiser signature authenticates the verdict; it does not establish the appraiser's present eligibility. Withdrawal changes relying-party eligibility, not the signed verdict or historical evidence bytes.

A candidate status profile would bind authenticated status to the exact authority, key material and grant identity, with an effective revocation instant, freshness interval and rollback defense. In the existing RFC, `kid` is SHA-256 of the raw Ed25519 public key: changing that key changes its valid identifier. A status cache still needs authority and grant scope, rather than an identifier alone. Status authority comes from independent configuration, not URLs or keys carried by the token being appraised.

## Time, caching and unavailable evidence

Use an explicit evaluation instant. Current admission and retrospective assessment are separate questions. A current status response alone cannot prove eligibility at a past instant; historical assessment needs retained authenticated status history and an explicit policy for later compromise information.

Cache eligibility no longer than the applicable grant, evidence and status validity bounds, including declared clock tolerance. A cached positive response entails a revocation-detection delay. Immediate withdrawal cannot be claimed from a polling interval or TTL; stronger delivery/acknowledgment guarantees would need a separate design. Persisted rollback protection needs its own restart and replica assumptions.

Keep authenticated revocation distinct from unknown subject, expired status, unreachable service and invalid status signature. An unreachable service does not silently restore trust until `valid_until`. These are proposed diagnostic distinctions, not new wire codes or a decision about the composite result vocabulary.

## Planned acceptance pairs

| ID | Valid control | Perturbation and expected observation |
| --- | --- | --- |
| TW-01 | Configured leaf, exact component/profile and fresh authenticated positive status qualify. | At or after the effective withdrawal instant, supply authenticated withdrawal directly, bypassing positive caches; the same appraisal no longer qualifies and signed verdict bytes stay unchanged. Cache propagation is a separate bound to test. |
| TW-02 | Status covers the configured key and grant. | Rotate the key and its digest-derived `kid`, or change grant scope; old positive status cannot qualify the replacement. A mismatched key/`kid` remains invalid under the existing identity rule. |
| TW-03 | Independently configured status signer authenticates the response. | Substitute token-supplied signer or URL; it supplies no trust authority. |
| TW-04 | Positive status is within its declared validity at the evaluation instant. | Evaluate at expiry or beyond clock bounds; do not treat it as fresh. |
| TW-05 | Newly observed status advances retained status state. | Replay an older positive after retaining authenticated withdrawal, including after restart; detect rollback under the declared storage model. This does not detect a withdrawal never observed. |
| TW-06 | Fresh authenticated status is available. | Disconnect retrieval, return unknown subject, or corrupt the signature separately; retain distinct unavailable/invalid diagnostics without fallback eligibility. |
| TW-07 | Evaluation falls inside the grant interval. | Evaluate exactly at `valid_until`; status cannot extend the grant. |
| TW-08 | Retained authenticated history supports the selected past instant. | Only a current response exists; do not invent historical eligibility. |
| TW-09 | Eligible required component supports the existing composite calculation. | Withdraw its appraiser; recompute using the maintainer-selected unverifiable/result rule rather than accepting the former composite. |
| TW-10 | An eligible optional component and required controls preserve existing RFC behavior. | Withdraw only the optional component; do not silently invent a new rule that every optional absence invalidates the composite. |

For each future execution, retain exact source/dependency revisions, signed fixtures, independent trust configuration, evaluation time, status history, cache/storage model and observed outcomes. Remove the relevant guard while preserving fixture parsing and valid controls; the behavioral assertion should then fail. Passing this plan has not been claimed.

## Decisions before implementation

Maintainers still need to choose leaf-only scope; status authority and transport; key/grant identity; status lifetime and maximum withdrawal delay; clock and rollback assumptions; historical compromise semantics; and how unavailable eligibility maps into component/composite results. Schema or normative changes follow the repository's sponsorship and comment-period process. This document registers no new field, result code or trust delegation.

## References and limits

1. [Composite component appraisal RFC at the reviewed commit](https://github.com/agentrust-io/trace-spec/blob/53e347caadda536b34773349c38eb70fedfec761/docs/rfcs/composite-component-appraisal.md): authoritative baseline for this comparison; not an already approved revocation mechanism.
2. [RFC 9334, Remote ATtestation procedureS Architecture, especially section 10](https://www.rfc-editor.org/rfc/rfc9334.html#section-10): role separation and freshness reasoning. It does not specify TRACE appraiser withdrawal.
3. [RFC 6960, sections 2.2, 2.4 and 4.2.2](https://www.rfc-editor.org/rfc/rfc6960.html#section-2.2): prior art separating authenticated status, effective time and response freshness. This is a design analogy; neither OCSP transport, certificate chains nor its `good` semantics are adopted as TRACE rules.
4. [Existing #442 proposal](https://github.com/agentrust-io/trace-spec/issues/442#issuecomment-6271717474): discussion context only. Maintainer acceptance and implementation remain open.
