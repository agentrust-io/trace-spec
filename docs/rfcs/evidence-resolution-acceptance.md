# Evidence resolution and re-appraisal: proposed acceptance profile

Status: informative design proposal for [#441](https://github.com/agentrust-io/trace-spec/issues/441).
This document binds no implementation and changes no wire fields or outcomes.
It supplements the [composite appraisal proposal](composite-component-appraisal.md).
Maintainers still select the profile and local comparison representation before code.

## Claim and trust boundary

The first slice resolves one saved Azure SNP execution packet from
operator-configured offline storage and independently re-appraises its execution
and collateral under declared inputs. It establishes what the second appraisal
finds about those bytes under that context. It cannot establish what the original
appraiser read, current platform freshness, or protected model execution.

Delegated appraisal remains a legitimate alternative trust model. RATS [R1]
does not require every relying party to parse raw evidence. This opt-in profile
is for consumers that explicitly require their own re-appraisal.

The resolver has no network authority from a signed hint. Its operator controls
storage, size limits, access and retention. Missing, denied, deleted, oversized
or unavailable evidence leaves the corresponding appraisal unestablished.
A digest mismatch is a binding failure, not proof that the asserted content is false.

## Proposed processing obligations

1. Retain the received bytes in the declared private store. Parse unambiguously,
   including duplicate-member refusal, before canonicalization.
2. Check the reference against the existing `canonical_digest(packet)` contract
   in `prototype/verifier_token.py`: RFC 8785 canonical JSON and the named digest.
   Whitespace differences alone do not change that object digest. Arbitrary
   downloaded text hashes are not interchangeable with it [R2].
3. Independently supply holder/challenge context, execution policy, accepted
   roots, platform collateral, TCB floors and evaluation instant.
4. Reuse the authenticated execution path before collateral appraisal.
   `prototype/snp_collateral.py::appraise_collateral` explicitly assumes an
   already-authenticated packet; calling it alone is insufficient.
5. Retain execution and collateral results separately. Compare eligible local
   results with the original signed components without rewriting those components.
   Shared evidence identity does not imply that both appraisals occurred.
6. Preserve original observation/appraisal times. Fetching or serializing the
   packet today does not create new freshness.

The existing historical packet can legitimately fall below the selected vendor
floor. Such a result is an important control, not a reason to lower a real
acceptance floor. Any synthetic affirmative fixture has an explicit test policy
and is never described as production admission evidence.

## Proposed acceptance matrix

These are unexecuted cases. Each negative has a valid twin that reaches the
specific boundary, including genuine signatures for semantic-binding cases.

| ID | Controlled pair | Required distinction |
| --- | --- | --- |
| ER01 | Same object, changed whitespace / changed member | Same canonical digest / digest mismatch |
| ER02 | Available packet / missing, denied or deleted packet | Appraisal attempted / unavailable evidence |
| ER03 | Authenticated expected packet / wrong AK or root | Eligible appraisal / authentication failure |
| ER04 | Correct holder and challenge / validly signed wrong context | Correct binding / no applicable appraisal |
| ER05 | Both selected appraisals / execution only | Two reported results / collateral unappraised |
| ER06 | Explicit synthetic accepted test policy / genuine below-floor packet | Scoped affirmative control / contraindicated platform |
| ER07 | Recorded historical instant / same bytes fetched later | Historical result / no renewed observation freshness |
| ER08 | Agreed local result / eligible contradictory local result | Agreement / explicit comparison difference |
| ER09 | Unambiguous JSON / duplicate member or exceeded size limit | Parseable evidence / refused resolution |

## Corpus, second checker and evaluation plan

A future manifest records: case ID and version; source revision/file; exact
received-byte digest and canonical-object digest as distinct named values;
evidence class; trusted input files and digests; original observation and
evaluation instants; expected named results; positive twin; targeted mutation;
reproduction command; and public/private disposition. Real device identifiers
and protected payloads remain private. Predictable-content hashes are not
automatically safe to publish. Omitted raw material makes public reproduction
incomplete and is declared as such.

The bounded second checker validates resolution identity, invocation coverage
and result comparison without importing the reference adapter's decision logic.
Shared cryptographic libraries and specifications are disclosed dependencies;
this is not independent platform measurement. A separate qualified reader
defines expected cases before seeing checker outputs.

Compare signature/digest-only checking with the existing full appraisal path
and a strong stateful baseline given identical evidence and context. For change
handling, compare selective invalidation with full reassessment. Report false
establishment, legitimate controls retained, unavailable results and cost by
mechanism. Keep held-out mechanisms separate from template variants [R5].

Planned mutations disable digest, authentication, required-profile invocation
and result-comparison guards separately. The matching negative then fails a
behavioral assertion; valid twins still pass. Import errors and reject-all
behavior do not count as adequate detection. No benchmark result is claimed.

## Adjacent decisions, not bundled implementation

- [#442](https://github.com/agentrust-io/trace-spec/issues/442): first decide
  leaf-only appraiser status, authenticated key/grant identity, cache freshness,
  effective revocation time and unavailable outcomes. Retain historical and
  current-admission policies separately. A cached good response can entail a
  bounded observation delay; immediate revocation does not follow [R3].
- [#440](https://github.com/agentrust-io/trace-spec/issues/440): separately select
  authenticated admission-store transport, consistency and recovery assumptions.
  Partition, concurrent consume, restart, promotion, rollback and clock-boundary
  cases need history-based tests. A linearizable admission object does not make
  an unrelated external effect exactly once [R4].

These dependencies cannot be marked complete by accepting this informative text.

## Literature and its application

- R1: [RFC 9334, RATS Architecture (2023), sections 8 and 10](https://www.rfc-editor.org/rfc/rfc9334.html).
  Roles, appraisal policies and freshness inform the trust boundary.
- R2: [RFC 8785, JSON Canonicalization Scheme (2020)](https://www.rfc-editor.org/rfc/rfc8785.html).
  Defines the canonicalization antecedent; existing repository code determines
  this packet's preimage contract.
- R3: [Samuel et al., Survivable Key Compromise, CCS 2010](https://theupdateframework.io/papers/survivable-key-compromise-ccs2010.pdf).
  Timeliness and rollback are distinct trust-maintenance problems; not a TRACE
  appraiser-status implementation or mandated delegation scheme.
- R4: [Herlihy and Wing, Linearizability, 1990](https://cs.brown.edu/people/mph/HerlihyW90/p463-herlihy.pdf).
  Object-history reasoning motivates admission tests, not external-effect atomicity.
- R5: [Zabolotnii, Runtime Assurance Contracts, v2, 16 October 2026](https://arxiv.org/html/2609.39717v2).
  Detector omissions and strong stateful comparisons constrain evaluation claims.

These sources are prior art, not proof of this proposal's correctness or novelty.
No standardization, hardware run, independent acceptance or issue closure is claimed.
