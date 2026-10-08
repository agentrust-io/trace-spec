# Verifying a record after the freshness window

A TRACE verifier refuses a record older than its maximum age (24 hours by default, [section 3.2.2](https://trace.agentrust-io.com/spec/trace-v0.2/#322-mandatory-signature-and-freshness-binding)), and the issue time it measures against is `iat`, which the issuer writes. Both are right for an admission decision. Neither helps someone who has to answer a question about a run long afterwards: an auditor, a party to a dispute, an incident reviewer. Run today, a conformant verifier refuses the record, and nothing in the record bounds when it existed except the issuer's own claim.

This page describes a separate, historical check for that case: replay the freshness comparison at a time T taken from a registry anchor, evidence that the exact anchored bytes already existed by T. It is for verifier authors and for whoever has to write the conclusion.

> **Non-normative.** This page is informative. It changes no schema field, wire format, required claim or conformance requirement, and carries no uppercase RFC 2119 keyword. [Section 3.2.2](https://trace.agentrust-io.com/spec/trace-v0.2/#322-mandatory-signature-and-freshness-binding), [Registry Anchor Format v1](https://trace.agentrust-io.com/spec/registry-anchor-v1/index.md) and the [verification protocol](https://trace.agentrust-io.com/docs/verification/index.md) carry the normative rules; this page builds on them.

**What this is not.** Section 3.2.2 measures freshness against the verifier's current time. A replay at T is not a conformant section 3.2.2 verification at the present time, and it is reported as a separate, historical check with T stated.

## What is missing, and whose job it is

A late check needs a time bound that does not rest on `iat`, the one time claim the record carries. What an anchor adds is an upper bound: evidence that the exact anchored bytes existed no later than some time T.

That is the property the `transparency` member asserts. [Registry Anchor Format v1 section 5.2](https://trace.agentrust-io.com/spec/registry-anchor-v1/#52-what-verification-proves-and-what-it-does-not) states it: a successful inclusion check proves the exact signed claim bytes were part of a batch whose root is committed at the entry's timestamp, which is "when the bytes existed and that they have not changed since". This page uses that bound and asks nothing new of it. For an enveloping-signature profile (JWS, COSE), the anchored claim object carries no `signature` member, so the bound covers the claim body; say so when the statement relies on it.

## The procedure

1. **Hold the inputs.** The exact signed record; the trusted key or its thumbprint; the inclusion proof (`leaf_index` and `audit_path`, which the producer gives the claim holder under [Registry Anchor Format v1 section 5](https://trace.agentrust-io.com/spec/registry-anchor-v1/#5-inclusion-proof) and which are not in the registry entry); and the freshness bounds the deployment applies (maximum age and future clock skew). Keep them as [Retaining one verification call](https://trace.agentrust-io.com/docs/verification-outcome-statements/#retaining-one-verification-call) describes, with an explicit value where a check is disabled.
1. **Establish the bound T.** Retrieve the registry entry the record's `transparency` value names and check inclusion with the algorithm in [Registry Anchor Format v1 section 5.1](https://trace.agentrust-io.com/spec/registry-anchor-v1/#51-verification-algorithm), without contacting the issuer ([section 6](https://trace.agentrust-io.com/spec/registry-anchor-v1/#6-relationship-to-the-transparency-claim)). T is the entry's `ts`, subject to the caveat under [The statement it supports](#the-statement-it-supports). The leaf is hashed over the sorted-key bytes of [section 1](https://trace.agentrust-io.com/spec/registry-anchor-v1/#1-canonical-claim-bytes), not the RFC 8785 bytes the signature covers; [section 0](https://trace.agentrust-io.com/spec/registry-anchor-v1/#0-the-canonicalization-trap-before-anything-else) explains why reusing the signing canonicalizer here fails without a useful diagnostic.
1. **Replay the freshness comparison at T.** Run the verification with the verification time set to T and the same freshness bounds, as in the pattern under [Retaining one verification call](https://trace.agentrust-io.com/docs/verification-outcome-statements/#retaining-one-verification-call). Only the freshness comparison moves to T. Signature verification is time-independent, while evidence resolution, trust inputs and the accepted profile set are today's; the report says so.
1. **Record what was checked.** Keep the inclusion proof, the registry entry, T and where it came from, the bounds, and the complete result together, as the outcome statements page asks for a single call.

**A postdated record fails step 3 on its own terms.** If `iat` is later than T by more than the allowed future skew, the record claims an issue time after the bytes are proven to have existed. Replay at T refuses it under the same section 3.2.2 comparison that refuses any postdated record, and the anchor lends the claimed time no support.

## The statement it supports

When step 3 succeeds, the strongest sentence is: *the signature verifies under the trusted key; the anchored bytes existed no later than T; and the issuer's `iat` is no later than T plus the skew and no earlier than T minus the maximum age, where T comes from an inclusion proof checked without contacting the issuer.*

What has to stay out of the same sentence:

- **The record's claims.** Anchoring proves when bytes existed, not that what they say is true ([Registry Anchor Format v1 section 5.2](https://trace.agentrust-io.com/spec/registry-anchor-v1/#52-what-verification-proves-and-what-it-does-not)). Every non-claim on the [outcome statements](https://trace.agentrust-io.com/docs/verification-outcome-statements/#interpretation-matrix) page still applies.
- **The exact signing time.** The actual signing time is known only to be no later than T. `iat` remains the issuer's claim.
- **Key revocation.** [Section 3.2.3](https://trace.agentrust-io.com/spec/trace-v0.2/#323-revocation-of-record-signing-keys) places the boundary by log entry order, not by time: the question is whether the key was trusted when the record was made, answered by the current revocation statement for the key compared against the record's entry, and reported in section 3.2.3's form. Anchor Format v1 entries carry `batch_id` and `ts`, not SCITT entry IDs, so say which ordering the comparison used, or that no revocation check was performed.
- **Independence of T.** The entry's `ts` is written by whoever produced and submitted the batch ([section 4](https://trace.agentrust-io.com/spec/registry-anchor-v1/#4-registry-entry), `producer`), which can be the issuer. Append-only checkability stops an existing entry being rewritten; it does not stop a new entry being appended with an early `ts`. The bound that does not depend on the producer is the earliest time an independent party observed the entry, such as a mirror's copy or an auditor's checkpoint. State which one T is.

## When the bound is missing or does not check

- **No `transparency` value.** Below Level 2 the member is optional ([Registry Anchor Format v1 section 6](https://trace.agentrust-io.com/spec/registry-anchor-v1/#6-relationship-to-the-transparency-claim)). Without it there is no T, and the honest report is that freshness at any past time could not be established, not that the record was stale.
- **The inclusion check fails.** Any failure means the claim is not proven included ([section 5.1](https://trace.agentrust-io.com/spec/registry-anchor-v1/#51-verification-algorithm)), and there is no partial T. Report the failed check; do not fall back to `iat`.
- **Replay fails on age only.** The anchor came more than the maximum age after `iat`. That is a finding about anchoring delay, not evidence against the record, and it is reported as such.
- **The entry cannot be retrieved.** That is a fact about the registry at verification time, not a finding against the record. At Level 2, where an appraiser has to be able to retrieve the entry ([section 6](https://trace.agentrust-io.com/spec/registry-anchor-v1/#6-relationship-to-the-transparency-claim)), the appraisal cannot be completed. How long a reference has to stay resolvable is open: [section 3.1.2](https://trace.agentrust-io.com/spec/trace-v0.2/#312-references-facts-this-record-points-at) names the gap for `references` and `transparency` together, and [trace-tests#92](https://github.com/agentrust-io/trace-tests/issues/92) coordinates how `transparency` resolution is settled.

## More than one bound

A deployment may hold a second, independent bound, such as a public timestamp over the record's digest or over the registry's history. The same procedure applies with T taken from that evidence, provided it binds the same bytes and a reader can check it without the service's cooperation. Replay at each bound and report each, naming its source. Do not choose a bound after seeing which one passes.

## Related

- [Verification outcome statements](https://trace.agentrust-io.com/docs/verification-outcome-statements/index.md), for retaining one call and for the non-claims each outcome carries.
- [Registry Anchor Format v1](https://trace.agentrust-io.com/spec/registry-anchor-v1/index.md), for the inclusion proof and what it establishes.
- [SCITT-anchored records](https://trace.agentrust-io.com/docs/verification/#scitt-anchored-records) and [anchoring to the registry](https://trace.agentrust-io.com/docs/tutorials/anchoring-to-the-registry/index.md), for the reference sequence.
- [agentrust-io Discussion #47](https://github.com/orgs/agentrust-io/discussions/47), where this page was proposed.
