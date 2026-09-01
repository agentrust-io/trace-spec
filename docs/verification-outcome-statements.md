---
description: How a relying party or auditor turns a TRACE verifier outcome into a bounded statement - what each outcome supports, what it never claims, and what evidence to retain.
---

# Verification outcome statements

> **Non-normative.** This page is informative. It changes no schema field, wire format, required claim or conformance requirement, and carries no uppercase RFC 2119 keyword. [Section 3.3 of the specification](../spec/trace-v0.2.md) and the [verification protocol](verification.md) carry the normative rules; where those documents already speak, this page repeats their wording rather than adding to it.

## Purpose

A TRACE verifier produces an outcome: an `appraisal.status`, a recorded provenance depth, a set of checks it ran and did not run. The people who consume that outcome are often not verifiers. Auditors, assessors, customers and regulators read verifier output and have to turn it into a written conclusion. The failure mode this page exists to prevent is assurance overclaim - a conclusion written slightly stronger than the evidence behind it, so that a valid signature quietly becomes "the agent complied", or a signed acceptance receipt becomes "the action succeeded".

Two pages already tell a reader what not to conclude, each cut a different way: [Trust Levels](trust-levels.md) carries a *What it does not prove* line under each level, and the [OWASP Agentic Top 10 crosswalk](crosswalks/owasp-agentic-top-10.md) carries a *Limitations / out of scope* column and a closing *What TRACE does not do* list. This page is the third view of the same discipline, indexed by verifier outcome rather than by trust level or risk category. Where wording overlaps, those two pages carry the meaning and this page follows them.

## Non-normative status

Nothing on this page changes what a conformant implementation does. A bounded statement below is permitted only because some sentence in [`spec/trace-v0.2.md`](../spec/trace-v0.2.md), [`docs/verification.md`](verification.md) or [`LIMITATIONS.md`](../LIMITATIONS.md) already makes it true; each matrix row names that anchor. A statement that cannot be anchored to existing text belongs under [Open questions](#open-questions), not in the matrix.

Machine-checkable verifier-output/statement pairs are out of scope for this page; they belong wherever the vector sets whose outcomes they consume live.

## Interpretation matrix

The rows are representative, not exhaustive. Each row reads: the outcome a verifier records, the strongest statement the evidence supports, the claim that has to stay out of the same sentence, the evidence worth retaining alongside the record, and a sensible follow-up.

| Verification outcome | Supported bounded statement | Required non-claim | Evidence to retain | Follow-up |
|---|---|---|---|---|
| **Verified at the required floor.** Signature binding verified, record fresh, `appraisal.status` is `affirming` (or `warning`), and `appraisal.provenance_depth_verified` meets the deployment profile floor. | This record was not altered after issuance, and the checks the verifier ran passed at the recorded depth, under the appraisal policy named in `appraisal.policy_ref`. ([§3.2.2](../spec/trace-v0.2.md), [What verification proves](verification.md#what-verification-proves)) | Not current trust in the signing key unless revocation was actually consulted ([LIMITATIONS](../LIMITATIONS.md): pure offline verification cannot prove non-revocation). Not that the bound policy achieves its intended outcome ([LIMITATIONS](../LIMITATIONS.md): policy correctness is a separate control). Not soundness of the model's behavior ([§2.4](../spec/trace-v0.2.md)). Not success of any physical or business outcome ([§3.3.3](../spec/trace-v0.2.md)). Not a general trust score for the subject. | The record itself; the trusted-key thumbprint used; the freshness bounds applied; if revocation was checked, the bundle identity and `valid_until` - reported as "verified against revocation bundle valid at T" ([§3.2.3](../spec/trace-v0.2.md)); the complete `appraisal`. | Re-verify before material reliance on an aging record; consult current revocation status at decision time; keep the `policy_ref` target resolvable for whatever retention the published statement promises. |
| **Honestly downgraded, floor still met.** Evidence the claimed depth needs did not resolve; the verifier stopped lower and recorded the achieved depth in `appraisal.provenance_depth_verified`; nothing contradicted; the achieved depth still meets the configured floor. | Verification reached `builder` (for example); the deeper claim was left unverified because named evidence did not resolve; the unresolved evidence is identified. ([§3.3.1](../spec/trace-v0.2.md), [downgrade column of the depth table](verification.md#verifying-build-provenance-depth)) | The downgrade is not a defect in the record: "a record is not defective because someone else's transparency log is unreachable" ([verification.md](verification.md#verifying-build-provenance-depth)). Equally, nothing is assured at the unexecuted depth - unverified is not silently true ([what each stopping point leaves unknown](build-provenance-depth.md)). | `appraisal.provenance_depth_verified`; the evidence locations attempted and why each did not resolve; the configured floor; the final `appraisal`. | Retry resolution or obtain the evidence out-of-band; where the gap matters to the reader, state it explicitly instead of letting the affirming status carry the weight. |
| **Resolved and contradicted.** Named evidence resolves and refutes the record - attestation subject mismatch, dependency publisher outside the trusted set, digest mismatch. The appraisal fails and is not downgraded to escape the contradiction; `appraisal.status` is `contraindicated`. | The named artifact resolves and contradicts this record's claim at the named depth; the appraisal failed, and the record is treated as untrusted. ([§3.3.1](../spec/trace-v0.2.md), [Step 5 status meanings](verification.md#step-5--appraise-the-claims)) | The statement covers the specific contradiction observed and nothing else: it does not extend to other fields or axes, and appraisal output does not identify which adversary class from [§2.2](../spec/trace-v0.2.md) caused the contradiction. | The contradicting artifacts themselves (attestation bytes, publisher attestations, issuer identities outside the trusted set), the comparisons performed, the final `appraisal`. | Treat as incident input; contact the issuer or operator; corrected records need re-issue, not re-reading. |
| **Unresolvable below the floor.** Achieved `appraisal.provenance_depth_verified` sits below the deployment profile floor, so `appraisal.status` is `contraindicated` by the floor rule. Nothing resolved-and-contradicted. | Verification reached `surface`; this deployment's floor is `transitive`; the record is refused by the floor, with no contradicting evidence found. ([floor rule in §3.3.1](../spec/trace-v0.2.md)) | Unverifiable is not incriminating: "the strictness lives in the floor, not in a finding against the record" ([build provenance depth](build-provenance-depth.md#choosing-a-depth)). Do not report this as though evidence had contradicted the record - the depth vectors encode the two outcomes separately ([verification.md](verification.md#verifying-build-provenance-depth)), and reporting should keep them apart. | The attempted evidence locations and errors; the floor configuration; `appraisal.provenance_depth_verified`; `appraisal.status`. | Obtain the missing evidence, or let the rejection stand; record which of the two happened. |
| `policy.enforcement_mode` is `"declared"`: the policy is named and bound into the signed record, and nothing evaluated it. ([§4.3](../spec/trace-v0.2.md)) | The policy this deployment states it operated under is bound into the record by `policy.bundle_hash`; the record asserts no evaluation and no enforcement of any rule. | Reading `"declared"` as evidence that any rule was checked contradicts the field's own definition ([§4.3](../spec/trace-v0.2.md)): `enforce`, `advisory` and `silent` all assert some evaluation, `declared` asserts none, and a verifier appraising for enforcement treats it like an absent enforcement claim. | The record itself - the binding is signature-covered; the external report carries its own note that no evaluation claim is present. | If the assurance need requires evaluated policy, request records produced under `enforce` or `silent`, or evaluate the bound policy out-of-band; policy review remains a separate control ([LIMITATIONS](../LIMITATIONS.md)). |

## Evidence statement guidance

**Fields already in the record** that a bounded statement can cite:

- `subject` - names the workload the statement is about (SPIFFE SVID or DID URI, [§3.1](../spec/trace-v0.2.md)).
- `appraisal` - `status`, `verifier`, `policy_ref`, `timestamp`, `provenance_depth_verified`: the outcome, who produced it, and at what depth.
- `references` - points at retained facts held elsewhere (`rel`, `id`, `resolver`, `retention`, `digest`, [§3.1.2](../spec/trace-v0.2.md)). A pointer is not evidence: a verifier does not treat a resolved reference as attested evidence, and `retention` states an undertaking rather than an enforced guarantee ([§3.1.2](../spec/trace-v0.2.md)).

**Reporting elements with no home in the v0.2 schema today**, which belong in the external evidence statement or report rather than the record:

- the requested verification floor;
- the checks actually executed, including attempts that produced no result;
- exceptions;
- explicit non-claims.

Moving these into the record would be a schema change, which is out of scope for this page. For phrasing, follow the pattern [§3.2.3](../spec/trace-v0.2.md) already sets for revocation: state what was checked against what, and say plainly when a check was not performed rather than leaving it implied.

## Open questions

- Rows describing approval-bearing receipts - approval preceding execution, applicable approver authority, scope covering the action taken - depend on profile work routed through [#191](https://github.com/agentrust-io/trace-spec/issues/191) and sit behind the [#116](https://github.com/agentrust-io/trace-spec/issues/116) version boundary. Until that lands, they remain open questions rather than settled guidance.
- Comparability of `transitive` across verifiers stays open until the coverage-URI follow-up named in [verification.md](verification.md#transitive-is-a-floor-on-effort-not-a-comparable-claim) settles. Until then, a `transitive` value supports an effort-floor statement only, not a claim that two verifiers covered identical dependency sets.
- Whether `appraisal.policy_ref` gains reproducibility guarantees (a digest binding for the referenced appraisal policy) is an unresolved design question tracked in [#190](https://github.com/agentrust-io/trace-spec/issues/190). Until then, a bounded statement cites the appraisal policy by reference, and second-verifier reproduction of an appraisal verdict is not guaranteed.

## Related

- [Verification protocol](verification.md) - the rules these outcomes come from.
- [Build provenance verification depth](build-provenance-depth.md) - what each stopping point leaves unknown.
- [Known limitations](../LIMITATIONS.md) - what a TRACE claim does not prevent, at record level.
- [trace-spec#66](https://github.com/agentrust-io/trace-spec/issues/66) - the discussion this page grew out of.
