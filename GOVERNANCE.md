# Governance

## Roles

### Contributor

Anyone who submits a PR, files an issue, or participates in discussion. No formal appointment required. Must follow the [Code of Conduct](CODE_OF_CONDUCT.md) and sign commits with DCO.

### Reviewer

Trusted contributors with triage and review rights. Can approve PRs but cannot merge breaking spec changes without Project Lead approval.

**Advancement**: 3+ merged substantive PRs. Nominated by any Maintainer, confirmed by Project Lead.

### Maintainer

Full merge rights. Responsible for reviewing PRs in their area within 7 business days. See [MAINTAINERS.md](MAINTAINERS.md).

**Advancement**: Active Reviewer for 60+ days, 5+ merged PRs, demonstrated judgment on spec design questions. Nominated by any Maintainer, confirmed by Project Lead.

### Project Lead

Final decision authority on specification changes, conformance requirements, AAIF submission scope, and Maintainer appointments. Currently: Imran Siddique (OPAQUE Systems).

**Succession**: If the Project Lead is unavailable for 30+ days without notice, active Maintainers vote to appoint an interim lead.

## Decision-making

**Editorial changes** (typos, broken links, clarifications that do not affect normative requirements): Maintainer review + merge.

**Non-breaking spec changes** (new optional fields, new OPTIONAL conformance behavior, informative additions): open issue, 5-day comment period, Maintainer review, merge.

**Breaking spec changes** (backward-incompatible field changes, algorithm additions to the required set, conformance level redefinition): open issue, 14-day comment period, no unresolved objections from Maintainers, Project Lead sign-off.

**Wire format changes**: treated as breaking regardless of backward-compatibility argument.

**Voting**: If consensus cannot be reached, Maintainers vote. Simple majority for non-breaking changes; two-thirds for breaking changes. Project Lead has tie-breaking vote.

## Who may author normative text

Normative text is any statement using an RFC 2119 keyword in uppercase: what a conformant implementation MUST, SHOULD or MAY do. A normative change binds every implementation of TRACE, including implementations whose authors are not in the discussion.

**Normative spec changes require an organizational sponsor.** The sponsor is an organization that implements TRACE, or produces the attestation platform the change concerns, and is willing to be named as accountable for the requirement in the PR. In practice that has meant silicon and cloud attestation vendors, platform and framework implementers, and standards bodies carrying the work forward. Reviewers confirm the sponsorship, not the individual's competence.

The reason is maintenance cost, not merit. A MUST is a promise the project keeps for every future version. Evaluating whether it can be implemented, at what cost, across which platforms, needs an organization that will actually implement it and answer for it later. Individual authorship gives the project no way to make that assessment and no one to return to when the requirement proves wrong.

**Anyone may propose a normative change.** Open a Spec change proposal issue. Proposals are evaluated on the technical argument alone. If one is accepted without a sponsor, a Maintainer carries the normative PR and the proposer is credited in the CHANGELOG entry. This is a question of who signs the requirement, not whose idea it was.

**No sponsor is required for** editorial changes, examples, conformance tests, tooling, schema changes tracking an already-merged spec change, and informative additions such as crosswalks and mappings to external schemas. Informative text carries no RFC 2119 keywords and binds no implementation, so it is the right home for a mapping that is still settling. Most contributions are in this set.

A normative PR opened without a sponsor is not rejected on that basis. Reviewers will say so on the PR and either identify a sponsor or convert it to an informative change.

## Conflict of interest

Maintainers must disclose commercial interest in a proposal before participating in its review. Disclosed conflicts do not disqualify a Maintainer from voting but must be on record in the PR or issue.

## Vendor annexes

Vendor-co-authored platform-mapping annexes (§4.4 of the spec) are informative. They are reviewed by the vendor author and one TRACE Maintainer. Annexes do not require the full spec-change process.

## Foundation transition

TRACE is targeting co-hosting under CoSAI (technical workstream) and the Linux Foundation entity hosting MCP (spec, IP, trademark, conformance mark). On acceptance, governance transitions to a Technical Steering Committee (TSC) as defined in [CHARTER.md](CHARTER.md). Until then, this document is the governance authority.

## Amendments

Amendments to this document require a PR, 14-day comment period, and Project Lead approval.
