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

## Conflict of interest

Maintainers must disclose commercial interest in a proposal before participating in its review. Disclosed conflicts do not disqualify a Maintainer from voting but must be on record in the PR or issue.

## Vendor annexes

Vendor-co-authored platform-mapping annexes (§4.4 of the spec) are informative. They are reviewed by the vendor author and one TRACE Maintainer. Annexes do not require the full spec-change process.

## Foundation transition

TRACE is targeting co-hosting under CoSAI (technical workstream) and the Linux Foundation entity hosting MCP (spec, IP, trademark, conformance mark). On acceptance, governance transitions to a Technical Steering Committee (TSC) as defined in [CHARTER.md](CHARTER.md). Until then, this document is the governance authority.

## Amendments

Amendments to this document require a PR, 14-day comment period, and Project Lead approval.
