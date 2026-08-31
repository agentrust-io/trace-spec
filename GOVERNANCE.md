# Governance

## General Project Policies

TRACE Specification has been established as TRACE Specification a Series of LF Projects, LLC. Policies applicable to TRACE Specification and participants in the TRACE Specification project, including guidelines on the usage of trademarks, are located at https://www.lfprojects.org/policies/. Governance changes approved as per the provisions of this governance document must also be approved by LF Projects, LLC.

TRACE Specification participants acknowledge that the copyright in all new contributions will be retained by the copyright holder as independent works of authorship and that no contributor or copyright holder will be required to assign copyrights to the project.

All specification contributions to the Project must be made under the [Community Specification License 1.0](Governance/COMMUNITY-SPECIFICATION-LICENSE.md) and the [Community Specification Contributor License Agreement](Governance/CLA.md).

All code contributions to the Project must be made under the Apache License, Version 2.0, available at https://www.apache.org/licenses/LICENSE-2.0 (the "Source Code License"). Outbound code will be made available under the Source Code License. The Maintainers may approve an alternative open source license for code on an exception basis.

All documentation (excluding specifications) will be made available under the Creative Commons Attribution 4.0 International license, available at: https://creativecommons.org/licenses/by/4.0.

Specification text published before this policy took effect stays available under the license under which it was published. See [LICENSE](LICENSE) and the [license map](Governance/License.md).

## Roles

### Contributor

Anyone who submits a PR, files an issue, or participates in discussion on the repository is a Contributor bound by the license terms. No formal appointment is required. Contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md) and sign commits with DCO.

### Reviewer

Trusted Contributors with triage and review rights. Reviewers can approve PRs but cannot merge breaking spec changes without Project Lead approval.

**Advancement**: 3+ merged substantive PRs. Nominated by any Maintainer, confirmed by the Project Lead.

### Maintainer

Full merge rights. Responsible for reviewing PRs in their area within 7 business days. See [MAINTAINERS.md](MAINTAINERS.md).

**Advancement**: Active Reviewer for 60+ days, 5+ merged PRs, demonstrated judgment on spec design questions. Nominated by any Maintainer, confirmed by the Project Lead.

### Project Lead

The Project Lead is responsible for determining Consensus among Contributors regarding specification changes, conformance requirements, advancement of the project or its deliverables to other organizations, role appointments, and other project decisions. If Consensus can't be determined, the Project Lead may call for a majority vote of the Maintainers. The current Project Lead is listed in [MAINTAINERS.md](MAINTAINERS.md).

**Succession**: Active Maintainers vote to appoint a new Project Lead if the then-current Project Lead steps down or is unavailable for more than 30 days without notifying the Maintainers.

## Decision Making

### Consensus-based decision making

The Project makes decisions through a consensus process ("Approval" or "Approved"). While the agreement of all Contributors is preferred, it is not required for consensus. Rather, the Project Lead will determine consensus based on their good faith consideration of a number of factors, including the dominant view of the Project Contributors and nature of support and objections. The Project Lead will document evidence of consensus in accordance with these requirements.

### Appeal process

Decisions may be appealed via a pull request or an issue, and that appeal will be considered by the Project Lead in good faith, who will respond in writing within a reasonable time.

## Ways of Working

Inspired by [ANSI's Essential Requirements for Due Process](https://share.ansi.org/Shared%20Documents/Standards%20Activities/American%20National%20Standards/Procedures,%20Guides,%20and%20Forms/2020_ANSI_Essential_Requirements.pdf), the Project adheres to consensus-based due-process requirements for approving, revising, reaffirming, and withdrawing TRACE specifications. Any person or organization with a direct and material interest has the right to express a position and its basis, have that position considered, and appeal a decision.

### Openness

Participation is open to all persons and organizations directly and materially affected by the work. There are no undue financial barriers to participation. Voting or decision-making eligibility is not conditional on membership in another organization or unreasonably restricted by technical qualifications.

### Lack of dominance

The specification-development process must not be dominated by any single interest category, individual, or organization to the exclusion of fair and equitable consideration of other viewpoints.

### Balance

The Project seeks participation from diverse interest categories, including implementers, technology providers, users, security and privacy experts, and other materially affected parties.

### Coordination and harmonization

The Project makes good-faith efforts to identify and resolve conflicts between TRACE deliverables and existing industry standards.

### Consideration of views and objections

The Project promptly considers written views and objections from all Contributors. The Project Lead documents the evidence used to determine Consensus, including material objections and their disposition.

### Written procedures

This governance document and other materials describing the Community Specification development process are publicly available to any interested person.

### Review periods by change class

Review periods are minimums. The Project takes as much time as it needs to reach a consensus decision, and a period does not expire a discussion that is still live.

**Editorial changes** (typos, broken links, clarifications that do not affect normative requirements): Maintainer review + merge.

**Non-breaking spec changes** (new optional fields, new OPTIONAL conformance behavior, informative additions): open issue, a minimum 5 business days for comment, Maintainer review, merge.

**Breaking spec changes** (backward-incompatible field changes, algorithm additions to the required set, conformance level redefinition): open issue, a minimum 30-day comment period, no unresolved objections from Maintainers, Project Lead sign-off. See [Backward compatibility](#backward-compatibility).

**Wire format changes**: treated as breaking regardless of backward-compatibility argument.

**Voting**: If Consensus cannot be determined, the Project Lead may call for a majority vote of the Maintainers. Two-thirds of Maintainers are required for breaking changes. The Project Lead has the tie-breaking vote.

## Specification Development Process

### Pre-Draft

Any Contributor may submit a proposed initial draft document as a candidate Draft Specification of the Project. The Project Lead will designate each submission as a "Pre-Draft" document.

### Draft

Each Pre-Draft document must first be Approved to become a "Draft Specification". Once the Project approves a document as a Draft Specification, the Draft Specification becomes the basis for all going forward work on that specification.

A Draft Specification is not stable. Normative requirements, wire formats, and conformance criteria may change, including incompatibly, while a specification is in Draft. Implementers should expect change and should not treat a Draft as a long-lived interoperability target. Every Draft carries this status in its header.

### Final

Once the Project believes it has achieved the objectives for its specification as described in the [Scope](Governance/Scope.md), it will Approve that Draft Specification and progress it to "Final" status. A Final specification is an "Approved Specification" for purposes of the Community Specification License 1.0.

A Final specification is stable. Its normative content does not change except through errata, which are corrections that do not alter what a conformant implementation must do. New requirements are made in a new version, not in the published one. Conformance claims are made against a Final version, and the conformance suite tracks Final versions.

### Deprecated

A Final specification is marked "Deprecated" when it has been superseded and the Project no longer intends to maintain it. A Deprecated version stays published and readable. It receives no further errata, and the Project states in the deprecation notice how long conformance claims against that version continue to be recognized.

### Publication and submission

Upon designation of a Draft Specification as Final, the Project Lead will publish it in a manner agreed upon by the Project Contributors. Publication in a publicly accessible manner must include the terms under which the specification is being made available.

No Draft Specification or Final specification may be submitted to another standards development organization without Approval of the Project. Upon reaching Approval, the Project Lead will coordinate the submission. Project Contributors that developed that specification agree to grant the copyright rights necessary to make those submissions.

## Backward compatibility

TRACE does not break backward compatibility in a Final specification. Implementers build against published requirements, and a requirement that changes underneath them costs them work they did not choose. Additive change is the default: new capability arrives as an optional field, an optional conformance behavior, or a new conformance level, so that an existing conformant implementation stays conformant.

A breaking change is a last resort. The Project will consider one only where the existing requirement cannot be left standing:

- a cryptographic algorithm or construction is broken, or is withdrawn by the body that issued it
- a requirement creates a security or privacy defect that cannot be corrected compatibly
- an identifier or wire construct is invalid under the external standard it claims to conform to
- a requirement is not implementable on a platform within the specification's stated scope

A breaking change carries a minimum 30-day comment period, an explicit backward-compatibility statement naming what breaks and what implementers must do, and Project Lead sign-off. Where the change can be staged, the affected element is marked Deprecated in one version before it is removed in a later one.

Draft specifications are exempt: see [Draft](#draft).

## Conflict of interest

Maintainers must disclose commercial interest in a proposal before participating in its review. Disclosed conflicts do not disqualify a Maintainer from voting but must be on record in the PR or issue.

## Sponsorship

Sponsors are recognized in [SPONSORS.md](SPONSORS.md). Sponsorship and participant affiliations are informational and do not confer specification authority, additional decision rights, preferential conformance treatment, or endorsement of a sponsor's implementation. Project decisions follow the consensus and due-process rules in this document regardless of sponsorship.

## Vendor annexes

Vendor-co-authored platform-mapping annexes (§4.4 of the spec) are informative. They are reviewed by the vendor author and one TRACE Maintainer. Annexes do not require the full spec-change process.

## Non-Confidential, Restricted Disclosure

Information disclosed in connection with any Project activity, including but not limited to meetings, Contributions, and submissions, is not confidential, regardless of any markings or statements to the contrary. Notwithstanding the foregoing, if the Project is collaborating via a private repository, the Contributors will not make any public disclosures of that information contained in that private repository without the Approval of the Project.

## Linux Foundation hosting

TRACE Specification is hosted at the Linux Foundation as a Series of LF Projects, LLC. The Linux Foundation [announced the contribution of TRACE](https://www.linuxfoundation.org/press/linux-foundation-welcomes-trace-to-advance-verifiable-runtime-evidence-for-ai-workloads) on 25 August 2026.

The technical home for ongoing specification work is not yet settled. Formation paperwork is also still in progress: the Technical Charter and Project Contribution Agreement are being executed with LF Projects, LLC. This document is the governance authority until the Technical Charter takes effect, at which point governance transitions to a Technical Steering Committee as described in [CHARTER.md](CHARTER.md), and the Technical Charter controls where the two differ.

## Amendments

Amendments to this document require a PR, a minimum 14-day comment period, and Project Lead approval. Per [General Project Policies](#general-project-policies), governance changes approved under this document must also be approved by LF Projects, LLC.
