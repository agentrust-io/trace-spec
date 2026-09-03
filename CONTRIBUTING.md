# Contributing to TRACE

TRACE is an open specification. Contributions are welcome in four areas: the specification text, the JSON Schema, the examples, and the conformance test suite (in [agentrust-io/trace-tests](https://github.com/agentrust-io/trace-tests)).

## Running the reference-library checks

Install the development dependencies and run the suite from the repository root:

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src/agentrust_trace
```

Pytest is configured to import `src/agentrust_trace` from the checkout. A stale
wheel installed elsewhere in the environment must not shadow the code under
test; a regression test fails with the resolved import path if that guarantee is
lost.

## Using AI to contribute

Use agents. A lot of this was built with them and saying otherwise would be dishonest.

The rule is that you have to understand what you submit. If you cannot explain what your change does and how it interacts with the rest of the system, with the agent closed, do not open the pull request. Reviewing a change nobody can explain costs more than writing it did, and it becomes someone else's problem the moment it merges.

That is a rule about understanding, not about tooling.

## DCO sign-off

All commits must include a Developer Certificate of Origin sign-off:

```
git commit -s -m "fix: clarify runtime measurement format"
```

This adds `Signed-off-by: Your Name <you@example.com>`. PRs without DCO sign-off will not be merged.

## Types of contribution

### Spec changes (normative text)

Changes to `spec/trace-v0.2.md` that affect what implementations must do. Normative text is any statement using an RFC 2119 keyword in uppercase: what a conformant implementation MUST, SHOULD or MAY do. A normative change binds every implementation of TRACE, including implementations whose authors are not in the discussion.

**Anyone may propose a Normative Change, however only Normative Contributions with an organizational sponsor willing to implement and maintain that element in the specification will be accepted.**

The sponsor is an organization that implements TRACE, or produces the attestation platform the change concerns, and is willing to be named as accountable for the requirement in the PR. In practice that has meant silicon and cloud attestation vendors, platform and framework implementers, and standards bodies carrying the work forward. Reviewers confirm the sponsorship, not the individual's competence.

The reason is maintenance cost, not merit. A MUST is a promise the project keeps for every future version. Evaluating whether it can be implemented, at what cost, across which platforms, needs an organization that will actually implement it and answer for it later.

Steps for a normative contribution:

1. Open a GitHub issue using the **Spec change proposal** template. Describe the problem, the proposed change, and the spec section affected. Proposals are evaluated on the technical argument alone, sponsored or not.
2. Allow a minimum 5 business days for comment. Breaking changes, including anything touching wire format, cryptographic algorithms, or Trust Record required fields, carry a minimum 30-day comment period. See [Backward compatibility](GOVERNANCE.md#backward-compatibility) for the conditions under which a breaking change is considered at all.
3. Name the sponsoring organization in the PR. If a proposal is accepted without a sponsor, a Maintainer may sponsor and carry the PR, and the proposer is credited in the `CHANGELOG.md` entry. A normative PR opened without a sponsor is not rejected on that basis: reviewers will say so on the PR and either identify a sponsor or convert it to an informative change.
4. Submit the PR. Mark changed normative text with an HTML comment: `<!-- CHANGED: #NNN - description -->`.
5. Update `CHANGELOG.md`.
6. Breaking changes require Project Lead approval and an explicit backward-compatibility statement naming what breaks and what implementers must do.

**No sponsor is required for** editorial changes, examples, conformance tests, tooling, schema changes tracking an already-merged spec change, and informative additions such as crosswalks and mappings to external schemas. Informative text carries no RFC 2119 keywords and binds no implementation, so it is the right home for a mapping that is still settling. Most contributions are in this set.

### Schema changes (schema/trace-claim.json)

Schema changes must track normative spec changes. A schema PR without a corresponding spec PR (or reference to a merged one) will not be merged.

### Example additions

New hardware provider examples in `examples/` are welcome. Follow the existing format: real field names, truncated digests with `...` suffix, a `_comment` field explaining the hardware platform.

### Editorial changes

Typos, broken links, and clarity improvements can go straight to a PR without a prior issue.

## Vendor profile annexes

TRACE will publish vendor-co-authored claim-mapping annexes (§4.4 of the spec) as informative companions to v1.0. If you represent a silicon or cloud attestation vendor and want to author the annex for your platform, open an issue with the `vendor-annex` label.

## Review timeline

Comment periods are minimums. The project takes as much time as it needs to reach a consensus decision.

- Non-breaking spec changes: a minimum 5 business days for comment
- Breaking or wire-format changes: a minimum 30-day comment period + Project Lead sign-off

Maintainer response targets are commitments to you, not minimums. Ping the PR if one is missed.

- Editorial PRs: reviewed within 3 business days
- Spec change PRs: reviewed within 7 business days

## Style

- Normative requirements use RFC 2119 keywords (MUST, SHOULD, MAY) in uppercase.
- Non-normative text does not use uppercase RFC 2119 keywords.
- Field names in `code` formatting.
- Diagrams in ASCII (no binary image files in the spec directory).

## License

Anyone who submits a PR, files an issue, or participates in discussion on the repository is a Contributor bound by the license terms.

Specification contributions are made under the [Community Specification License 1.0](Governance/COMMUNITY-SPECIFICATION-LICENSE.md) and the [Community Specification Contributor License Agreement](Governance/CLA.md). Source-code contributions are made under Apache License 2.0. Documentation contributions other than specification text are made under CC BY 4.0. You keep the copyright in your contributions: no contributor is asked to assign copyright to the project. See [LICENSE](LICENSE), the [license map](Governance/License.md), and [General Project Policies](GOVERNANCE.md#general-project-policies).
