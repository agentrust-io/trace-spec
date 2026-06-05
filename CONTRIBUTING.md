# Contributing to TRACE

TRACE is an open specification. Contributions are welcome in four areas: the specification text, the JSON Schema, the examples, and the conformance test suite (in [agentrust-io/trace-tests](https://github.com/agentrust-io/trace-tests)).

## DCO sign-off

All commits must include a Developer Certificate of Origin sign-off:

```
git commit -s -m "fix: clarify runtime measurement format"
```

This adds `Signed-off-by: Your Name <you@example.com>`. PRs without DCO sign-off will not be merged.

## Types of contribution

### Spec changes (normative text)

Changes to `spec/trace-v0.1.md` that affect what implementations must do.

1. Open a GitHub issue using the **Spec change proposal** template. Describe the problem, the proposed change, and the spec section affected.
2. Allow 5 business days for comment. Changes touching wire format, cryptographic algorithms, or Trust Record required fields require 14 days.
3. Submit a PR. Mark changed normative text with an HTML comment: `<!-- CHANGED: #NNN — description -->`.
4. Update `CHANGELOG.md`.
5. Breaking changes (backward-incompatible field removals, algorithm deprecations) require Project Lead approval and an explicit backward-compatibility statement.

### Schema changes (schema/trace-claim.json)

Schema changes must track normative spec changes. A schema PR without a corresponding spec PR (or reference to a merged one) will not be merged.

### Example additions

New hardware provider examples in `examples/` are welcome. Follow the existing format: real field names, truncated digests with `...` suffix, a `_comment` field explaining the hardware platform.

### Editorial changes

Typos, broken links, and clarity improvements can go straight to a PR without a prior issue.

## Vendor profile annexes

TRACE will publish vendor-co-authored claim-mapping annexes (§4.4 of the spec) as informative companions to v1.0. If you represent a silicon or cloud attestation vendor and want to author the annex for your platform, open an issue with the `vendor-annex` label.

## Review timeline

- Editorial PRs: 3 business days
- Non-breaking spec changes: 7 business days
- Breaking or wire-format changes: 14 business days + Project Lead sign-off

## Style

- Normative requirements use RFC 2119 keywords (MUST, SHOULD, MAY) in uppercase.
- Non-normative text does not use uppercase RFC 2119 keywords.
- Field names in `code` formatting.
- Diagrams in ASCII (no binary image files in the spec directory).

## License

By contributing you agree that your contributions will be licensed under the terms in [LICENSE](LICENSE).
