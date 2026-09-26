# Lost response, retry, changed declarations

An informative, synthetic example for [issue #324][issue] and the [proposed MCP
profile][draft], using an ordinary signed **TRACE v0.2** record. Its local format
claims no TRACE v0.3 conformance and changes no SDK acceptance rule.

| Step | Retained producer observation | What it supports |
|---|---|---|
| Discover | Two ordered `tools/list` result pages, through the terminal page | A reported complete traversal, not an atomic server catalog |
| Attempt 1 | Request ID `1`; response stream lost | Execution outcome unknown, not proof of non-execution |
| Discover again | Two new pages; an **uncalled** tool's metadata changed | A different snapshot, not a replacement for the first capture |
| Attempt 2 | New request ID `2`, linked to attempt 1; a successful response recorded | Producer-reported response only; attempt 1 stays unknown |

The `inventory.lookup` declaration and fictional arguments are unchanged. A shared
OTel `traceparent` correlates distinct attempts without establishing authorization
or causality. `call_count: 2` counts attempts, not completed operations. The new ID
illustrates the [MCP retry rule][mcp]; no MCP client, server or network failure runs.

## Files and exact commitments

`packet.json` holds the signed record, transcript and snapshots keyed by digest.
`verification-inputs.json` supplies a separate trust key and evaluation time; never trust
a key from the incoming packet. The deterministic `gen_mcp_retry.py` uses a public test
seed with no real-world signer identity. [Tests][tests] check the fixture and tampering.

The existing `sign_record()` / `verify_record()` APIs authenticate the record. Its signed
`tool_transcript.hash` is SHA-256 of the canonical **entire transcript object**, binding
each attempt's declaration digest and canonicalization identifier. Snapshot digests are
SHA-256 of the canonical **entire snapshot object**, including ordered pages, cursors,
cache metadata, observation flags, capture identity and every declaration member.
Committed `format` members distinguish transcript and snapshot hash domains.

`example-only/jcs-safe-integers-v1` means UTF-8 RFC 8785 via `rfc8785`: duplicate members
are rejected before conversion, floats refused and integers limited to the inclusive
range `[-9007199254740991, 9007199254740991]`. Booleans, null and array order are retained.
Unsupported MCP schema numbers are refused without rounding, coercion or dropping members.
The identifiers are unregistered local constants; fixture whitespace is not committed.

Every synthetic JSON result page is retained in full. The capture excludes HTTP bytes,
headers, connection identity, server authentication and timing; traversal does not prove atomicity.

## Reproduce (repository root, development dependencies installed)

```bash
python examples/mcp-retry/gen_mcp_retry.py
pytest tests/test_mcp_retry_example.py tests/test_generators_reproduce_fixtures.py
git diff --exit-code -- examples/mcp-retry/packet.json examples/mcp-retry/verification-inputs.json
```

The generator test regenerates JSON in a temporary checkout and compares bytes. Tests
distinguish missing (unavailable) evidence from present evidence with a mismatched digest;
an otherwise intact record signature can still verify in either case.

## Limits

Producer commitments do not prove truthful collection, agent visibility, execution history,
server identity, execution, authorization, safety, runtime integrity, hardware provenance
or exactly-once behavior. Producer observations are not server-signed responses. Enforcement
is `declared`, appraisal is `none`, and runtime/model/build fields are synthetic, not
attestations or SLSA evidence. No revocation check is performed. Freshness, collection
notifications, resource limits, continuations and confidentiality/retention are outside
scope. Interoperable formats and verifier rules still require the draft's adoption process.

[issue]: https://github.com/agentrust-io/trace-spec/issues/324
[draft]: ../../spec/mcp-profile-v0.3-draft.md
[mcp]: https://modelcontextprotocol.io/specification/2026-07-28/changelog
[tests]: ../../tests/test_mcp_retry_example.py
