# Lost response, retry, changed declarations

An executable, synthetic example for [#324](https://github.com/agentrust-io/trace-spec/issues/324)
and the [proposed MCP profile](../../spec/mcp-profile-v0.3-draft.md), not a v0.3 implementation.
Install the repository's development dependencies, then run from its root:

```sh
example_out=$(mktemp -d)
python examples/mcp-retry/mcp_retry.py --out "$example_out"
python -m json.tool "$example_out/packet.json"
pytest tests/test_mcp_retry_example.py
```

The script writes `packet.json` and separate `verification-inputs.json` (trusted key
and fixed evaluation time). These generated files are not committed; the script is
the single source. Tests reproduce them twice and pin their exact bytes, then check
the signature with the separate trusted key and recompute commitments without the
generator's helper. Both paths use `rfc8785`; this is not independent validation of
that library's canonicalization. Outputs use explicit UTF-8/LF bytes on every platform.
The deterministic public signing seed is test material with no real-world identity.

| Observation | Meaning |
|---|---|
| Two ordered `tools/list` pages through termination | Reported complete traversal, not an atomic catalog |
| Request `1` loses its response stream | Execution outcome remains unknown |
| Fresh discovery; an uncalled tool's metadata changes | Both full snapshots retained; selected tool unchanged |
| Retry `2` links to `1` and records success | New attempt, not proof the first did not execute |

The requests retain the same arguments and OTel `traceparent`; correlation grants
no authority or causality. `call_count: 2` counts attempts, not completed operations.
This illustrates the [MCP retry rule](https://modelcontextprotocol.io/specification/2026-07-28/changelog);
no client, server or network failure runs.

## Exact commitments and limits

The v0.2 record's signed `tool_transcript.hash` is SHA-256 of the canonical **entire
transcript**, including each attempt's snapshot digest. Snapshot digests are SHA-256
of the canonical **entire snapshot**: all declarations (called or not), ordered result
pages, cursors, cache metadata and capture context. Committed `format` members
distinguish the two hash domains.

`example-only/jcs-safe-integers-v1` is UTF-8 RFC 8785 via `rfc8785`: reject duplicate
members, all floats and integers outside `[-9007199254740991, 9007199254740991]`;
preserve booleans, null and array order. No coercion or dropped members. Identifiers
are local, not registered formats; JSON whitespace is not committed. Missing evidence
is unavailable, not a match; changed retained evidence mismatches even if the record
signature still verifies. Tests cover both boundaries, wrong keys and signed-field edits.

All observations are producer assertions, not authenticated server responses.
Enforcement is `declared`, appraisal `none`, and runtime/model/build fields synthetic.
No revocation check, HTTP capture, freshness-policy or resource-limit appraisal.
It does not establish truthful collection, agent visibility, complete history, execution,
authorization, safety, runtime integrity, hardware provenance or exactly-once behavior.
SDK acceptance is unchanged; interoperable formats still require the draft's adoption.
