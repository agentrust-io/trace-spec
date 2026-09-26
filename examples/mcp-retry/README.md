# Lost response, retry, changed declarations

An informative, synthetic worked example for [issue #324][issue] and the
[proposed MCP profile][draft]. It uses an ordinary signed **TRACE v0.2** record.
It does not implement or claim conformance to TRACE v0.3, and changes no SDK
acceptance rule. The small local format below is an example, not a profile proposal.

## Read the trace

| Step | Retained producer observation | What it supports |
|---|---|---|
| Discover | Two ordered `tools/list` result pages, through the terminal page | A reported complete traversal, not an atomic server catalog |
| Attempt 1 | Request ID `1`; response stream lost | Execution outcome unknown, not proof of non-execution |
| Discover again | Two new pages; an **uncalled** tool's metadata changed | A different snapshot, not a replacement for the first capture |
| Attempt 2 | New request ID `2`, linked to attempt 1; a successful response recorded | Producer-reported response only; attempt 1 stays unknown |

The selected `inventory.lookup` declaration and its fictional arguments do not
change. Both attempts share an OTel `traceparent`, but have distinct producer
attempt IDs and request contexts. Correlation is not authorization or causality.
`call_count: 2` counts recorded attempts, not completed business operations.

The [MCP 2026-07-28 changes][mcp] require a new request ID when reissuing after a
lost response stream. This packet illustrates that boundary; it does **not** run
an MCP client, server, network failure, model, policy engine or TPM.

## Files and exact commitments

- `packet.json`: signed record, retained transcript and snapshots keyed by digest.
- `verification-inputs.json`: separately configured fixture trust key and fixed
  evaluation time. Never derive a trusted key from an incoming packet.
- `gen_mcp_retry.py`: deterministic generator. Its public test seed is intentionally
  not a secret and establishes no real-world signer identity.
- [`test_mcp_retry_example.py`][tests]: executable, test-local evidence checks and
  causal negative controls. This is not a production MCP verifier.

The signature covers the record through the existing `sign_record()` /
`verify_record()` APIs. The signed `tool_transcript.hash` is SHA-256 of the
canonical **entire transcript object**. Each attempt inside that object binds its
declaration digest and canonicalization identifier. A snapshot digest is SHA-256
of the canonical **entire snapshot object**, including ordered pages, request
cursors, cache metadata, observation flags, capture identity, and every declaration
member, not a selected-field catalog projection.

The local canonicalization identifier is `example-only/jcs-safe-integers-v1`:
UTF-8 RFC 8785 using `rfc8785`, duplicate JSON members rejected before conversion,
all floating-point numbers refused, integers restricted to the inclusive range
`[-9007199254740991, 9007199254740991]`. Booleans and null are retained. Array order
is preserved. This deliberately does not support all numbers allowed in MCP
schemas; no rounding, coercion or dropping unsupported members occurs.

The committed `format` members distinguish transcript and snapshot hash domains.
The `example-only/...` names are local constants, **not registered profile IDs**.
Pretty-print whitespace in the fixture is not committed; the canonical JSON
values are. These are retained synthetic JSON result objects, not captured HTTP
bytes. Headers, connection identity, server authentication and transport timing
are not evidenced. Every result page is retained in full for this synthetic
capture; page completion does not establish a single atomic server revision.

## Reproduce

From the repository root, with its development environment installed:

```bash
python examples/mcp-retry/gen_mcp_retry.py
pytest tests/test_mcp_retry_example.py tests/test_generators_reproduce_fixtures.py
git diff --exit-code -- examples/mcp-retry/packet.json examples/mcp-retry/verification-inputs.json
```

The existing generator test deletes the example JSON from a temporary checkout
and regenerates it before comparing bytes. Negative controls use copies of the
committed packet, not unchecked generator verdicts. The tests separately check
record authentication, transcript integrity and snapshot availability/integrity.
Missing retained evidence is unavailable, not a successful comparison; changed
retained evidence is a mismatch. Neither changes the narrower fact that an
otherwise intact record signature verifies.

## Assurance ceiling and remaining work

The packet authenticates a fixture producer's commitments. It does not prove
truthful collection, what an agent actually saw, a complete execution history,
server identity, actual execution, authorization, safe behavior, runtime integrity,
hardware provenance, or exactly-once execution. `policy.enforcement_mode` is
explicitly `declared`; `appraisal.status` is `none`. Runtime, model and build fields
are synthetic placeholders, not attestations or SLSA evidence. No revocation
check is performed. The two evidence sources remain separate: a producer-signed
response observation is not a server-signed response.

This covers the requested small lost-response/retry/changed-declarations example,
not every acceptance case in draft section 6. Cached reuse/freshness policy,
notifications during collection, resource limits, multi-round-trip continuations,
independent server proofs and confidentiality/retention remain future work.
Wire schema, canonicalization choices, resource bounds and interoperable verifier
rules still require the draft's normal adoption process.

[issue]: https://github.com/agentrust-io/trace-spec/issues/324
[draft]: ../../spec/mcp-profile-v0.3-draft.md
[mcp]: https://modelcontextprotocol.io/specification/2026-07-28/changelog
[tests]: ../../tests/test_mcp_retry_example.py
