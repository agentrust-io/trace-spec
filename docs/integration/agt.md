# Integration: AGT

The [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) can supply policy and audit evidence to a TRACE producer. `TraceAGTAdapter` maps supplied session inputs into a standalone software-only record; it does not run the agent or independently verify those inputs.

## Choose the integration path

Use the [adapter tutorial](../tutorials/agt-adapter.md) for a complete local example with synthetic session data. For a real AGT deployment, capture the exact policy bytes, audit entries, chain tip, and identity from the version you run. Check that version's API and output profile before connecting it to the current TRACE verifier.

A record under the superseded v0.1 EAT profile is not accepted by the current v0.2 verifier. Reissue through a compatible producer rather than relabeling signed bytes.

## Field mapping

| Input | TRACE commitment |
|---|---|
| Agent SPIFFE URI or DID | `subject` |
| Exact policy bytes | SHA-256 in `policy.bundle_hash` |
| Canonical audit-entry list | SHA-256 in `tool_transcript.hash` |
| Entry count, or explicit override | `tool_transcript.call_count` |
| UTF-8 chain-tip string | SHA-256 software commitment in `runtime.measurement` |
| Deployment metadata | Model, classification, and build-provenance declarations |

The adapter uses RFC 8785 for transcript canonicalization. It currently accepts a transparency string but does not submit to a registry. `appraisal.status` defaults to `none`, because the adapter does not evaluate the session and `appraisal.status` is the verifier's field (spec section 3.3.1); pass `appraisal_status` only when an appraisal actually happened. A producer must accurately set those fields before signing; the tutorial shows how to avoid claiming an anchor for synthetic input.

## Assurance

Software signing authenticates the producer's statement when the recipient trusts its key. Hardware evidence requires a separately verified runtime and key binding. Level 2 additionally requires transparency anchoring. Placing an AGT application near a cMCP gateway does not automatically create matching or superseding records; use the [cMCP integration guide](cmcp.md) for that runtime's boundary.
