# Integration: AGT

This page is for teams that already use the Agent Governance Toolkit (AGT) and want a TRACE record for each agent session. It explains what the adapter puts into the record, what it leaves to you, and how much the result proves.

The [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) is open-source software that checks what AI agents do against rules while they run, and keeps an audit log. `TraceAGTAdapter` takes a session's policy, audit log and identity, as you supply them, and turns them into a standalone TRACE record signed in software, with no hardware evidence. It does not run the agent or independently verify those inputs.

## Choose the integration path

Use the [adapter tutorial](https://trace.agentrust-io.com/docs/tutorials/agt-adapter/index.md) for a complete local example with synthetic session data. For a real AGT deployment, capture the exact policy bytes, audit entries, chain tip, and identity from the version you run. Check that version's API and output profile before connecting it to the current TRACE verifier.

A record under the superseded v0.1 EAT profile is not accepted by the current v0.2 verifier. Reissue through a compatible producer rather than relabeling signed bytes.

## Field mapping

Most inputs go into the record as a SHA-256 hash, a short fingerprint that changes if a single byte of the input changes. A verifier holding the original policy file or audit log can recompute the hash and compare.

| Input                             | TRACE commitment                                         |
| --------------------------------- | -------------------------------------------------------- |
| Agent SPIFFE URI or DID           | `subject`                                                |
| Exact policy bytes                | SHA-256 in `policy.bundle_hash`                          |
| Canonical audit-entry list        | SHA-256 in `tool_transcript.hash`                        |
| Entry count, or explicit override | `tool_transcript.call_count`                             |
| UTF-8 chain-tip string            | SHA-256 software commitment in `runtime.measurement`     |
| Deployment metadata               | Model, classification, and build-provenance declarations |

Before hashing the audit log, the adapter writes it out in one fixed byte form (RFC 8785 canonicalization), so any implementation gets the same hash. It currently accepts a transparency string but does not submit to a registry. `appraisal.status` defaults to `none`, because the adapter does not evaluate the session and `appraisal.status` is the verifier's field (spec section 3.3.1); pass `appraisal_status` only when an appraisal actually happened. A producer must accurately set those fields before signing; the tutorial shows how to avoid claiming an anchor for synthetic input.

`enforcement_mode` is required and has no default. The adapter observes a session; it does not evaluate the policy, so it cannot know which mode applied. A default of `"enforce"` would claim an evaluation nobody saw, and spec section 4.3 says `"declared"` must not be a default. Pass the mode the deployment actually ran under, or `"declared"` when no policy engine evaluated the policy. This changes the evidence constructor, not the runtime's enforcement default or behavior.

## Assurance

The record proves who signed it and that it has not changed since. It does not prove the session ran on particular hardware.

Software signing authenticates the producer's statement when the recipient trusts its key. Hardware evidence requires a separately verified runtime and key binding. Level 2 additionally requires transparency anchoring. Placing an AGT application near a cMCP gateway does not automatically create matching or superseding records; use the [cMCP integration guide](https://trace.agentrust-io.com/docs/integration/cmcp/index.md) for that runtime's boundary.
