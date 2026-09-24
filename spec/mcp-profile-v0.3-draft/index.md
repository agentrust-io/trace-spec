# MCP transcript profile for TRACE v0.3

Status: proposed requirements, not an adopted profile or implemented wire format. This document does not change TRACE v0.2 verifier acceptance. Field names below describe logical requirements; serialization and a profile identifier remain subject to normative review before implementations claim conformance.

## 1. Scope

This proposal covers evidence for MCP tool-call attempts, including the complete tool declaration set the producer used when selecting and dispatching a call. It targets [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog), which removed protocol sessions and documents OpenTelemetry context propagation. Earlier MCP revisions can supply additional protocol-session metadata; that metadata does not replace the evidence identity defined here.

The requirements below use MUST, MUST NOT, SHOULD and MAY as proposed normative requirements. Publication of this draft does not adopt those requirements.

## 2. Evidence identity and correlation

A producer MUST assign an execution-scope identifier and a distinct identifier for each outbound tool-call attempt. The pair MUST be unique within that producer's signing identity. A verifier MUST interpret identifiers together with that identity; equal identifiers from different producers do not establish a shared execution. Reuse for conflicting attempts MUST be rejected.

The signed evidence MUST bind the scope, attempt, MCP protocol revision, target server identity as observed, tool name, exact request commitment and declaration snapshot commitment. Any authentication or appraisal of the target server MUST be reported separately from the producer's assertion of its identity.

OpenTelemetry `traceparent` and `tracestate` MAY be recorded as correlation metadata. They MUST NOT substitute for authenticated producer identity, attempt identity, authorization or proof of causality. Server-minted handles remain application state in tool arguments; they MUST NOT be treated as MCP sessions. Sensitive handles and baggage SHOULD NOT be copied into additional public metadata merely to correlate calls.

## 3. Declaration snapshot

For every attempt, the producer MUST commit to the complete tool declaration set it used at call time, including tools not selected. The snapshot MUST retain all members of each declaration, including input and output schemas, annotations, extensions and metadata. Missing members MUST remain distinguishable from explicit values. A selected-field catalog projection does not meet this rule.

The retained snapshot MUST identify the server, protocol revision, collection context and ordered `tools/list` result pages used to assemble the set. Result pages MUST be retained in full, including pagination and cache metadata. The snapshot MUST record whether collection reached a terminal page and whether the producer observed a catalog-change notification during collection or before dispatch. An incomplete collection MUST NOT be reported as a complete snapshot. Repeated pagination cursors or a collection stopped by resource limits MUST be reported as incomplete. Cached snapshots MUST identify their original capture and the freshness policy under which they were reused. A new fetch after execution cannot replace the snapshot used for selection.

The profile's eventual canonicalization contract MUST specify duplicate-key rejection, number handling, array ordering and digest algorithm/domain separation for the entire snapshot object. It MUST preserve declaration members rather than silently projecting away fields it does not recognize. If a value cannot be represented by that contract, the producer MUST report unsupported evidence rather than drop or coerce it. TRACE's existing integer-only JCS boundary needs explicit treatment for MCP declarations containing non-integer schema values; this draft does not silently widen that boundary or select a replacement.

A complete traversal records what the producer observed. It does not prove an atomic server catalog revision across pages, a truthful server, or that the server executed the captured declaration. A profile verifier MUST report those limits. An independently authenticated revision or server observation MAY add evidence, with its issuer and verification result identified separately.

## 4. Signature and transcript binding

The snapshot digest, its canonicalization/version identifier and the attempt identity MUST be inside the authenticated evidence boundary. One permitted design is to place them in each transcript entry and cover those entries with the signed Trust Record's `tool_transcript.hash`; the final profile MUST specify the transcript serialization and hash preimage before this is interoperable. A mutable URI alone MUST NOT satisfy snapshot binding.

Verification MUST check the record signature and trust policy, recompute the transcript commitment, and match each attempt to its retained snapshot bytes. Changing an uncalled tool's declaration MUST invalidate the snapshot comparison. Unavailable snapshot or transcript bytes MUST be reported as unavailable evidence, not as a successful declaration or call verification. Signature verification can still be reported separately with its narrower meaning.

The [server provenance v1 projection](https://trace.agentrust-io.com/spec/server-provenance-v1/index.md) and the proposed [v2 projection in PR #409](https://github.com/agentrust-io/trace-spec/pull/409) are different artifacts. V2 adds four behavioral hints but still omits output schemas and extensions. Neither projection proves this full-snapshot requirement. Policy or authorization evidence remains separately identifiable when bound by an application profile; a declaration digest itself grants no authority.

## 5. Retries and outcomes

Each re-issued request MUST receive a new attempt identifier. The producer MUST retain the prior attempt and explicitly link any retry to it within the same authenticated evidence boundary. MCP request IDs MUST be recorded with their type and request context; they MUST NOT serve as globally unique attempt IDs.

The transcript MUST distinguish a recorded response, an observed transport failure, and an unknown execution outcome. A broken response stream or timeout MUST NOT be described as proof that the tool did not execute. A successful retry MUST NOT overwrite the earlier unknown outcome or imply execution occurred only once. Multi-round-trip continuations likewise need distinct request attempts and an explicit relationship; an interim result is not a completed tool result.

Recorded responses MUST be bound to their attempt and exact contents. A response reported by a producer is not automatically authenticated by the server. Any separate server response proof MUST state its verification boundary. Call counts MUST count the profile's recorded tool-call attempts, including failed or unknown attempts, and MUST NOT be presented as counts of business operations completed.

## 6. Acceptance cases for the eventual implementation

These are required test designs, not claims of tests already implemented.

| Positive control                                         | Negative or boundary case                                 | Required distinction                      |
| -------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------- |
| Retained complete snapshot matches the signed commitment | Change an uncalled tool, output schema or extension       | Snapshot mismatch                         |
| All result pages retained through termination            | Missing page, repeated cursor or collection limit reached | Incomplete evidence                       |
| Original cached capture and freshness policy retained    | Replace it with a post-call fetch                         | Wrong snapshot                            |
| Supported canonical values round-trip                    | Duplicate keys or unsupported numeric value               | Reject or report unsupported; no coercion |
| Trusted record and recomputed transcript/snapshot        | Move the digest outside the signed boundary               | Binding failure                           |
| Available snapshot bytes match                           | URI resolves to changed bytes or bytes are missing        | Mismatch or unavailable, separately       |
| Two attempts linked by an authenticated retry relation   | Reuse an attempt ID or replace the first outcome          | Identity/history conflict                 |
| Timeout followed by successful retry                     | Treat first attempt as proven non-execution               | Unknown remains unknown                   |
| Producer records a server response                       | Assert server authentication without its proof            | Producer observation only                 |

## 7. Adoption and remaining work

Before adoption, specify the wire shape and profile identifier, transcript and snapshot canonicalization, pagination consistency limits, resource bounds and validation errors. Add schema, producer/verifier implementation, retained vectors and causal negative controls for section 6. Review confidentiality and retention of declaration metadata and tool arguments before publishing example artifacts.

Existing v0.2 records retain their original semantics and MUST NOT be relabeled as conforming to this profile. Implementations will need explicit opt-in and verifier support; no existing SDK is claimed to implement this draft. Sponsorship, Project Lead approval and the applicable comment period remain governed by [CONTRIBUTING](https://trace.agentrust-io.com/CONTRIBUTING/index.md) and [GOVERNANCE](https://trace.agentrust-io.com/GOVERNANCE/index.md).

Signatures authenticate commitments from an identified producer. They do not prove complete execution history, truthful declarations, actual tool behavior, authorization, exactly-once execution or business completion.
