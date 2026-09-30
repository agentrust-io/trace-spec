# MCP Server Provenance Record v2

| Field | Value |
|---|---|
| Version | 2 |
| Status | Draft proposal, companion to TRACE v0.2 |
| License | CC BY 4.0 |

<!-- CHANGED: #406 - versioned binding of behavioral tool annotations -->

## 1. Scope and inherited requirements

This version binds four behavioral declarations in an MCP tool catalog. All
requirements of [Server Provenance v1](server-provenance-v1.md) apply except the
format identifier and catalog projection specified below. In particular, identity,
assurance kinds, trusted-key selection, signatures, anchoring and absence retain
their v1 meanings. This is a separate provenance format version, not a new TRACE
Trust Record version.

The record's `format` MUST be `agentrust-io/mcp-server-provenance/2`. It is covered
by the signature. A verifier MUST reject unknown versions and MUST select the
catalog projection from the signed format. It MUST NOT retry a mismatching v2
catalog using the v1 projection.

## 2. Catalog projection

For each tool, v2 adds an `annotations` object to the v1 projection of `name`,
`description` and `input_schema`. The object MUST contain exactly these four
boolean members, using the following defaults for absent members:

| Member | Default |
|---|---|
| `readOnlyHint` | `false` |
| `destructiveHint` | `true` |
| `idempotentHint` | `false` |
| `openWorldHint` | `true` |

These defaults follow MCP's [ToolAnnotations definition](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-06-18/schema.ts).
An absent `annotations` member is equivalent to an empty object. A present
`annotations` value MUST be an object; explicit null is invalid. Each present
behavioral member MUST be a JSON boolean. Null, numbers and strings MUST NOT be
coerced to booleans or treated as absent.

```json
{"name":"write","description":"Write a file","input_schema":{"type":"object"},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}}
```

The list is sorted and hashed with the same sorted-key canonicalization and
SHA-256 rules as v1 section 4. `inputSchema` is accepted as the wire spelling of
`input_schema`; if both appear, their canonical values MUST agree. Missing
`name`, `description` or input schema retain v1's null projection. This projection
does not replace MCP tool validation.

All four declarations are retained even when `readOnlyHint` is true. MCP gives
destructive and idempotent hints behavioral meaning only for non-read-only tools;
v2 nevertheless binds the declarations themselves, including otherwise inactive
ones. Omitted and explicitly defaulted values have identical hashes. Any boolean
change has a different projection. Output schemas, annotation titles, other
annotations, `_meta` and vendor extensions remain excluded.

## 3. Verification and migration

A verifier supporting both versions MUST preserve v1's original projection.
Existing v1 signatures and catalog hashes do not acquire annotation coverage.
Consumers requiring behavioral annotation binding MUST require v2 explicitly;
accepting any supported version is insufficient. Signature verification and live
catalog comparison remain separate required checks.

The reference library retains `FORMAT`, `build_record()` and `tool_catalog_hash()`
defaults as v1. New producers select `format=FORMAT_V2` in both APIs. Consumers
can enforce v2 with `required_format=FORMAT_V2` in both `verify_record()` and
`check_tool_catalog()`. Old v1-only verifiers reject v2; upgrade consumers before
switching producers. Do not relabel an existing record: recompute its catalog
hash and sign a new record. An empty catalog has the same digest in both versions;
the signed format still distinguishes their contracts.

## 4. Limits and conformance

A bound hint is an authenticated declaration, not evidence of actual behavior.
Consumers MUST NOT infer behavioral guarantees or permission to execute from a
successful catalog comparison. Trusted-key selection and local authorization
remain necessary. MCP cautions against trusting hints from untrusted servers.

In addition to v1's inherited checks, v2 conformance requires accepting omitted
and explicitly defaulted hints equivalently, detecting each behavioral hint
change, rejecting malformed hint values, preserving v1 verification, rejecting
unknown formats, and rejecting v1 when v2 is required. The reference tests in
`tests/test_provenance_v2.py` exercise these boundaries, including all 16 boolean
combinations and changes to each member.
