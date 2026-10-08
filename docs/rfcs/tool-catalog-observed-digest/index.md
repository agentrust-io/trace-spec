# Tool-catalog observed digest: a recomputable preimage for `tool-catalog` components

When an agent connects to an MCP server, the server sends a list of the tools it offers (its tool catalog). This note fixes one way to turn that list into a fingerprint (a digest) that anyone holding the same list can recompute and compare, without asking anyone else for the value. It is for people building gateways and verifiers, and it is a draft that binds nothing.

**Status:** Draft, informative. Binds nothing. **Scope:** How the `observed_digest` of a `tool-catalog` component is derived from the `tools/list` a server served, so that a relying party can set `expected_observed_digest` from bytes it holds and a second implementation can recompute every value from the same bytes. Two counterexamples, digest-mismatch and wrong-subject, with the pinned bytes they recompute from. **Target:** `TR-COMP-MCP-001` in [`composite-component-appraisal.md`](https://trace.agentrust-io.com/docs/rfcs/composite-component-appraisal/index.md), and input to open question 6 there. What an `mcp-server` component rests on (endpoint identity, transport key binding) and the server-to-catalog relationship method (`TR-COMP-MCP-002`) stay open. **Conformance material:** [`examples/verifier-token-conformance/catalog/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/verifier-token-conformance/catalog) (three pinned catalogs and `digests.json`), vectors `COMP-MCP-004` to `COMP-MCP-006`, and `tests/test_tool_catalog_digest.py`, which recomputes every digest from the pinned bytes without the generator.

Requirement keywords are lowercase throughout, on the same line the composite proposal draws: this is informative text and binds no implementation.

______________________________________________________________________

## 1. What a catalog digest is for

A `tool-catalog` component carries an `observed_digest`, and a relying party may pin an `expected_observed_digest` in its requirement; a token whose component differs is rejected with `component_observation_mismatch`. The composite proposal says that much and no more. It does not say what the digest is a digest of, so today the pin is a value the relying party copies from somewhere and cannot check against anything a server actually served.

This document fixes one derivation: from the `tools` member of a `tools/list` result to one digest per tool, keyed by tool name, and one digest for the whole catalog. A relying party that holds the `tools/list` a server served computes the catalog digest itself and pins it; an appraiser that observed the same catalog carries the same digest; a verifier compares two strings it can recompute from bytes. No party needs to call another to obtain the value.

The per-tool digests are the unit that matters at the gateway, where one call is authorized against one definition. The catalog digest is a fold over them and is what the `tool-catalog` component carries, because the component has one `observed_digest`.

## 2. Input

The input is the `tools` member of a `tools/list` result: a JSON array of tool definitions, as served. The derivation reads the JSON value, so the whitespace, member order and transport framing of the response (JSON body or SSE frame) do not matter. The pinned catalogs under `catalog/` are that array, re-serialized with indentation for review and byte-identical in value to what was served.

A definition that RFC 8785 cannot canonicalize (a number outside the IEEE 754 double range, for instance) has no digest under this derivation.

## 3. Per-tool digest

For one tool definition `t`:

1. **Restrict** `t` to the members `name`, `title`, `description`, `inputSchema`, `outputSchema` and `annotations`, in that this is the set the model and client act on. A member that is absent, or present with the value `null`, is omitted. Any other value is kept as is: an empty string, an empty object and `false` are hashed. `_meta` and every member not in the set are never hashed, so a change confined to them is not drift.
1. **Wrap** the restricted object under a profile label:

```
{"profile": "trace.mcp-tool-definition.v1", "tool": <restricted definition>}
```

This document defines the derivation under the `trace.` label. The label is part of the preimage, carried literally, and versions the derivation: if the member set or any rule here changes, the label changes, and a digest under one label never equals a digest under another. An implementation that adopts this derivation unchanged uses this exact string, or its digests do not recompute.

1. **Canonicalize** the wrapped object with RFC 8785 (JCS) and hash the canonical bytes with SHA-256.
1. **Write** the digest as `sha256:` followed by 64 lowercase hexadecimal characters, which is the form the token schema accepts for `observed_digest`.

## 4. Key

Each per-tool digest is keyed by the tool's name, encoded so that the key is printable ASCII, cannot contain the separators the fold uses, and is bounded in length:

1. Start from the `name` member as a string. A definition with no `name`, or an empty one, is keyed as `unnamed`.
1. Every character outside `0x21` to `0x7E` (space, controls, DEL and every non-ASCII character), plus `%` and `=`, is replaced by its UTF-8 bytes, each written as `%` and two uppercase hexadecimal digits. Every other character is literal.
1. If the encoded body is longer than 128 characters, it is cut to its first 96 characters and suffixed with `~` and the first 16 lowercase hexadecimal characters of SHA-256 over the raw UTF-8 bytes of the original name. The cut is a count of characters in the encoded body, not of source characters, and may fall inside a `%XX` triplet; the partial triplet is kept as it falls.
1. The key is `tool:` followed by the encoded body.

Because `=` and every control character are encoded, no name can forge a line of the fold in section 5. The two pinned servers have plain ASCII names, so `digests.json` also carries thirteen name-to-key pairs that exercise rules 2 and 3, including a body of exactly 128 characters that stays literal, bodies of 129 and 200 ASCII characters and of 50 two-byte characters that are cut, and two names whose cut lands inside a triplet.

## 5. Catalog digest

With the per-tool map `{key: digest}` from sections 3 and 4:

1. Sort the keys in ascending code-point order (the keys are printable ASCII, so byte order and code-point order agree).
1. Write one line per key, `key=digest`, joined by a single `\n` with no trailing newline.
1. The catalog digest is `sha256:` and the SHA-256 of the UTF-8 bytes of that text.

Reordering the array is therefore not drift, and a change to one definition changes exactly one line. Two edge rules are stated for completeness; neither is exercised by the pinned catalogs:

- Two definitions with the same key fold into one entry, whose digest is SHA-256 over the UTF-8 text `trace.mcp-tool-definition.v1.duplicates\n` followed by the sorted per-tool digests joined by `\n`.
- Beyond 500 entries, the first 500 keys in sorted order are kept and the rest fold into one entry keyed `tools:overflow`, whose digest is SHA-256 over `trace.mcp-tool-definition.v1.overflow\n` followed by the remaining `key=digest` lines joined by `\n`.

## 6. Where the values go in the token

- The `tool-catalog` component's `observed_digest` is the catalog digest of the `tools/list` the appraiser observed.
- The relying party's requirement for that component sets `expected_observed_digest` to the catalog digest of the `tools/list` it holds for the server it is asking about.
- The verifier compares the two strings. A difference is `component_observation_mismatch`, as today.

Nothing else in the token changes. The component's `profile` is whatever appraisal profile produced the status; the vectors use the corpus's example profile. Which profile identifier names this derivation for `accepted_profiles` is left to the project (section 10).

## 7. Pinned catalogs and their digests

Three catalogs are pinned under `catalog/`. The first and third were fetched from the servers named, with one `initialize` and one `tools/list` request each, and are the `tools` member of the result as served. The second was not served: it is the first with one sentence appended to the description of `ask_wiki_question`, and stands for what the server would serve after one definition changed.

| Catalog          | File                               | Served by                                         | Tools | Catalog digest                                                            |
| ---------------- | ---------------------------------- | ------------------------------------------------- | ----- | ------------------------------------------------------------------------- |
| deepwiki         | `deepwiki-tools-list.json`         | `https://mcp.deepwiki.com/mcp`, 2026-10-01        | 3     | `sha256:b3d3955a3da0c0eb95a263ac53e4df2efcb0634193b7cbee92337144f4146cbd` |
| deepwiki-drifted | `deepwiki-tools-list-drifted.json` | constructed from deepwiki                         | 3     | `sha256:fffdf1917378cc03057ab6dc7973731123e392adb365f6833dff650281a9dbf6` |
| cloudflare-docs  | `cloudflare-docs-tools-list.json`  | `https://docs.mcp.cloudflare.com/mcp`, 2026-10-02 | 2     | `sha256:aa6ec740288222f2e1081056057f05a0d4a38d4114fe3914ba9b95270835e53b` |

Per-tool digests:

| Key                        | deepwiki                                                                  | deepwiki-drifted                                                          |
| -------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `tool:ask_wiki_question`   | `sha256:7b433df44e34a9356d6481fc370283840a598c47b879d0f663952e91d8b3e729` | `sha256:a7da4da5eca7b1d7f329a555a7dd748587124dadd75056f375b306129215b4d6` |
| `tool:read_wiki_contents`  | `sha256:60d4ddd7838f28963920e8687ef644096fb38e8602cb25b8a53149fe87fc72d5` | unchanged                                                                 |
| `tool:read_wiki_structure` | `sha256:9b1330cf1cf19a6b003fc093dc0d92bdea53a47de4cf4efd17b7a0add7945c50` | unchanged                                                                 |

| Key                                    | cloudflare-docs                                                           |
| -------------------------------------- | ------------------------------------------------------------------------- |
| `tool:search_cloudflare_documentation` | `sha256:c4411b558681b396ca09a421f5dad4582804d906f80cd02a6f823d5d6b3d700e` |
| `tool:migrate_pages_to_workers_guide`  | `sha256:8f5e64cb597baefb37e8f11d4325f7fe88d23e4947301ef777897aa2ea8e599b` |

The deepwiki definitions each carry `name`, `description`, `inputSchema`, `outputSchema` and `_meta`, and no `title` or `annotations`; the cloudflare definitions carry `annotations` on both, `outputSchema` on one, and no `title` or `_meta`. Between them, every allowed member except `title` is present in at least one definition and absent from another, and the excluded `_meta` is present in three.

Every value in both tables was recomputed from the pinned files by `gen_corpus.py` when it built the vectors and, separately, by `tests/test_tool_catalog_digest.py`.

## 8. The cases

All three vectors share one requirement set: `mcp.server` (type `mcp-server`, no pin, as in `COMP-MCP-001`) and `tools.catalog` (type `tool-catalog`) with `expected_observed_digest` set to the deepwiki catalog digest. They differ only in what the token's `tools.catalog` component presents.

| Vector         | Kind                            | Presents                            | Outcome                          |
| -------------- | ------------------------------- | ----------------------------------- | -------------------------------- |
| `COMP-MCP-004` | positive                        | the deepwiki catalog digest         | `valid`, composite `affirming`   |
| `COMP-MCP-005` | counterexample, digest-mismatch | the deepwiki-drifted catalog digest | `component_observation_mismatch` |
| `COMP-MCP-006` | counterexample, wrong-subject   | the cloudflare-docs catalog digest  | `component_observation_mismatch` |

**Digest-mismatch** is drift after appraisal: the same server, one definition changed. Of the three per-tool lines, one differs, so a party holding both catalogs can name the tool that moved. The token carries only the fold, so the verifier reports the mismatch and not the tool; the per-tool localization is in the pinned material, not in the token.

**Wrong-subject** is a correct digest of the wrong catalog: every per-tool digest is right for what `docs.mcp.cloudflare.com` served, and none of its keys appears in the pinned catalog. The relying party asked about one server and was shown another server's catalog.

Both counterexamples carry the same reason code, and that is a statement about the token, not an oversight in the vectors. The token has no member that names the server a catalog came from, so inside the token the two cases are the same event: the presented digest is not the pinned one. The pinned bytes are what tell them apart. Separating them in the token is exactly the server-to-catalog relationship method that `TR-COMP-MCP-002` leaves to the gateway, and this document does not propose one.

`tests/test_tool_catalog_digest.py` holds each vector to the recorded roles: the pin in its context is the deepwiki digest, the component presents the digest of the catalog named for it, and the expected outcome is as above. It also pins the properties the derivation claims: `_meta` and unknown members do not change a digest, `null` and absent are the same and an empty string is not, reordering the array is not drift, drift changes one line, and the wrong-subject catalog shares no key with the pinned one.

## 9. What this establishes, and what it does not

A pinned catalog digest that matches establishes exactly this: the appraiser observed, at `appraised_at`, a `tools/list` whose definitions, restricted to the six members above, are the ones the relying party holds. Freshness, authority and the rest of the component's checks apply as the composite proposal says.

It establishes nothing about:

- **Runtime behavior.** What a tool does when called, whether its implementation matches its description, or what the server does between two observations.
- **Definitions not observed.** A tool the appraiser did not see has no line in the fold.
- **Which server served it.** The catalog digest does not contain the server's identity. A valid digest presented for the wrong server is caught only because the relying party pinned a value for the server it meant, which is `COMP-MCP-006`. Endpoint identity and transport key binding are what an `mcp-server` component would rest on and are open (composite proposal, section 11, question 6).
- **The evidence object.** The component's `evidence_refs` are not defined here. The served `tools/list` object is a natural candidate for the evidence an appraiser cites, but that choice, and the digest form it would take, is not made in this document.
- **The gateway's own catalog hash.** A gateway may project a catalog into a different digest for its own binding, as the cMCP gateway does with a Merkle root over leaves of a different shape (`tests/test_cmcp_catalog_binding.py`). That projection and this derivation are different functions of the same catalog; neither is derivable from the other, and the `profile` a component carries is what says which one its `observed_digest` is.

## 10. Open points for review

1. **A profile identifier.** The preimage label `trace.mcp-tool-definition.v1` names the derivation and is fixed. Whether the same identifier, or another in the project's namespace, should also name this derivation for `accepted_profiles` is the project's to decide; adopting one would not change any digest.
1. **Carrying the per-tool map.** The token carries one `observed_digest` per component. Whether a `tool-catalog` component should also carry the per-tool map, so that a verifier can localize drift without the pinned bytes, is a schema question this document does not raise.
1. **The evidence reference.** Whether the served `tools/list` object should be the component's cited evidence, and under what media type.

## 11. Reproduction

```
python examples/verifier-token-conformance/gen_corpus.py
python -m pytest tests/test_tool_catalog_digest.py tests/test_conformance_corpus.py
node tools/independent-verifier/verify.mjs examples/verifier-token-conformance/vectors/COMP-MCP-00[456].json
```

The generator recomputes the three catalog digests from the files under `catalog/` on every run; the test recomputes them again without the generator's code and checks `digests.json`, the vectors and the properties in section 8; the independent verifier reports the expected outcome for each vector.
