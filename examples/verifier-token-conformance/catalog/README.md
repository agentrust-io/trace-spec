# Pinned tool catalogs for the COMP-MCP cases

The bytes that `COMP-MCP-004` to `COMP-MCP-006` recompute from. The derivation, from
these files to the `observed_digest` a `tool-catalog` component carries, is stated in
[`docs/rfcs/tool-catalog-observed-digest.md`](../../../docs/rfcs/tool-catalog-observed-digest.md).

| File | What it is |
|---|---|
| `deepwiki-tools-list.json` | The `tools` member of the `tools/list` result served by `https://mcp.deepwiki.com/mcp` on 2026-10-01. Three tools. Each carries a `_meta` member, which is not hashed. |
| `deepwiki-tools-list-drifted.json` | Not served. The file above with one sentence appended to the description of `ask_wiki_question`. Stands for what the server would serve after one definition changed. |
| `cloudflare-docs-tools-list.json` | The `tools` member of the `tools/list` result served by `https://docs.mcp.cloudflare.com/mcp` on 2026-10-02. Two tools, with `annotations`; one with `outputSchema`. |
| `digests.json` | The per-tool and catalog digests recorded for each file, the role each file plays in each vector, and thirteen name-to-key pairs that exercise the key encoding rules the pinned names do not. |

Each catalog file holds the JSON value of the served array, re-serialized with
indentation. The derivation canonicalizes with RFC 8785 before hashing, so the
whitespace here is not part of any preimage.

`gen_corpus.py` recomputes the three catalog digests from these files on every run
and writes them into the vectors: the deepwiki digest as the relying party's
`expected_observed_digest` in all three, and the digest of the presented catalog
as the component's `observed_digest`. `tests/test_tool_catalog_digest.py`
recomputes the same values without the generator's code and holds `digests.json`
and the vectors to them.

The two served catalogs are what the servers returned on the dates given. A fresh
fetch may return something else; that would be drift, and these files are the
fixture, not the URLs.
