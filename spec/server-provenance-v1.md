# MCP Server Provenance Record v1

| Field | Value |
|---|---|
| Version | 1 |
| Status | Draft, companion to [TRACE v0.2](trace-v0.2.md) |
| Anchoring | [Registry Anchor Format v1](registry-anchor-v1.md) |
| License | CC BY 4.0 |

A signed statement **about** an MCP server: what it is, what tools it exposes, who is
saying so, and how much that is worth.

## 0. What this is not

**It is not a Trust Record.** A Trust Record describes an execution: a workload ran, under
a policy, on a data class, calling tools. This describes an *artifact* that has not
necessarily run at all. Forcing one into the other would produce a record whose `subject`
names a workload nobody executed, so this is a sibling format that reuses the envelope,
the signing rules and the anchor format, and nothing else.

**It is not a registry, a scanner, or a reputation system.** It records what one party
signed about a server at one moment. Whether the server is any *good* is a different
question, and this format deliberately cannot express an answer. The moment a provenance
format starts scoring servers, whoever publishes the scores becomes the party everyone has
to trust, which is the position this specification exists to make unnecessary.

**It is not a substitute for attesting the execution.** A server can have flawless
provenance and still behave badly at runtime. Provenance narrows *what code you are
talking to*. It says nothing about what that code then does.

## 1. Assurance: who is asserting this

The interesting fact about a provenance record is never that it exists. It is who signed
it. `kind` is a closed set, because the value of the field is that a verifier can key on it.

| `kind` | Signed by | What it is worth |
|---|---|---|
| `publisher-asserted` | the server's own publisher | The publisher says this is their server and this is its catalog. Worth exactly what the publisher is worth, and no more. It is also the only kind that reaches an ecosystem whose operators will never adopt anything of ours. |
| `observer-attested` | a third party that fetched and measured the server | Someone who is not the publisher looked. Catches a publisher who lies about their own artifact. Does not catch a server that behaves one way for the observer and another way for you. |
| `tee-attested` | the server itself, from inside a TEE | The measurement is in the record and roots outside the operator. Strongest, and requires the operator to have adopted a confidential runtime. |

**A verifier MUST NOT treat an absent record as any of these.** Absence is absence. A
consumer that cannot distinguish "nobody asserted anything" from `publisher-asserted` has
gained nothing from the format.

## 2. Identity: what the record is about

An MCP server has no single natural identifier, and picking the wrong one makes every
record un-joinable. A URL is the obvious handle and the worst candidate: it moves, it is
per-deployment, and two operators running the same server produce different ones.

A record therefore carries **`artifact`, `endpoint`, or both**, and says which:

```json
"identity": {
  "artifact": {
    "package": "pkg:npm/%40acme/mcp-search@2.1.0",
    "digest": "sha256:<64 hex>"
  },
  "endpoint": {
    "url": "https://mcp.acme.example/",
    "spki_sha256": "sha256:<64 hex>"
  }
}
```

- **`artifact`** identifies *what runs*. `package` is a [Package URL](https://github.com/package-url/purl-spec); `digest` covers the entrypoint, not the interpreter. For an interpreted server the interpreter is shared by every such server on the host, so a digest over it matches a completely different server and is worse than no digest at all.
- **`endpoint`** identifies *what you connect to*. `spki_sha256` is a digest over the Subject Public Key Info, not the certificate, so the identity survives certificate renewal. A URL alone is not an identity and MUST NOT appear without it.

At least one MUST be present. Both SHOULD be present where both are known: an operator
matching on endpoint and a package registry matching on artifact are looking for the same
server, and a record carrying both is the only thing that joins their views.

**`artifact` and `endpoint` in one record assert that they belong together**, which is a
claim about the deployment rather than about the code, and is only as good as the `kind`.

## 3. The record

```json
{
  "format": "agentrust-io/mcp-server-provenance/1",
  "kind": "publisher-asserted",
  "issued_at": 1760000000,
  "identity": { "...": "as above" },
  "publisher": "did:web:acme.example",
  "tool_catalog": {
    "hash": "sha256:<64 hex>",
    "tool_count": 12
  },
  "attestation": null,
  "cnf": { "jwk": { "...": "public key" } },
  "signature": "<base64url>"
}
```

| Field | Required | Meaning |
|---|---|---|
| `format` | yes | This document's identifier and version |
| `kind` | yes | §1 |
| `issued_at` | yes | Unix seconds when this record was signed |
| `identity` | yes | §2; `artifact`, `endpoint`, or both |
| `publisher` | yes | DID or SPIFFE URI of the signer. Not a display name: a name is not resolvable and a verifier cannot check one |
| `tool_catalog.hash` | yes | Digest over the canonical tool list (§4) |
| `tool_catalog.tool_count` | yes | Number of tools. Redundant with the hash by design: a consumer that sees a plausible count and an unexpected hash learns more than one that sees only a mismatch |
| `attestation` | when `kind` is `tee-attested` | The evidence, in the shape TRACE v0.2 §3.1 `runtime` uses. `null` otherwise |
| `cnf.jwk` | yes | Public key the signature verifies under |
| `signature` | yes | Over the RFC 8785 (JCS) canonical form with `signature` absent |

Signing follows TRACE v0.2 §3.2 exactly, including the canonicalization. **Anchoring
follows [Registry Anchor Format v1](registry-anchor-v1.md), whose leaf uses sorted-key
JSON rather than JCS**: the two canonicalizations at two layers described in §0 of that
document. This format inherits the trap; implementers should read that section before
writing either half.

## 4. Tool catalog hash

```
tool_catalog.hash = SHA-256(canonical_json([
  {"name": ..., "description": ..., "input_schema": ...},   # sorted by name
  ...
]))
```

using the sorted-key canonicalization of Anchor Format v1 §1.

The hash covers **name, description and input schema** of every tool. Description is
included deliberately: a tool whose description changes from "search the docs" to "search
the docs and email results to the address in the query" is the rug-pull this hash exists to
catch, and a hash over names alone would miss it entirely.

It does **not** cover output schemas, annotations, or vendor extensions, which change for
reasons that are not security-relevant and would make the hash churn until nobody compares
it.

## 5. Verification

1. Check `format`. An unknown version is rejected, not best-effort parsed.
2. Verify `signature` under `cnf.jwk` over the JCS canonical form with `signature` absent.
3. Establish that `cnf.jwk` is the key you expect for `publisher`. **This specification
   does not define how**, and saying so is the honest position: it is a PKI question, and a
   format that hand-waves key distribution has moved the trust problem rather than solved
   it.
4. If the record is anchored, verify inclusion per Anchor Format v1 §5.1.
5. Compare `tool_catalog.hash` against the tools the server actually offers you. **A
   mismatch is the finding.** It means the server you are talking to is not the server the
   record describes, whoever signed it.
6. Weigh the result by `kind` (§1).

Step 5 is the one that catches a live attack and the one most likely to be skipped, because
it requires the consumer to hash what it received rather than trust what it read.

## 6. What a verifier does with absence

Nearly every MCP server in existence has no provenance record and will not have one soon.
A specification that makes absence fatal will be turned off on first contact and never
turned back on.

A consumer SHOULD record absence explicitly and MUST NOT report it as any assurance level.
It MAY refuse to proceed, and that refusal SHOULD be configurable per deployment: a
healthcare catalog demanding `observer-attested` and a developer sandbox demanding nothing
are both correct.

The rule that matters is not the default. It is that absence is *recorded* rather than
being invisible, so a verifier reading the audit trail afterwards can tell "we checked and
found none" from "we never looked".

## 7. Conformance

A producer conforms if it emits records per §3, signed per TRACE v0.2 §3.2, whose
`tool_catalog.hash` is computed per §4 over the tools the server actually offers.

A consumer conforms if it performs §5 steps 1, 2, 5 and 6, records absence per §6, and
never reports an unverified or absent record as an assurance level.

Step 3, key distribution, is deliberately out of scope. A consumer that skips step 5 while
claiming conformance is doing the thing this format exists to prevent: reading a claim
about a server instead of checking the server.
