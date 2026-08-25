# Canonicalization boundary vectors

Spec section 3.2.2 requires an RFC 8785-conformant canonicalizer and names
`json.dumps(sort_keys=True)` as insufficient.

**What already existed.** `tests/test_sign.py` carries four literal-byte known-answer
tests over `_canonical_bytes` — non-ASCII escaping, number formatting, whitespace and
key sorting, and a comparison against the reference library. They are good tests and
they do catch a regression in this library.

**What these vectors add.** Two things those tests cannot do:

1. **They are portable.** A known-answer test over a private function is runnable only
   from Python, by this package. The roadmap targets Go, Rust and TypeScript verifiers
   for v1.0, and none of them can run `test_sign.py`. These are signed records: any
   implementation runs them against its own verifier. Every *other* record in the
   repository is ASCII-only with schema-fixed keys, where all serializers agree
   byte-for-byte — so no existing record's acceptance depends on canonicalizing
   correctly.
2. **One of them separates key ordering, which nothing else does.**
   `test_jcs_distinguishes_unicode_key_order_from_json_dumps` compares `{"z": 1,
   "\U0001f600": 2}`. Under RFC 8785's UTF-16 code-unit sort and under Python's
   code-point sort that object serializes in the *same* order — its own docstring says
   so — and the test detects divergence through `ensure_ascii` escaping instead. A
   canonicalizer that sorts by code point but emits raw UTF-8 passes it. Vector `03`
   is the first object in the repository whose two orderings actually disagree.

Each record is schema-valid and correctly signed over its RFC 8785 bytes, so a
conformant verifier accepts it, and a verifier built on any ad-hoc form computes
different signing bytes and rejects a valid record.

## The ladder

Each form fixes the previous one's divergence and still fails somewhere:

| Form | Diverges because | Caught by |
|---|---|---|
| `json.dumps(o, sort_keys=True)` | Default separators insert spaces | every vector (and any signed record) |
| `… separators=(",", ":")` | `ensure_ascii` escapes non-ASCII as `\uXXXX`; RFC 8785 emits literal UTF-8 | `01`, `02`, `03` |
| `… separators=(",", ":"), ensure_ascii=False` | Python sorts keys by code point; RFC 8785 sorts by UTF-16 code units. The orders differ exactly when a key contains a supplementary-plane character | `03` only |

`03-utf16-key-order.json` is the load-bearing vector: it is the only record in this
repository that distinguishes a true RFC 8785 serializer from `json.dumps` with every
option chosen carefully. Its two extra `cnf.jwk` members (RFC 7517 permits additional
JWK members, and `cnf.jwk` is the one schema object open to them) are `zk` followed by
U+1F600 and `zk` followed by U+FFFD — U+1F600 is `D83D DE00` in UTF-16, so it sorts
*before* U+FFFD by code units and *after* it by code points.

## What each fixture carries

- `record` — a complete, schema-valid, signed v0.2 Trust Record.
- `trusted_key` — the Ed25519 JWK to verify against.
- `expected.outcome` — `verified`, always. These are positive vectors; the negative
  behaviour (rejection) is what a non-conformant verifier does to them.
- `diverges_under` — which ad-hoc forms compute different bytes for this record.
  `tests/test_canonicalization_boundary.py` recomputes this list on every run rather
  than trusting it, and separately asserts that the set as a whole still catches every
  form on the ladder.

`iat` is fixed so the set regenerates byte-for-byte; run with freshness disabled or
with `iat`'s instant supplied as "now". `gen_boundary_vectors.py` regenerates the set.

## What there is deliberately no vector for

RFC 8785's IEEE 754 number serialization is the other divergence the spec warns about.
There is no vector for it, and the reason is different for each half of the surface.

The integer half was reachable, and an earlier version of this note said it was not.
Integers up to 2^53 do serialize identically everywhere, which is true and was never the
whole claim: `iat`, `origin.ingested_at`, `tool_transcript.call_count` and
`appraisal.timestamp` were typed `integer` with no upper bound, so a value above 2^53 was
schema-valid. Two independent RFC 8785 implementations disagree on such a value and
neither is safe to rely on: `rfc8785` 0.1.4 refuses it, and `canonicalize` 4.0.0 emits for
it the same bytes it emits for the integer next to it, so one signature stands for two
records and nothing raises. Those fields now carry the range RFC 8785 Appendix B note 1
names, which section 3.2.2 raises from that note's SHOULD to a MUST.

The `number` half was reachable too, through the same door vector `03` uses. `cnf.jwk` is
open because RFC 7517 permits members this schema does not name, and its
`additionalProperties` was absent, which means true. A float, or a colliding integer, went
in as an undeclared member, was covered by the signature like everything else, and met no
constraint at all. Undeclared members are now held recursively to
`#/$defs/canonicalizableValue`, which admits strings, booleans, null, arrays, objects and
integers inside the range, and no `number`.

One surface stays out of reach of any schema, and out of reach of a vector for the same
reason: `digest_jcs` and `SandboxAdapter.transcript_hash` canonicalize objects a caller
supplies and nothing validates. Two declarations differing only in an integer above the
range produce one digest under `canonicalize` 4.0.0. Section 3.2.2 states the rule for any
object canonicalized under it, and here `rfc8785` refuses the value, which is pinned as
behaviour rather than assumed.

So neither half is reachable now, and neither can be carried by a vector here: a positive
vector is a schema-valid record, and these cases are exactly the records the schema
rejects. The tests in this directory carry them instead, structurally and behaviourally.
If a `number` field is ever wanted, `test_no_schema_field_is_typed_number` is the place to
argue for it, and a number-formatting vector here is what the argument has to come with.

`number_divergence_repro.py` reproduces the number divergence itself, on the standard
library alone: run `python examples/canonicalization-boundary/number_divergence_repro.py`.
It first checks its own canonicalizer against `rfc8785` on every record in `examples/`,
then shows two records reaching one canonical form and one signature, why the bound is
2^53 - 1 rather than 2^53, and that the schema now refuses both. Exit code 0 means every
step reproduced.

These vectors exercise accepted normative text (the section 3.2.2 MUST), not a
proposal; they carry no proposal marker.
