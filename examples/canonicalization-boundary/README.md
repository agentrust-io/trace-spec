# Canonicalization boundary vectors

Spec section 3.2.2 requires an RFC 8785-conformant canonicalizer and names
`json.dumps(sort_keys=True)` as insufficient.

**What already existed.** `tests/test_sign.py` carries literal-byte known-answer
tests over `_canonical_bytes`: non-ASCII escaping, number formatting, whitespace and
key sorting, and a comparison against the reference library. Those tests catch a
regression in this library.

**What these vectors add.** Portable positive and negative controls over complete,
schema-valid records, with deterministic signatures:

1. **They are portable.** A known-answer test over a private function is runnable only
   from Python, by this package. The roadmap targets Go, Rust and TypeScript verifiers
   for v1.0, and none of them can run `test_sign.py`. These are signed records: any
   implementation can run them against its own verifier. ASCII-only values and
   schema-fixed keys can conceal the differences between JCS and ad-hoc serializers;
   these records deliberately exercise those differences.
2. **They separate key ordering from escaping.**
   `test_jcs_distinguishes_unicode_key_order_from_json_dumps` compares `{"z": 1,
   "\U0001f600": 2}`. Under RFC 8785's UTF-16 code-unit sort and under Python's
   code-point sort that object serializes in the *same* order; its own docstring says
   so. The test detects divergence through `ensure_ascii` escaping instead. A
   canonicalizer that sorts by code point but emits raw UTF-8 passes it. Vectors `03`
   and `04` instead contain keys whose two orderings disagree, at different nesting
   depths.
3. **They require both accepting and rejecting answers.** The original four
   fixtures expect acceptance. Fixtures `05` and `06` retain valid record shapes and
   genuine Ed25519 signatures, but those signatures cover different bytes from the
   RFC 8785 signing preimage. A conformant verifier rejects them. This supplies the
   missing direction recorded by
   [the corpus adequacy checks](../../tests/test_adequacy_all_sets.py), without
   changing the signature contract.

The positive records are correctly signed over their RFC 8785 bytes. The negative
records have signatures that are mathematically valid over their declared alternate
preimages, but are not valid TRACE signatures over those records. This is not a
test of rejecting random signature bytes, a different trust key, or malformed JSON.

## The ladder

Each ad-hoc form fixes the previous one's divergence and still rejects at least one
positive record. The two negative records also distinguish a verifier that tries
alternate serializations after JCS signature verification fails:

| Form | Diverges because | Positive vectors that it rejects |
|---|---|---|
| `json.dumps(o, sort_keys=True)` | Default separators insert spaces | `01`, `02`, `03`, `04` |
| `json.dumps(o, sort_keys=True, separators=(",", ":"))` | `ensure_ascii` escapes non-ASCII as `\uXXXX`; RFC 8785 emits literal UTF-8 | `01`, `02`, `03`, `04` |
| `json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` | Code-point key order can differ from RFC 8785's UTF-16 code-unit order | `03`, `04` |

`03-utf16-key-order.json` carries two extra `cnf.jwk` members (RFC 7517 permits
additional JWK members): `zk` followed by U+1F600 and `zk` followed by U+FFFD.
U+1F600 is `D83D DE00` in UTF-16, so it sorts
*before* U+FFFD by code units and *after* it by code points.
`04-utf16-key-order-nested.json` moves that divergence inside another object, so the
set does not depend on one key-order vector at one nesting depth.

## Negative signing-preimage controls

| Vector | Bytes actually signed | Expected result |
|---|---|---|
| `05-ascii-escaped-signature.json` | Compact JSON with non-ASCII string values escaped | `rejected`, `signature_invalid` |
| `06-codepoint-order-signature.json` | Compact literal-UTF-8 JSON with keys sorted by code point | `rejected`, `signature_invalid` |

For each negative, the tests check the schema and configured key, verify the
signature over the declared alternate bytes, and confirm that those bytes differ
from the RFC 8785 form. Verification over the RFC 8785 form fails. Re-signing the
same payload over its RFC 8785 form succeeds, isolating the signing preimage as the
reason for rejection. The two forms test different serialization shortcuts rather
than two arbitrary corruptions of a signature.

The whitespace, escaping and key order of the outer fixture file are not the
signature preimage. A consumer parses the `record` object and canonicalizes it with
only `signature` absent. Pretty-printing that same object does not invalidate a
correct TRACE signature. These fixtures are generated here; they are not evidence
of an independent producer or a test of delegation parent-record hash semantics.

## What each fixture carries

- `record`: a complete, schema-valid v0.2 record with an embedded signature.
- `trusted_key`: the Ed25519 JWK selected externally for verification.
- `expected.outcome`: `verified` for `01` through `04`, or `rejected` for `05` and
  `06`; the negatives also carry `expected.failure: signature_invalid`.
- `diverges_under`: which ad-hoc forms compute different bytes for this record.
  `tests/test_canonicalization_boundary.py` recomputes this list on every run rather
  than trusting it, and separately asserts that the set as a whole still catches every
  form on the ladder.
- `signing_form` (negative fixtures): identifies the alternate serialization that
  produced the signed bytes.
- `signed_input_utf8` (negative fixtures): the actual signing preimage as a JSON
  string; encode its decoded value as UTF-8 to recover the bytes.
- `canonical_input_utf8` (negative fixtures): the RFC 8785 preimage in the same
  representation, recomputed by the tests rather than trusted as an assertion.

These fixture metadata fields are outside `record`. They describe the test; they
are not new TRACE fields or instructions to a verifier to accept another form.

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

So neither half is reachable now, and neither can be carried by a vector here: every
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
