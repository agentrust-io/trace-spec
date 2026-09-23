# Number-spelling vectors (proposed, not accepted)

> These fixtures encode the rule proposed in
> [agentrust-io/trace-spec#247](https://github.com/agentrust-io/trace-spec/issues/247).
> **No normative text for them has been accepted.** Do not read a passing vector here
> as a conformance requirement.

JSON has one number type. `1785000000`, `1785000000.0` and `1.785e9` are three
spellings of one value, and RFC 8785 writes all three as `1785000000`, so a Trust
Record carrying any of them has one signing pre-image and one signature. JSON Schema
2020-12 agrees: `integer` matches any number with a zero fractional part.

The Python reference did not. It decided whether `iat` was an integer by Python type,
and `json.loads` returns an `int` for the first spelling and a `float` for the other
two, so it rejected two correctly signed records that its own schema check had just
accepted, and that a JavaScript verifier, which has only the parsed value, cannot tell
apart from the first.

The rule proposed for section 3.2.2: whether a member is an integer, and whether an
integer is inside the safe-integer range, is decided by the value the number denotes,
not by how it is written.

## The vectors

| Fixture | Member | Written as | Outcome | What it pins down |
|---|---|---|---|---|
| `01-integer-spelling-verified.json` | `iat` | `1785000000` | verified | The baseline: the record and signature of `examples/verifier-compatibility/01-known-version-verified.json`, unchanged. |
| `02-fraction-spelling-verified.json` | `iat` | `1785000000.0` | verified | A fraction spelling of 01's value, with 01's signature. |
| `03-exponent-spelling-verified.json` | `iat` | `1.785e9` | verified | An exponent spelling of 01's value, with 01's signature. |
| `04-fractional-value-rejected.json` | `iat` | `1785000000.5` | rejected, `not_an_integer_value` | A value that is not a whole number. |
| `05-fractional-value-exponent-spelling-rejected.json` | `iat` | `17850000005e-1` | rejected, `not_an_integer_value` | 04's value with no decimal point, and 04's signature. |
| `06-above-range-integer-spelling-rejected.json` | `appraisal.timestamp` | `9007199254740992` | rejected, `outside_safe_integer_range` | One past the range, written as an integer. |
| `07-above-range-exponent-spelling-rejected.json` | `appraisal.timestamp` | `1.0e+21` | rejected, `outside_safe_integer_range` | The example on #247: whole, past the range, and a float in Python. |

**Every signature in the set is valid.** A rejecting vector is signed over its own
record, so the rule it names is the only reason to reject it. The range vectors use
`appraisal.timestamp` rather than `iat` because no freshness rule reads that member,
and a value past the range would otherwise also be a record from the far future.

## Two vectors per rule, and why these two

Each rule is carried by two vectors that a plausible shortcut cannot both pass:

- **02 and 03.** A verifier that refuses an exponent, or one that accepts
  `1785000000.0` by stripping a trailing `.0` from the text, verifies 02 and rejects
  03. One that decides on the parsed value cannot tell the two apart.
- **04 and 05.** A verifier that looks for a decimal point to find a fraction accepts
  05, which has none.
- **06 and 07.** A verifier that leaves the range to its canonicalizer, with the
  `rfc8785` Python package as that canonicalizer, rejects 06, because the package
  refuses an `int` outside the range, and verifies 07, because it writes the float
  `1e21` as `1e+21` without complaint.

`tests/test_integer_by_value.py` runs those shortcuts over the set and checks that
each one fails at least one vector.

## Format

Nothing in a fixture names a language or an API:

```jsonc
{
  "member":   "iat",               // the member under test, dotted from the record root
  "spelling": "1785000000.0",      // how it is written in this file, character for character
  "same_signature_as": "01-...",   // present when the value, and so the signature, is another vector's
  "verifier": { "verification_time": 1785000100, "max_age_seconds": 86400,
                "max_future_skew_seconds": 300 },
  "trusted_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "record":   { "iat": 1785000000.0, "signature": "..." },
  "expected": { "outcome": "verified" | "rejected",
                "failure": null | "not_an_integer_value" | "outside_safe_integer_range" }
}
```

`spelling` exists because a parser discards it: the file is the only place the
spelling survives, so the tests read it back out of the file's text and check it
against `spelling`. A fixture reformatted by a tool that rewrites numbers stops
testing anything, and the tests say so.

`expected.failure` names the rule, not a registered failure code: the Python
reference rejects 04 through 07 at the schema, which reports `is not of type
'integer'` for 04 and 05 and `is greater than the maximum of 9007199254740991` for
06 and 07. `verification_time` is fixed so the set does not expire; `iat` is 100
seconds before it.

## The signature on 06

The `rfc8785` Python package refuses to write `9007199254740992` at all. RFC 8785
section 3.2.2.3 writes every number through an IEEE 754 double, and the double of
that integer is exact, so the pre-image an implementation of the RFC writes for this
record is the one the package writes for `9007199254740992.0`. The generator signs
those bytes. A verifier that refuses the value while canonicalizing never reaches the
signature, and that is a rejection for the right reason.

## Running them

```bash
python examples/number-spelling/gen_number_spelling.py      # rewrites the seven files
node --test examples/number-spelling/spelling.test.mjs       # Node.js 20 or later, no dependencies
python -m pytest tests/test_integer_by_value.py
python examples/number-spelling/scan_published_numbers.py    # see below
```

The generator is deterministic, and `tests/test_generators_reproduce_fixtures.py`
rebuilds the set on every run and compares it byte for byte. The key is the
verifier-compatibility fixture key, from the same published seed: public test
material, and not a new key.

The JavaScript test parses the three spellings and gets one value, shows the spelling
does not survive `String(Number(x))`, the serialization RFC 8785 adopts, walks the
safe-integer boundary as the double sees it, and verifies every signature in the set
with `node:crypto` over a minimal RFC 8785 serialization of each record.

## Which published records this changes

The rule changes a verdict only for an integer-typed member written with a fraction or
an exponent. `scan_published_numbers.py` counts those in any directory it is given,
reading each number's spelling through `json`'s `parse_int` and `parse_float` hooks.
It skips this directory, whose vectors are re-spelled on purpose, unless it is named
itself, which makes the scan find the five re-spelled members here.

| Scanned | JSON documents | Numbers | Integer-typed | Written with a fraction or an exponent |
|---|---:|---:|---:|---:|
| this repository, `examples/` | 202 | 1064 | 453 | 0 |
| this repository, `spec/`, `docs/`, `schema/` | 19 | 86 | 11 | 0 |
| `agentrust-io/trace-tests` at `3af2b53` | 16 | 47 | 32 | 0 |
| `agentrust-io/trace-registry` at `d8fa885` | 26 | 64 | 9 | 0 |

No published record, fixture or example carries such a member, so no published
verdict changes.
