# Signature-encoding vectors (proposed, not accepted)

> These fixtures encode the obligation proposed in
> [agentrust-io/trace-spec#247](https://github.com/agentrust-io/trace-spec/issues/247).
> **No normative text for it has been accepted.** Do not read a passing vector here
> as a conformance requirement.

Spec section 3.2.2 already names the embedded `signature` field's encoding as
base64url, no padding. What it leaves open is whether a *different spelling of
the same 64 bytes* is the same record. An Ed25519 or ES256 signature is 64
bytes (512 bits); base64url without padding spends 86 characters (516 bits) on
them, so the final character carries 4 bits nothing signs. RFC 4648 section 3.5
calls a spelling with non-zero unused bits non-canonical. A decoder that only
restores padding and decodes accepts it, because those bits are discarded, not
checked; a decoder that also checks them refuses the spelling.

The proposal is not a choice of encoding. It is: does section 3.2.2 require the
canonical form of the encoding it already names.

## The vectors

| Fixture | Outcome | What it pins down |
|---|---|---|
| `01-canonical-signature.json` | verified | The signature is spelled canonically: the final character's unused bits are zero. |
| `02-non-canonical-respelling-low-bit.json` | rejected | The same 64 signature bytes, respelled with the final character's unused bits set to binary `0001`: the smallest change that makes the spelling non-canonical. |
| `03-non-canonical-respelling-all-bits.json` | rejected | The same 64 signature bytes again, respelled with the unused bits set to binary `1111`. |

Two rejecting vectors, not one: `tests/test_adequacy_all_sets.py` flags a
boundary covered by a single rejecting vector, because an implementation could
special-case that one bad string and pass without implementing the rule of
checking the unused bits generally. `02` and `03` trip the same rule with two
different bad strings.

All three fixtures carry the same `record`, `trusted_key` and
`decoded_signature_hex`; only `record.signature`'s final character differs
between them. `tests/test_signature_encoding.py` recomputes
`decoded_signature_hex` from the committed bytes rather than trusting the
declaration: it decodes every signature and asserts the raw bytes are equal
across all three, then re-derives which spellings are canonical from first
principles (decode, re-encode without padding, compare) rather than trusting
the `encoding` field either.

`01` reuses the record, trusted key and signature already published at
`examples/verifier-compatibility/01-known-version-verified.json`, so this set
introduces no new signing key. `02` and `03` each change one character of that
same signature; the record each accompanies is otherwise byte-identical.

## Format

```jsonc
{
  "name": "...",
  "description": "...",
  "spec": "trace-v0.2 section 3.2.2, embedded signature bullet",
  "profile": "trace.signature_encoding.proposal.v0",
  "proposal": {
    "issue": "agentrust-io/trace-spec#247",
    "status": "under review, not accepted normative text"
  },
  "encoding": "canonical" | "non_canonical",
  "decoded_signature_hex": "...",           // the 64 bytes all three fixtures share, as hex
  "canonical_counterpart": "...",           // 02 and 03 only: the file each respells
  "trusted_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "record":      { "eat_profile": "...", "signature": "..." },
  "expected": {
    "outcome":  "verified" | "rejected",
    "failure":  null | "signature_not_canonical"
  }
}
```

`expected.failure` is informative, the same convention
[`examples/verifier-compatibility/README.md`](../verifier-compatibility/README.md#what-failure-is-and-is-not)
states: it names which rule the vector expects to bite, not a wire format or an
exception message, and nothing in a portable adapter reads it. The two
implementations measured so far disagree even on which failure class this is:
today, before this proposal, the reference library in this repository decodes
a non-canonical respelling leniently (the unused bits are discarded, not
checked) and verifies it; the TypeScript verifier under review in #376 already
refuses the same spelling, reporting `signature_malformed`. Tightening the
schema pattern, as this proposal does, makes the reference library agree with
that refusal, through the schema-validation path both implementations already
run every record through first, rather than through a new check specific to
this one field.

## Which existing records would stop passing

`scan_published_signatures.py` walks every `*.json` file under a given root,
finds every 86-character `signature` value (the shape of a 64-byte embedded
signature), and reports how many are already canonically encoded. Run without
arguments it scans this repository's own `examples/`:

```bash
python examples/signature-encoding/scan_published_signatures.py
```

Pass additional roots to reproduce a combined count over other checkouts, for
example the `agentrust-io/trace-tests` conformance corpus pinned at a specific
commit, or a read-only clone of `agentrust-io/trace-registry`:

```bash
git clone https://github.com/agentrust-io/trace-tests /path/to/trace-tests
git -C /path/to/trace-tests checkout 3af2b53
python examples/signature-encoding/scan_published_signatures.py \
  examples /path/to/trace-tests

git clone https://github.com/agentrust-io/trace-registry /path/to/trace-registry
python examples/signature-encoding/scan_published_signatures.py /path/to/trace-registry
```

The numbers from one such run, and the exact command that produced them, belong
in the PR that carries this proposal, not in this file: they are a fact about
the corpus on the day the scan ran, not about the vectors themselves. Only
`signature` is scanned, at the top level of a Trust Record. `sig.value` in a
revocation statement or bundle carries the same base64url pattern and the same
open question, but that pattern is untouched by this proposal, so it is outside
this scan's scope; see the PR for that as a candidate follow-up.

## Boundary

These vectors show whether a verifier's schema accepts or refuses a specific
respelling of a real, already-verifying signature. They make no claim about
the record's other fields, about revocation, or about freshness, each of which
is exercised elsewhere in `examples/`.
