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
exception message, and nothing in a portable adapter reads it. The
implementations measured so far do not share a failure class for it. Through
0.10.0 the reference library in this repository decoded a non-canonical
respelling leniently (the unused bits were discarded, not checked) and verified
it. Since 0.11.0 its decoder refuses the spelling (#418), and `verify_record`
reports that refusal before it reaches the schema step. The TypeScript verifier
under review in #376 refuses the same spelling and reports
`signature_malformed`. Tightening the schema pattern, as this proposal does,
adds the refusal to the two surfaces that never decode the value: schema
validation and the models. A consumer that only validates a record then gets
the same answer as one that verifies it.

## Classification

An incompatible tightening of the draft's acceptance rules: a record the
previous rules accepted can be rejected under this one. The maintainer set the
class on [#401](https://github.com/agentrust-io/trace-spec/pull/401).

## Which spellings are newly rejected

Only an 86-character `signature`, the length of a 64-byte Ed25519 or ES256
signature. Its final character carries 2 signed bits and 4 unused ones, so each
signature has 16 spellings: one canonical, ending in `A`, `Q`, `g` or `w`, and 15
that end in one of the other 60 base64url characters. The previous pattern,
`^[A-Za-z0-9_-]+$`, accepted all 16. The reference library verified all 16
through 0.10.0, because its decoder discarded the unused bits, and has refused
the 15 at decode time since 0.11.0 (#418). The new pattern accepts the
canonical one only, so the schema and the models refuse the 15 as well. A
value of any other length is matched exactly as before;
a 96-byte ES384 signature spends 128 characters on 768 bits and has no unused
bits to set.

## Handling existing records

A record whose `signature` is non-canonical is rejected, with no grace period
in this proposal. Its signature bytes are not in question, so the holder can
zero the final character's unused bits and the record verifies again without
re-signing. The respelled record is still a different record under section
3.1.3: `delegation.parent_record_hash` is computed over the complete parent
record including its `signature` member, so a child that names the old
spelling no longer matches, and has to be re-issued against the new one.

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
the revisions scanned on the day the scan ran, not about the vectors themselves,
and a count of canonical signatures in those revisions says nothing about
records minted elsewhere. Only
`signature` is scanned, at the top level of a Trust Record. `sig.value` in a
revocation statement or bundle carries the same base64url pattern. The
library's decoder has refused a non-canonical spelling of a bundle's
`sig.value` since #418; the schema pattern is untouched by this proposal, so
it is outside this scan's scope; see the PR for that as a candidate follow-up.

## Boundary

These vectors show whether a verifier's schema accepts or refuses a specific
respelling of a real, already-verifying signature. They make no claim about
the record's other fields, about revocation, or about freshness, each of which
is exercised elsewhere in `examples/`.
