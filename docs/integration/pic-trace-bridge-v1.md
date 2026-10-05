# PIC/TRACE authorization bridge v1

This informative profile binds a separately authorized pre-execution decision to
the TRACE evidence for the execution that followed it. It is an optional bridge;
it does not make PIC a dependency of TRACE and it does not change the TRACE
Trust Record schema.

## Trust boundary

The bridge is a detached authorization artifact signed by an authorizer key
resolved by the verifier's trust configuration. The artifact contains an
`authorizer_key_id`, which must match the trusted JWK's `kid`; the artifact
never carries a public key or trust anchor. A plugin, runtime, or gateway cannot
bootstrap its own authority by embedding a key in the signed object.

The signature covers `profile` and the complete `authorization` object.
Unknown fields are rejected so an implementation cannot silently ignore a new
security meaning. `authorized_at` and `expires_at` are bounded to the JCS
safe-integer range for the same reason every integer in a signed TRACE object
is: the signature is over RFC 8785 canonical bytes, and outside that range two
distinct values share a pre-image and therefore a signature. See spec section
3.2.2. A decision other than `allow`, an authorization outside its validity
window, an expired authorization, or an invalid signature is not usable as
authorization evidence.

## Binding rules

The `pic` member preserves PIC-CJSON/1.0's `intent_digest` and `args_digest`
values. The bridge does not recompute those PIC digests; it compares the values
provided by the PIC verifier. Bridge-specific `declaration_digest` and
`tool_call_digest` are SHA-256 over RFC 8785/JCS bytes of the corresponding JSON
objects.

The verifier checks that the executed tool is in `scope.tools`, the declaration
impact is in `scope.impacts`, and both bridge-specific digests match. If
`transcript_required` is true, the bridge requires the pre-execution/dispatch
`before` transcript and `before.tool_call` must equal the executed call.

Successor evidence is deliberately not carried in the pre-execution authorization.
Evidence that can only exist after execution must not be required as an authenticated
input to the artifact relied on as pre-execution authorization. Instead, the observer
creates a separate post-execution successor artifact. That artifact binds the
`authorization_id` to the RFC 8785 / SHA-256 digest of the exact successor envelope
and authenticates the binding with the observer key.

This gives the lifecycle:

~~~text
sign pre-execution authorization
        ↓
execute
        ↓
observe successor
        ↓
sign successor artifact(authorization_id + exact-envelope digest)
~~~

The two signatures establish different facts and are verified separately. A caller
cannot move post-execution knowledge backward into the authorization artifact, and a
successor artifact naming another authorization is rejected.

### PIC digest values at the bridge boundary

PIC gives both values as 64 lowercase hexadecimal characters, and computes them
differently: PIC Canonical JSON v1 section 8.1 digests the canonical bytes of
`action.args`, while section 8.3 digests the UTF-8 bytes of the `intent` string with no
JSON wrapping, escaping, or canonicalization. This bridge preserves whichever values the
PIC verifier produced and does not recompute either one.

What differs at the boundary is the representation. `schema/pic-trace-bridge-v1.json`
constrains both fields through the `$defs/digest` it uses for every digest it carries,
`^sha256:[0-9a-f]{64}$`, so an adapter serializes the PIC verifier's output as
`sha256:<pic_hex>`, on the bridge artifact and on the values handed to the reference
implementation alike. A bare hex value is refused by `agentrust_trace.intent_bridge`,
which reports `authorization.pic.intent_digest must be a sha256 digest` for the artifact
and `intent_digest must be a sha256 digest` for the argument.

The prefix is a TRACE serialization of the same digest value. It is not a change to the
PIC definition, and a consumer comparing across the boundary compares the hexadecimal
that PIC defines.

### Successor-observation binding

After execution, the observer may produce a successor envelope with exactly three
fields:

~~~json
{
  "observation": {"application": "defined"},
  "observer": "observer-identity",
  "observed_at": 1750000000
}
~~~

The bridge identity relation is the SHA-256 digest of the RFC 8785 canonical bytes of
that complete envelope. The expected digest is carried in the separately signed
post-execution successor artifact, together with `authorization_id`, `observer`,
`observer_key_id`, and `observed_at`. The verifier checks the successor signature,
the exact authorization identifier, and the digest against the separately supplied
envelope. The signed observer and observation time must also match the envelope.
The verifier is given the trusted observer key together with the observer identity
that key belongs to, and the signed observer must equal that identity. The identity
comes from the verifier's own key configuration, never from the artifact or the
envelope, which the signer wrote. The trust and independence policy below decides on
the observer's name, so a key accepted for one observer must not be able to sign under
another observer's name.

The binding therefore covers the observation content, observer identity, and
observation timestamp together without requiring any of them to exist before
execution. Relabelling a genuine observation to a different observer, retiming it,
altering its content, or attaching it to another authorization breaks verification.

A matching binding establishes **integrity**, not **sufficiency**. It does not by itself
establish that the requested transition occurred. A verifier evaluating a successor
claim separately applies its configured trust, freshness, and observation-source
policy and then an application- or profile-defined transition predicate.

The successor-evaluation surface has three evidence outcomes:

- `established`: trusted, bound successor evidence satisfies the transition predicate;
- `contradicted`: trusted, bound successor evidence contradicts the transition predicate;
- `not-established`: the available evidence is absent or insufficient to justify
  either conclusion.

Malformed successor artifacts, invalid observer signatures, observer names that are not
the trusted key's identity, authorization-id mismatches, and exact-envelope binding
failures are refusals, not a fourth evidence outcome. The
pre-execution bridge does not require an `after` object and therefore can be verified
before successor evidence exists. At the separate successor-evaluation surface, absence
remains `not-established` and never becomes a positive conclusion.

Observation independence is policy, not a universal rule. Where verifier policy
requires an observer independent of the executing principal, executor-supplied
successor evidence alone is insufficient and yields `not-established`. Where the
applicable policy permits deterministic local evidence, the same-principal observation
is not rejected merely because observer and executor are equal.

A successful successor binding permits the verifier to conclude only that it is
evaluating the exact bound observation envelope and, after policy evaluation, that the
envelope's source/freshness/trust properties are acceptable. A transition-level
positive conclusion additionally requires the defined predicate over the relevant
predecessor, action/execution, and successor evidence. A bound `after` object alone
does not prove a real-world outcome.

The surface-local three-state result is an instance of the evidence discipline tracked
in #279; it does not introduce a repository-wide status enum.

The reference implementation is `agentrust_trace.intent_bridge`. The versioned
pre-execution authorization schema is `schema/pic-trace-bridge-v1.json`; the
post-execution observer binding is `schema/pic-trace-successor-v1.json`.

## Failure semantics

Malformed or unverifiable artifacts raise `IntentBridgeError`. A signed deny
raises `AuthorizationDenied`. A valid authorization whose scope, digest, or
transcript does not match the execution raises `AuthorizationMismatch`.
Consumers must fail closed when the profile is required and any of these
conditions occurs.

## References

PIC is the source of authority for `PIC-CJSON/1.0`, `intent_digest` and `args_digest`:
this bridge consumes those values and does not define them. It also compares a declaration's
`impact` against the signed `scope.impacts`, and constrains neither to a vocabulary, so an
integrator aligning with PIC's declaration semantics takes them from PIC's glossary below rather
than from this document.

- PIC Standard: <https://github.com/pic-standard/pic-standard>
- PIC Canonical JSON v1 (`PIC-CJSON/1.0`), the canonicalization and digest profile this
  bridge names:
  <https://github.com/pic-standard/pic-standard/blob/main/docs/canonicalization.md>.
  Section 8 gives the digest byte rules for `intent_digest` and `args_digest`.
- PIC vocabulary, the glossary PIC asks downstream specifications to cite rather than
  recoin, and which names a source for each term:
  <https://github.com/pic-standard/pic-standard/blob/main/docs/vocabulary.md>
- How this bridge carries those values:
  [`schema/pic-trace-bridge-v1.json`](../../schema/pic-trace-bridge-v1.json)
- TRACE v0.2 specification, section 3.2.2, for the canonical bytes this profile signs
  over: [`spec/trace-v0.2.md`](../../spec/trace-v0.2.md)
- Origin issue: <https://github.com/agentrust-io/trace-spec/issues/361>
