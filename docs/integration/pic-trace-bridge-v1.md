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
`transcript_required` is true, a complete `before` and `after` transcript is
required. `before.tool_call` must equal the executed call, and `after` must be
the successor-observation envelope whose RFC 8785 / SHA-256 digest equals the
signed `authorization.successor_observation_digest`. Because that digest is
inside the signed authorization, a caller cannot substitute both a new
observation and a matching expected digest. This binds the authorization to the
exact call and exact successor envelope without claiming that TRACE proves the
real-world outcome of the call.

### Successor-observation binding

When `transcript_required` is true, `transcript.after` is the successor envelope and
has exactly three fields:

~~~json
{
  "observation": {"application": "defined"},
  "observer": "observer-identity",
  "observed_at": 1750000000
}
~~~

The bridge identity relation is the SHA-256 digest of the RFC 8785 canonical bytes of
that complete envelope. The expected digest is carried in the signed
`authorization.successor_observation_digest`; it is not supplied independently by the
caller. The binding therefore covers the observation content, observer identity, and
observation timestamp together. Relabelling a genuine observation to a
different observer, retiming it, or altering its content changes the binding.

A matching binding establishes **integrity**, not **sufficiency**. It does not by itself
establish that the requested transition occurred. A verifier evaluating a successor
claim separately applies its configured trust, freshness, and observation-source
policy and then an application- or profile-defined transition predicate.

The successor-evaluation surface has three evidence outcomes:

- `established`: trusted, bound successor evidence satisfies the transition predicate;
- `contradicted`: trusted, bound successor evidence contradicts the transition predicate;
- `not-established`: the available evidence is absent or insufficient to justify
  either conclusion.

Malformed successor artifacts and binding failures are refusals, not a fourth evidence
outcome. At the bridge layer, an absent `after` is a refusal when
`transcript_required` is true because the signed authorization explicitly requires the
successor binding. At the separate successor-evaluation surface, where an observation may
be absent before bridge verification is attempted, absence remains
`not-established` and never becomes a positive conclusion.

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

The reference implementation is `agentrust_trace.intent_bridge`; the versioned
schema is `schema/pic-trace-bridge-v1.json`.

## Failure semantics

Malformed or unverifiable artifacts raise `IntentBridgeError`. A signed deny
raises `AuthorizationDenied`. A valid authorization whose scope, digest, or
transcript does not match the execution raises `AuthorizationMismatch`.
Consumers must fail closed when the profile is required and any of these
conditions occurs.
