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
required, and `before.tool_call` must equal the executed call. This binds the
authorization to the call and its execution evidence without claiming that
TRACE proves the real-world outcome of the call.

The reference implementation is `agentrust_trace.intent_bridge`; the versioned
schema is `schema/pic-trace-bridge-v1.json`.

## Failure semantics

Malformed or unverifiable artifacts raise `IntentBridgeError`. A signed deny
raises `AuthorizationDenied`. A valid authorization whose scope, digest, or
transcript does not match the execution raises `AuthorizationMismatch`.
Consumers must fail closed when the profile is required and any of these
conditions occurs.
