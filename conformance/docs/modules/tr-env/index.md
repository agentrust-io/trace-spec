# TR-ENV: Envelope

Checks the outer wrapper of a record and its basic fields: which version of the format it uses, when it was issued, which agent it is about, and the public key used to check its signature. A common cause of failure here is a record made for an older version of TRACE (see [Known limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md)).

Technically, the envelope is an EAT (Entity Attestation Token, an IETF format for signed statements about a system), and these checks cover its top-level structure.

## Required at Level 0+

| Test ID    | Description                                                                 | Positive Case                                         | Negative Case                                                 |
| ---------- | --------------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------- |
| TR-ENV-001 | `eat_profile` present and correct URI                                       | `tag:agentrust-io.com,2026:trace-v0.2`                | missing or wrong                                              |
| TR-ENV-002 | `iat` is a valid Unix timestamp                                             | integer, reasonable range                             | string, future date                                           |
| TR-ENV-003 | `subject` matches SPIFFE URI or DID                                         | `spiffe://trust.example/agent/x` or `did:key:z6Mk...` | bare string                                                   |
| TR-ENV-004 | `cnf.jwk.kty` is present. This is not a gate over the schema's required set | `cnf.jwk.kty` set to any value                        | `cnf` absent, `cnf.jwk` absent or not an object, `kty` absent |
| TR-ENV-005 | `cnf.jwk` carries no private key material                                   | `cnf.jwk` with `kty`/`crv`/`x` only                   | `cnf.jwk` containing `d`, `p`, `q`, `dp`, `dq`, `qi` or `k`   |
