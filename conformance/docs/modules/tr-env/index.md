# TR-ENV — Envelope

Tests the top-level EAT envelope structure of a TRACE Trust Record.

## Required at Level 0+

| Test ID    | Description                                                                 | Positive Case                                         | Negative Case                                                 |
| ---------- | --------------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------- |
| TR-ENV-001 | `eat_profile` present and correct URI                                       | `tag:agentrust-io.com,2026:trace-v0.2`                | missing or wrong                                              |
| TR-ENV-002 | `iat` is a valid Unix timestamp                                             | integer, reasonable range                             | string, future date                                           |
| TR-ENV-003 | `subject` matches SPIFFE URI or DID                                         | `spiffe://trust.example/agent/x` or `did:key:z6Mk...` | bare string                                                   |
| TR-ENV-004 | `cnf.jwk.kty` is present. This is not a gate over the schema's required set | `cnf.jwk.kty` set to any value                        | `cnf` absent, `cnf.jwk` absent or not an object, `kty` absent |
| TR-ENV-005 | `cnf.jwk` carries no private key material                                   | `cnf.jwk` with `kty`/`crv`/`x` only                   | `cnf.jwk` containing `d`, `p`, `q`, `dp`, `dq`, `qi` or `k`   |
