# TR-ENV: Envelope

Checks the outer wrapper of a record and its basic fields: which version of the format it uses, when it was issued, which agent it is about, and the public key used to check its signature. A common cause of failure here is a record made for an older version of TRACE (see [Known limitations](../../LIMITATIONS.md)).

Technically, the envelope is an EAT (Entity Attestation Token, an IETF format for signed statements about a system), and these checks cover its top-level structure.

## Required at Level 0+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-ENV-001 | `eat_profile` present and correct URI | `tag:agentrust-io.com,2026:trace-v0.2` | missing or wrong |
| TR-ENV-002 | `iat` is a valid Unix timestamp | integer, reasonable range | string, future date |
| TR-ENV-003 | `subject` matches SPIFFE URI or DID | `spiffe://trust.example/agent/x` or `did:key:z6Mk...` | bare string |
| TR-ENV-004 | `cnf.jwk.kty` is present. TR-ENV-006 checks the rest of the required set | `cnf.jwk.kty` set to any value | `cnf` absent, `cnf.jwk` absent or not an object, `kty` absent |
| TR-ENV-005 | `cnf.jwk` carries no private key material | `cnf.jwk` with `kty`/`crv`/`x` only | `cnf.jwk` containing `d`, `p`, `q`, `dp`, `dq`, `qi` or `k` |
| TR-ENV-006 | Every field the spec requires (3.1) is present: `eat_profile`, `iat`, `subject`, `model`, `runtime`, `policy`, `data_class`, `build_provenance`, `appraisal`, `cnf` | all present | any of them absent or `null` |
