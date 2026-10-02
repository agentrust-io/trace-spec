# TR-SIG — Signature

Tests Ed25519 signature binding on the TRACE Trust Record.

## Required at Level 0+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-SIG-001 | cmcp only: `signature` is present, and the Ed25519 verification outcome | signed cmcp claim | missing or empty `signature`, bit-flipped signature |
| TR-SIG-002 | cmcp only: `cnf.jwk` is an OKP/Ed25519 key carrying `x` | JWK with `kty` OKP, `crv` Ed25519, `x` set | ES256, RS256, missing `x` |
| TR-SIG-004 | `cnf.jwk` carries no private key material, and `cnf.jwk.kty` is a supported key type | JWK with `x` only, `kty` of `OKP` or `EC` | JWK with `d` present, missing `kty`, `RSA` |
| TR-SIG-005 | The signature check outcome: verified, unverifiable, not checked, or absent | valid Ed25519 signature | bit-flipped signature, no signature, JWK carrying `d` |
