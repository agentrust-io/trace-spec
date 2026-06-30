# Sign Your First Trust Record

Generate an Ed25519 signing key and produce a signed TRACE Trust Record that any verifier can check offline.

## What you'll learn

- How to generate a signing key and export its public JWK
- Which fields a minimal valid TrustRecord requires
- How `sign_record()` constructs the signature and embeds `cnf.jwk`
- Why RFC 8785 JCS canonical form matters and how the library handles it
- How to verify the signed record with `verify_record()`

## Prerequisites

```bash
pip install agentrust-trace
```

---

## Generate a Key

`generate_key()` returns an `Ed25519PrivateKey` from the `cryptography` library. Keep the private key secret. Distribute only the public half.

```python
from agentrust_trace import generate_key, key_to_jwk

key = generate_key()
jwk = key_to_jwk(key)
print(jwk)
# {'kty': 'OKP', 'crv': 'Ed25519', 'x': '<base64url-encoded public key>'}
```

`key_to_jwk()` returns the public JWK dict in OKP format (RFC 8037). This is the value that will appear in `cnf.jwk` on every record you sign with this key.

For production use, persist the private key and load it via the `TRACE_PRIVATE_KEY_PEM` environment variable:

```python
from agentrust_trace import load_signing_key

# Reads TRACE_PRIVATE_KEY_PEM if set, otherwise generates an ephemeral key
# (ephemeral keys emit a warning and cannot be re-verified after the process exits)
key = load_signing_key()
```

---

## Construct a Minimal TrustRecord

Every TRACE Trust Record requires these top-level fields. There are no optional shortcuts for a conformant record.

```python
import time

record = {
    "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
    "iat": int(time.time()),
    "subject": "spiffe://trust.example.org/agent/my-agent",
    "model": {
        "provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
        "version": "20251001",
    },
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "0" * 64,
    },
    "policy": {
        "bundle_hash": "sha256:b2c3d4e5f6a7b8c9" + "0" * 48,
        "enforcement_mode": "enforce",
    },
    "data_class": "internal",
    "build_provenance": {
        "slsa_level": 1,
        "digest": "sha256:e5f6a7b8c9d0e1f2" + "0" * 48,
    },
    "appraisal": {
        "status": "none",
        "verifier": "https://verifier.example.org",
    },
    "transparency": "https://registry.agentrust.io/claim/placeholder",
}
```

A few constraints to keep in mind:

- `subject` must be a SPIFFE URI (`spiffe://...`) or a DID URI (`did:...`).
- `measurement` must be a `sha256:` or `sha384:` digest string. For `software-only` development records, all-zero digests are conventional.
- `enforcement_mode` must be `"enforce"`, `"advisory"`, or `"silent"`. Omitting the field is not valid.
- `appraisal.status` of `"none"` is correct for software-only Level 0 records. Use `"affirming"` for hardware-attested records.

---

## Sign the Record

Pass the record dict and the private key to `sign_record()`. It returns a new dict with two additional fields: `cnf.jwk` (populated from the key) and `signature`.

```python
from agentrust_trace import sign_record

signed = sign_record(record, key)

print(signed["cnf"]["jwk"])   # {'kty': 'OKP', 'crv': 'Ed25519', 'x': '...'}
print(signed["signature"])    # base64url string, no padding
```

The signature covers every field in the record except `signature` itself. `cnf.jwk` is included in the signed payload, which binds the public key to the record content.

---

## What the Signature Covers

The library signs the canonical byte representation of the record with the `signature` field removed. Canonicalization follows RFC 8785 JSON Canonicalization Scheme (JCS):

- Object keys sorted in UTF-16 code-unit order (ascending)
- No whitespace between tokens
- Numbers serialized in IEEE 754 double-precision shortest round-trip form (RFC 8785 §3.2.2.3)
- Strings emitted as raw UTF-8, escaping only the characters RFC 8259 §7 requires

`_canonical_bytes()` is implemented with the RFC 8785-conformant [`rfc8785`](https://pypi.org/project/rfc8785/) library. `json.dumps(record, sort_keys=True, ensure_ascii=True)` is **not** a substitute: it escapes non-ASCII characters as `\uXXXX`, zero-pads number exponents (`1e-07` vs JCS `1e-7`), and sorts by Unicode code point rather than UTF-16 code unit. Any of these would break cross-implementation verification and allow signature-preserving mutation, so the library is used in both signing and verification.

The spec (section 3.2.2) requires JCS canonical form. Do not reimplement this by hand.

---

## Verify the Signed Record

`verify_record()` requires a trusted key, recomputes the canonical bytes, and checks the Ed25519 signature. It raises `cryptography.exceptions.InvalidSignature` if the record was tampered with, and returns `None` on success. Pass the public JWK of the key you trust — here, the `jwk` from earlier in the tutorial.

```python
from agentrust_trace import verify_record
from cryptography.exceptions import InvalidSignature

try:
    verify_record(signed, jwk)  # jwk is the public key you trust
    print("signature valid")
except InvalidSignature:
    print("tampered — do not trust this record")
```

To confirm that tampered records are rejected:

```python
import copy

tampered = copy.deepcopy(signed)
tampered["data_class"] = "public"  # change a field after signing

try:
    verify_record(tampered, jwk)
except InvalidSignature:
    print("correctly rejected")  # this branch runs
```

---

## Validate the Schema

Signature verification and schema validation are separate steps. A record can have a valid signature but still violate the JSON Schema (for example, a malformed digest string). Call `validate_json()` to check conformance:

```python
from agentrust_trace import validate_json
import jsonschema

try:
    validate_json(signed)
    print("schema valid")
except jsonschema.ValidationError as e:
    print(e.message)
```

For all violations at once instead of failing on the first:

```python
from agentrust_trace import iter_errors

errors = iter_errors(signed)
for e in errors:
    print(e.message)
```

---

## Summary

You generated an Ed25519 key, built a minimal TRACE Trust Record, signed it with `sign_record()`, and verified it with `verify_record()`. The signature covers all fields except `signature` itself, canonicalized via RFC 8785 JCS. The `cnf.jwk` field embeds the public key so any verifier can check the record offline without a separate key distribution step.

Next steps:

- [Verify a trust record received from a third party](verifying-a-trust-record.md)
- [Hardware attestation platforms](hardware-attestation-platforms.md)
