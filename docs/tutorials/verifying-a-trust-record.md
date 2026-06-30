# Verify a Trust Record

Check the integrity and schema conformance of a TRACE Trust Record you received from a third party, and decide whether to trust the agent session it describes.

## What you'll learn

- What `verify_record()` does internally, step by step
- How to verify against a pinned trusted key instead of the embedded key
- How to run schema validation separately from signature verification
- How to collect all validation errors with `iter_errors()`
- How to interpret `runtime.platform` to distinguish development from hardware-attested records
- What to do when verification fails

## Prerequisites

```bash
pip install agentrust-trace
```

---

## Understand What verify_record() Does

When you call `verify_record(record, trusted_key)` the library:

1. Reads `record["signature"]` and base64url-decodes it to raw bytes
2. Resolves the trusted key you supplied, checking `kty == "OKP"` and `crv == "Ed25519"` before reconstructing an `Ed25519PublicKey` from the `x` field
3. Enforces freshness: rejects records whose `iat` is older than `max_age_seconds` (default 24h), and, if you pass `expected_nonce`, compares it in constant time to `runtime.nonce`
4. Rebuilds the canonical payload: all fields except `signature`, serialized with sorted keys and no whitespace
5. Calls `Ed25519PublicKey.verify(sig_bytes, payload_bytes)` from the `cryptography` library
6. Returns `None` on success, raises `cryptography.exceptions.InvalidSignature` on a bad signature and `ValueError` on every other rejection

A trusted key is required. A record cannot authenticate itself with the key it embeds, so `verify_record` will not fall back to `cnf.jwk` unless you explicitly opt in with `allow_embedded_key=True` (which emits a `UserWarning`, since it proves only internal consistency, not authenticity).

```python
import json
from agentrust_trace import verify_record
from cryptography.exceptions import InvalidSignature

with open("session.trace.json") as f:
    record = json.load(f)

# trusted_jwk obtained out-of-band (see "Verify Against a Pinned Public Key" below)
try:
    verify_record(record, trusted_jwk)
    print("signature valid")
except InvalidSignature:
    print("signature invalid — record may have been tampered with")
except ValueError as e:
    print(f"verification failed: {e}")
```

`ValueError` is raised when no trusted key is supplied, the record is missing a `signature` field, a key or signature cannot be decoded, the JWK type is not Ed25519, or the record is stale. Treat all of these as verification failure.

---

## Verify Against a Pinned Public Key

The embedded `cnf.jwk` proves the record was not tampered with after signing. It does not prove the key is one you should trust. For stricter verification, supply your own trusted public key as the second argument.

Pass either an `Ed25519PublicKey` object or a JWK dict you obtained out-of-band (for example, from the issuer's published key manifest):

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64

# Trusted JWK obtained from the issuer's key directory
trusted_jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<base64url public key bytes>",
}

# verify_record accepts a JWK dict directly
verify_record(record, trusted_jwk)
```

Or with an `Ed25519PublicKey` object:

```python
x_bytes = base64.urlsafe_b64decode(trusted_jwk["x"] + "==")
pub_key = Ed25519PublicKey.from_public_bytes(x_bytes)

verify_record(record, pub_key)
```

When you supply a key, the library uses it instead of `cnf.jwk`. If the record was signed with a different key, `InvalidSignature` is raised.

---

## Validate the Schema

Signature verification confirms the record was not modified after signing. It says nothing about whether the record conforms to the TRACE v0.1 schema. A valid signature over a malformed record is still a malformed record.

Call `validate_json()` to check schema conformance. It raises `jsonschema.ValidationError` on the first violation:

```python
from agentrust_trace import validate_json
import jsonschema

try:
    validate_json(record)
except jsonschema.ValidationError as e:
    print(f"schema violation: {e.message}")
    print(f"at path: {list(e.absolute_path)}")
```

To collect all violations at once instead of stopping at the first:

```python
from agentrust_trace import iter_errors

errors = iter_errors(record)
if errors:
    for e in errors:
        print(f"{list(e.absolute_path)}: {e.message}")
else:
    print("schema valid")
```

Run schema validation before trusting any claims in the record. A record that passes both `verify_record()` and `validate_json()` was signed by the stated key and has a well-formed structure.

---

## Check the EAT Profile

Every TRACE record carries an `eat_profile` field that identifies the spec version. Reject records with an unexpected profile before parsing their claims:

```python
EXPECTED_PROFILE = "tag:agentrust.io,2026:trace-v0.1"

if record.get("eat_profile") != EXPECTED_PROFILE:
    raise ValueError(f"unexpected eat_profile: {record.get('eat_profile')!r}")
```

---

## Interpret the Appraisal Status

After verifying the signature and schema, read `appraisal.status`:

```python
status = record["appraisal"]["status"]

if status == "affirming":
    # All evidence passed appraisal. Safe to act on the session output.
    pass
elif status == "warning":
    # Evidence passed with conditions. Review before acting.
    pass
elif status == "contraindicated":
    # Evidence failed. Treat the session output as untrusted.
    raise RuntimeError("appraisal contraindicated — do not process agent output")
elif status == "none":
    # No appraisal performed (software-only Level 0 record).
    # Acceptable for development; not acceptable for production.
    pass
```

---

## Distinguish Software-Only from Hardware-Attested Records

The `runtime.platform` field tells you the attestation root. Before trusting a record in a production context, confirm it is not a development record:

```python
runtime = record["runtime"]

if runtime["platform"] == "software-only":
    # All-zero measurement, no TEE binding. Only accept in dev/test.
    raise ValueError("software-only records are not accepted in production")

# Hardware-attested platforms
HARDWARE_PLATFORMS = {
    "intel-tdx",
    "amd-sev-snp",
    "nvidia-h100",
    "nvidia-blackwell",
    "aws-nitro",
    "arm-cca",
    "google-confidential-space",
    "tpm2",
}

if runtime["platform"] not in HARDWARE_PLATFORMS:
    raise ValueError(f"unknown platform: {runtime['platform']!r}")

print(f"platform: {runtime['platform']}")
print(f"measurement: {runtime['measurement']}")
```

For hardware-attested records, `runtime.measurement` is a real digest from the TEE. To confirm the key was generated inside the attested enclave, compare `runtime.measurement` against the published Reference Integrity Manifest at `runtime.rim_uri`. See [Hardware attestation platforms](hardware-attestation-platforms.md) for per-platform details.

---

## Complete Verification Sequence

Put it together for a production verifier:

```python
import json
from agentrust_trace import verify_record, validate_json, iter_errors
from cryptography.exceptions import InvalidSignature
import jsonschema

def verify_trust_record(path: str, trusted_jwk: dict) -> dict:
    with open(path) as f:
        record = json.load(f)

    # 1. Schema validation first — reject malformed records early
    errors = iter_errors(record)
    if errors:
        messages = [e.message for e in errors]
        raise ValueError(f"schema violations: {messages}")

    # 2. Signature verification
    try:
        verify_record(record, trusted_jwk)
    except InvalidSignature:
        raise RuntimeError("signature invalid — record tampered or wrong key")
    except ValueError as e:
        raise RuntimeError(f"record malformed: {e}")

    # 3. Profile check
    if record.get("eat_profile") != "tag:agentrust.io,2026:trace-v0.1":
        raise ValueError(f"unexpected eat_profile: {record.get('eat_profile')!r}")

    # 4. Appraisal
    status = record["appraisal"]["status"]
    if status == "contraindicated":
        raise RuntimeError("appraisal contraindicated — do not process agent output")

    return record
```

---

## What to Do When Verification Fails

If `verify_record()` raises `InvalidSignature`:

- Do not process the agent output.
- Do not rely on any claim in the record.
- Log the failure with the record's `subject` and `iat` fields for audit purposes.
- Investigate whether the record was modified in transit or the wrong key was used.

A failed signature means either the record was tampered with after issuance, or it was not signed by the key in `cnf.jwk`. Either way, the record cannot be trusted.

---

## Summary

You verified a TRACE Trust Record by checking its Ed25519 signature, validating its schema, and interpreting the appraisal status. Signature verification uses the embedded `cnf.jwk` by default; pass a trusted key to pin verification to a specific issuer. Schema validation with `validate_json()` or `iter_errors()` is a separate step that confirms the record structure is well-formed.

Related tutorials:

- [Sign your first trust record](signing-your-first-trust-record.md)
- [Hardware attestation platforms](hardware-attestation-platforms.md)
- [Integration with cMCP](integrating-with-cmcp.md)
