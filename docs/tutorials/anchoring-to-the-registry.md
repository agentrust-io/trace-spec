# Anchoring a Trust Record to the TRACE registry

After signing a Trust Record, you should anchor it to the TRACE transparency registry. The anchor receipt proves that the record existed at a specific time and has not been altered since — tamper evidence that holds even if the operator who produced the record is later compromised.

**What you need:** A signed Trust Record (from [Signing your first trust record](signing-your-first-trust-record.md)).

**What you'll do:** Submit the record to the registry, receive a SCITT receipt, and set the `transparency` field to the canonical receipt URI.

---

## Why transparency anchoring matters

A Trust Record carries a signature from the issuer's key. A verifier holding that key can confirm the record has not been modified — but only if the key is trustworthy. If the issuer is later compromised, an attacker could forge records backdated to before the compromise.

The `transparency` field solves this with a different trust root: an append-only log operated by an independent party. Once a record is registered, its content is fixed in the log at that timestamp. A verifier checks that the record's digest matches the log entry — no trust in the operator required.

TRACE uses SCITT ([draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)) as its transparency log substrate.

---

## The `transparency` field

In the `TrustRecord` schema, `transparency` is a required string:

```python
transparency: Annotated[str, Field(min_length=1)]
```

It holds the canonical URI of the registry entry — the URL at which any verifier can independently retrieve the SCITT receipt and confirm the record's inclusion.

Example value from the spec:

```
https://registry.agentrust.io/claim/trace-2026-06-23T09:15:42Z-f2a8d1
```

---

## Step 1 — Build and sign the record with a placeholder

During development, use a placeholder for `transparency` so you can construct and sign a valid record before anchoring:

```python
import time
from agentrust_trace.sign import generate_key, sign_record

key = generate_key()

record = {
    "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
    "iat": int(time.time()),
    "subject": "spiffe://example.org/agent/my-agent",
    "model": {
        "provider": "anthropic",
        "model_id": "claude-sonnet-4-6",
    },
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "0" * 64,
    },
    "policy": {
        "bundle_hash": "sha256:" + "a" * 64,
        "enforcement_mode": "enforce",
    },
    "data_class": "internal",
    "build_provenance": {
        "slsa_level": 0,
        "digest": "sha256:" + "b" * 64,
    },
    "appraisal": {
        "status": "none",
        "verifier": "self",
    },
    # Placeholder — replace after anchoring
    "transparency": "pending",
}

signed = sign_record(record, key)
```

!!! note
    `transparency: "pending"` is valid for local development. Production records MUST carry a real receipt URI before being handed to a verifier that enforces §3.3 step 6.

---

## Step 2 — Submit to the registry

!!! info "No SDK client yet"
    The `agentrust_trace` SDK does not yet include a registry client. Submit directly via HTTP using the SCITT Reference API ([draft-ietf-scitt-scrapi](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/)). A Python client will be added to the SDK in a future release.

Submit the signed record as a SCITT Signed Statement:

```python
import json
import requests  # pip install requests

REGISTRY_URL = "https://registry.agentrust.io"

response = requests.post(
    f"{REGISTRY_URL}/entries",
    headers={"Content-Type": "application/json"},
    data=json.dumps(signed),
    timeout=30,
)
response.raise_for_status()

entry = response.json()
# entry contains the registry-assigned receipt URI
receipt_uri = entry["receipt_uri"]
print(f"Anchored: {receipt_uri}")
```

The registry returns a JSON object with at minimum:

| Field | Description |
|---|---|
| `receipt_uri` | Canonical URL of the SCITT receipt — use this as `transparency` |
| `entry_id` | Registry-internal identifier for the log entry |
| `registered_at` | ISO 8601 timestamp of registration |

---

## Step 3 — Set `transparency` and re-sign

Replace the placeholder and re-sign the record with the real receipt URI:

```python
record["transparency"] = receipt_uri
signed_final = sign_record(record, key)
```

The signature now covers the real `transparency` value. A verifier who later retrieves the receipt from `receipt_uri` can confirm the digest matches — without contacting the original operator.

---

## Step 4 — Verify the receipt (optional, recommended)

To confirm the registry accepted the record correctly, retrieve and inspect the receipt:

```python
receipt_resp = requests.get(receipt_uri, timeout=30)
receipt_resp.raise_for_status()
receipt = receipt_resp.json()

# The receipt contains the log entry digest and a Merkle inclusion proof.
# Check that it references your record's content.
assert receipt["subject"] == signed_final["subject"]
assert receipt["iat"] == signed_final["iat"]
```

A full cryptographic Merkle proof verification is not yet in the SDK. The registry exposes the raw proof fields for implementers who want to verify inclusion independently.

---

## Verification step 6

When a verifier calls `verify_record()`, it checks the signature. Step 6 of the TRACE verification procedure (spec §3.3) additionally requires the transparency receipt to resolve:

> SCITT receipt resolves on the named transparency log.

A verifier configured with `require_transparency: true` will retrieve `transparency` and check the digest against the log. Verifiers that skip this step accept a weaker guarantee — signature-only, not log-anchored.

---

## Summary

| Step | What happens |
|---|---|
| Build record with `"pending"` | Valid locally, not for production hand-off |
| POST to registry | SCITT log records the digest at this timestamp |
| Replace `transparency`, re-sign | Signature now covers the real receipt URI |
| Verifier retrieves receipt URI | Tamper evidence independent of operator trust |
