# Verifying the tool call transcript

A TRACE Trust Record commits the evidence of every tool call by hash. This tutorial explains what the `tool_transcript` field contains, how to verify that a received record's transcript hash is consistent with the actual tool calls, and how external execution receipts extend the chain.

**What you need:** A Trust Record with a `tool_transcript` field, the matching transcript file, and the issuer's public key.

---

## What `tool_transcript` captures

The `tool_transcript` field in `TrustRecord` has three fields:

```python
class ToolTranscript(BaseModel):
    hash: DigestStr          # sha256 or sha384 digest of all tool call content
    call_count: int | None   # number of calls in this session (optional)
    transcript_uri: str | None  # where the full transcript can be retrieved
```

`hash` is the binding between the Trust Record (which is signed) and the full transcript (which is stored externally). When the Trust Record signature verifies, the `hash` inside it is signed. When the hash matches the transcript you retrieve from `transcript_uri`, you know the transcript has not been altered since the record was signed.

The full transcript is NOT embedded in the Trust Record — it lives at `transcript_uri`. This keeps records small enough to sign and transmit while still committing all call-level evidence.

---

## Step 1 — Retrieve and verify the record signature

Start by checking the Trust Record signature with the issuer's public key:

```python
from agentrust_trace.sign import verify_record, load_key

with open("issuer_pub.pem", "rb") as f:
    public_key = load_key(f.read())

with open("trust_record.json") as f:
    import json
    record = json.load(f)

result = verify_record(record, public_key_or_jwk=public_key)
# raises agentrust_trace.exceptions.VerificationError on failure
# returns True on success
```

`verify_record` confirms that the signed content of the record has not been altered. This includes the `tool_transcript.hash` field — if the signature is valid, you have a trusted copy of the hash.

---

## Step 2 — Retrieve the transcript

The full transcript lives at `tool_transcript.transcript_uri`. Retrieve it and hold the raw bytes for hashing:

```python
import requests

transcript_uri = record["tool_transcript"]["transcript_uri"]
response = requests.get(transcript_uri, timeout=30)
response.raise_for_status()

# Hold raw bytes — hash must be computed over the exact bytes served
transcript_bytes = response.content
```

!!! warning "Hash bytes, not parsed content"
    The `tool_transcript.hash` is computed over the raw bytes of the transcript as stored. Do not decode, re-encode, or reformat before hashing — JSON parsing and re-serialization changes whitespace and key order, which changes the hash.

---

## Step 3 — Verify the transcript hash

Parse the `hash` field to determine the algorithm, then compute and compare:

```python
import hashlib

expected = record["tool_transcript"]["hash"]
# expected is a DigestStr: "sha256:<hex>" or "sha384:<hex>"

algorithm, expected_hex = expected.split(":", 1)

if algorithm == "sha256":
    computed = hashlib.sha256(transcript_bytes).hexdigest()
elif algorithm == "sha384":
    computed = hashlib.sha384(transcript_bytes).hexdigest()
else:
    raise ValueError(f"Unsupported digest algorithm: {algorithm}")

if computed != expected_hex:
    raise RuntimeError(
        f"Transcript hash mismatch.\n"
        f"  Expected: {expected}\n"
        f"  Computed: {algorithm}:{computed}"
    )

print(f"Transcript verified: {len(transcript_bytes)} bytes, {algorithm}:{computed[:16]}...")
```

If this check passes, the transcript at `transcript_uri` is byte-for-byte what was hashed when the Trust Record was signed. Combined with the signature check from Step 1, this gives you end-to-end integrity: record → hash → transcript.

---

## Step 4 — Inspect individual call records

The transcript is a JSON array of tool call records. Each entry captures one call:

```json
[
  {
    "call_index": 0,
    "tool_name": "read_file",
    "input_hash": "sha256:...",
    "output_hash": "sha256:...",
    "started_at": "2026-06-23T09:14:58Z",
    "duration_ms": 142
  }
]
```

The inputs and outputs are themselves hashed — the raw argument and response values are not in the transcript by default. This protects sensitive tool arguments while still committing the content:

```python
import json

calls = json.loads(transcript_bytes)

print(f"Total calls: {len(calls)}")
for call in calls:
    print(f"  [{call['call_index']}] {call['tool_name']}")
    print(f"    input:  {call.get('input_hash', 'not committed')}")
    print(f"    output: {call.get('output_hash', 'not committed')}")
```

Cross-check against `call_count` if it was set in the Trust Record:

```python
call_count = record["tool_transcript"].get("call_count")
if call_count is not None and len(calls) != call_count:
    print(f"Warning: record says {call_count} calls but transcript has {len(calls)}")
```

---

## External execution receipts

For high-assurance scenarios, individual calls may carry external execution receipts — signed by a third-party (the caller, an orchestrator, or a notary) rather than the agent that produced the Trust Record.

The spec (§3.3.1) defines the receipt structure:

| Field | Description |
|---|---|
| `issuer` | URI identifying the signing party |
| `issuer_key_id` | Key identifier within that party's key set |
| `signature` | Signature over `evidence_hash` |
| `evidence_hash` | Digest of the specific call being attested |
| `evidence_type` | Content type of the evidence (e.g., `application/json`) |
| `linked_call_id` | The call index this receipt binds to |

To verify a receipt against a specific call:

```python
def verify_external_receipt(call, receipt, issuer_public_key):
    expected_hash = call["input_hash"]  # or output_hash depending on what was attested
    algorithm, expected_hex = expected_hash.split(":", 1)

    receipt_evidence_hash = receipt["evidence_hash"]
    receipt_alg, receipt_hex = receipt_evidence_hash.split(":", 1)

    # The receipt's evidence_hash must match the call's committed hash
    if receipt_hex != expected_hex or receipt_alg != algorithm:
        raise RuntimeError(
            f"Receipt evidence_hash does not match call {call['call_index']}"
        )

    # The signature covers the evidence_hash bytes (algorithm-specific)
    # Verify using the issuer's public key from their published key set
    # (Key retrieval from issuer URI is application-specific)
    # ...
    return True
```

!!! info "No SDK helper for receipt verification"
    The `agentrust_trace` SDK does not include an issuer key resolver or receipt chain verifier. Resolution of `issuer` URIs to public keys is application-specific — typically a DID document or a published JWK Set at a well-known endpoint.

---

## Putting it together

A complete audit verification run:

```python
from agentrust_trace.sign import verify_record, load_key
import hashlib
import json
import requests

def verify_audit_chain(record_path, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = load_key(f.read())

    with open(record_path) as f:
        record = json.load(f)

    # Step 1: Verify record signature
    verify_record(record, public_key_or_jwk=public_key)
    print("Signature: OK")

    tt = record.get("tool_transcript")
    if not tt:
        print("No tool_transcript — nothing further to verify")
        return

    # Step 2: Retrieve transcript
    uri = tt.get("transcript_uri")
    if not uri:
        print("No transcript_uri — cannot retrieve transcript")
        return

    transcript_bytes = requests.get(uri, timeout=30).content

    # Step 3: Hash check
    algorithm, expected_hex = tt["hash"].split(":", 1)
    hashfn = hashlib.sha256 if algorithm == "sha256" else hashlib.sha384
    computed = hashfn(transcript_bytes).hexdigest()

    if computed != expected_hex:
        raise RuntimeError(f"Transcript hash mismatch: got {algorithm}:{computed}")

    print(f"Transcript hash: OK ({algorithm}:{computed[:16]}...)")

    # Step 4: Call count
    calls = json.loads(transcript_bytes)
    call_count = tt.get("call_count")
    if call_count is not None:
        match = "OK" if len(calls) == call_count else "MISMATCH"
        print(f"Call count: {len(calls)}/{call_count} [{match}]")
    else:
        print(f"Calls in transcript: {len(calls)}")
```

---

## Summary

| Step | What it proves |
|---|---|
| `verify_record()` | Record was not altered after signing; `tool_transcript.hash` is trusted |
| Transcript hash check | Transcript bytes are exactly what was hashed at signing time |
| Call count check | Transcript was not truncated |
| External receipt check | Third-party confirms specific call inputs/outputs (optional) |

The chain of custody runs: hardware/software measurement → signed Trust Record → committed transcript hash → per-call hashes → optional external receipts. Each link is independently verifiable without contacting the operator who produced the record.
