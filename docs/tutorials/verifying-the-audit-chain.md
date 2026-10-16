# Verify the Tool Call Transcript

This page is for anyone who has a TRACE record and the log of tool calls (the transcript) that came with it, and wants to know the log is the one the producer signed. The record holds a fingerprint (hash) of the transcript; you will recompute it and compare.

A match shows the transcript you hold is the one the record vouches for. It cannot show that the producer logged every call the agent really made.

## Run a complete local example

First save the complete [AGT adapter example](agt-adapter.md) as `adapter_example.py`. It creates synthetic audit entries and a signed software record. Append the following block to that same file, then run `python adapter_example.py`.

To recompute a fingerprint you need the exact bytes the producer hashed. This producer writes the log as JSON in one fixed standard layout (RFC 8785). Other producers may write their logs differently; use the format they document instead of assuming every TRACE transcript is a JSON list or a hash of an HTTP response.

```python
import hmac
import rfc8785

# The adapter defines these exact canonical bytes as its transcript input.
transcript_bytes = rfc8785.dumps(entries)

def check_transcript(record, payload, trusted_public_key):
    verify_record(record, public_key_or_jwk=trusted_public_key)
    commitment = record.get("tool_transcript")
    if commitment is None:
        raise ValueError("Record has no transcript commitment")
    algorithm, expected = commitment["hash"].split(":", 1)
    if algorithm not in {"sha256", "sha384"}:
        raise ValueError("Unsupported transcript digest")
    actual = hashlib.new(algorithm, payload).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("Transcript hash mismatch")
    # This adapter's profile counts entries in a JSON list.
    import json
    calls = json.loads(payload)
    if not isinstance(calls, list):
        raise ValueError("Expected a transcript list for this producer")
    count = commitment.get("call_count")
    if count is not None and len(calls) != count:
        raise ValueError("Transcript call count mismatch")
    return calls

assert len(check_transcript(signed, transcript_bytes, trusted_key)) == 1
print("PASS: transcript matches the signed commitment")
try:
    check_transcript(signed, transcript_bytes + b" ", trusted_key)
except ValueError as error:
    assert str(error) == "Transcript hash mismatch"
    print("PASS: changed transcript rejected")
else:
    raise RuntimeError("Changed transcript was accepted")
```

The final two lines should report a matching transcript and then a rejected copy with one extra byte. The demo keeps its own copy of the public key; a real recipient needs the producer's key from its own trusted settings.

## Verify a received transcript

For a record someone sent you, use the saved-record key-loading sequence in [verify a trust record](verifying-a-trust-record.md). Obtain transcript bytes through your application's approved artifact channel. `transcript_uri` is optional, so a record does not always provide a download location. Apply your application's URL, response-size, and access controls before fetching a producer-supplied URI.

Check the signature, recompute the fingerprint from the bytes in the producer's format, and reject any mismatch. If the record states a number of calls, compare it, counting calls the way that producer defines them. Do not silently treat absent evidence or a count mismatch as successful transcript verification.

## Interpret the result

A matching fingerprint ties these exact bytes to what the trusted key signed. A matching count shows the log has as many calls as the record says. Neither establishes that the producer disclosed every call, that an action completed, or that its outputs are correct. Hashing sensitive input also does not guarantee confidentiality, particularly for predictable values.

Receipts that another system issues for an action (action receipts) need their own issuer trust, signature, action binding, and freshness checks. Use the [action-receipt verification guide](../verification.md#action-receipts-and-embodied-workflows) for those checks; a generic transcript hash does not perform them.
