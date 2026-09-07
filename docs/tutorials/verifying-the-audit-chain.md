# Verify the Tool Call Transcript

Check that a signed record commits to the transcript you received. This establishes integrity of the supplied transcript; it cannot show that the producer recorded every real call.

## Run a complete local example

First save the complete [AGT adapter example](agt-adapter.md) as `adapter_example.py`. It creates synthetic audit entries and a signed software record. Append the following block to that same file, then run `python adapter_example.py`.

This producer hashes RFC 8785 canonical JSON. Other producers can define different transcript encodings; use their documented byte format instead of assuming every TRACE transcript is a JSON array or a hash of an HTTP response.

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

The final two lines should report a matching transcript and rejection of changed bytes. The verifier's key is retained independently by the demo; a recipient needs its own trusted issuer-key configuration.

## Verify a received transcript

Use the saved-record key-loading sequence in [verify a trust record](verifying-a-trust-record.md). Obtain transcript bytes through your application's approved artifact channel. `transcript_uri` is optional, so a record does not always provide a download location. Apply your application's URL, response-size, and access controls before fetching a producer-supplied URI.

Verify the signature, compute the digest using the producing profile's encoding, and reject mismatches. If a count is supplied, compare it using that profile's definition of a call. Do not silently treat absent evidence or a count mismatch as successful transcript verification.

## Interpret the result

A matching digest binds these bytes to the trusted key's signed statement. A matching count shows consistency with the declared count. Neither establishes that the producer disclosed every call, that an action completed, or that its outputs are correct. Hashing sensitive input also does not guarantee confidentiality, particularly for predictable values.

External action receipts require their own issuer trust, signature, action binding, and freshness checks. Use the [action-receipt verification guide](../verification.md#action-receipts-and-embodied-workflows) for those checks; a generic transcript hash does not perform them.
