# Verify a Trust Record

Verify a standalone TRACE record against a separately trusted issuer key, reject a changed record, and preserve the result of the revocation check. This walkthrough checks signed evidence; it does not authorize an agent action or appraise hardware.

## Prerequisites

Complete the [quick start](../quickstart.md) from a source checkout. It creates `session.trace.json` and `issuer-public.pem`. Run the blocks below from that directory, in one Python script. In production, obtain the issuer key through your own trust configuration rather than accepting a key supplied with an incoming record.

## Verify the record

```python
import json
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from agentrust_trace import verify_record

trusted_key = load_pem_public_key(Path("issuer-public.pem").read_bytes())
record = json.loads(Path("session.trace.json").read_text())
result = verify_record(record, public_key_or_jwk=trusted_key)
assert result.revocation.outcome == "no_check_performed"
print("signature and record checks passed; no revocation check performed")
```

`verify_record` checks schema and profile, key binding and signature, record age, future clock skew, and any nonce/revocation inputs you configure. It requires a trusted key by default. `allow_embedded_key=True` is an explicit consistency-only option, not issuer authentication.

The default maximum age is 24 hours. If the quick-start record has expired, recreate it. For historical evaluation, pin the evaluation time and retain the trust and revocation evidence used for that decision.

## Reject an edited record

```python
from copy import deepcopy
from cryptography.exceptions import InvalidSignature

changed = deepcopy(record)
changed["subject"] = "spiffe://example.test/agent/changed"
try:
    verify_record(changed, public_key_or_jwk=trusted_key)
except InvalidSignature:
    print("edited record rejected")
else:
    raise AssertionError("edited record accepted")
```

The replacement subject is schema-valid, so this case reaches the signature check. A malformed field can fail schema validation earlier and does not exercise the same check.

## Revocation is a separate outcome

Without a store or bundle, the result reports `no_check_performed`. A supplied bundle that cannot establish status can produce `unverified_for_revocation`; it does not necessarily raise. If your policy requires a current revocation check, inspect the result and refuse to proceed unless that requirement is satisfied.

See [checking revocation status](../verification.md#checking-revocation-status) for store and bundle inputs, freshness bounds, and implementation limits.

## Appraisal and hardware claims

A signed `appraisal.status` authenticates a statement about appraisal. This function does not independently verify the hardware report, expected measurement, policy execution, or transcript contents. Do not treat `affirming` or a non-software platform string as sufficient evidence to act.

For cMCP's `RuntimeClaim`, use [cmcp-verify](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/). That envelope is different from standalone TRACE. For the wider distinction, read [hardware evidence](hardware-attestation-platforms.md) and [trust levels](../trust-levels.md).

## Failure handling

`InvalidSignature` rejects a signature mismatch. `ValueError` rejects other supported verification failures, such as malformed input, an unsupported profile, an untrusted/mismatched key, stale timestamps, or configured nonce/revocation failures. Do not return a successful verification result when either is raised.

The returned verification result still needs the recipient's acceptance policy. A signed statement is not proof of task completion, hardware isolation, or complete audit history.
