# Verify a Trust Record

This page is for anyone who receives a TRACE record and needs to check it. You will confirm the record was signed by the producer you trust and has not been changed, watch an edited copy get rejected, and see how the result reports whether the key was checked for revocation (being withdrawn).

A passing check tells you the record is authentic and unchanged. It does not approve whatever the agent did, and it does not check any hardware.

## Prerequisites

Complete the [quick start](https://trace.agentrust-io.com/docs/quickstart/index.md) from a source checkout. It creates `session.trace.json` (the record) and `issuer-public.pem` (the producer's public key). Run the blocks below from that directory, in one Python script. In real use, get the producer's key from your own trusted settings, never from the record or the message it came with.

## Verify the record

```
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

`verify_record` checks that the record has the right structure, that the signature matches your trusted key, that the record is not too old or dated in the future, and any replay or revocation checks you set up. It asks for a trusted key by default. `allow_embedded_key=True` uses the key inside the record instead, which only shows the record agrees with itself; it does not tell you who produced it.

Technical detail: the full list of checks

`verify_record` checks schema and profile, key binding and signature, record age, future clock skew, and any nonce/revocation inputs you configure. `allow_embedded_key=True` is an explicit consistency-only option, not issuer authentication.

The default maximum age is 24 hours. If the quick-start record has expired, recreate it. For historical evaluation, pin the evaluation time and retain the trust and revocation evidence used for that decision.

## Reject an edited record

```
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

The new agent name is well formed, so the record passes the structure check and fails at the signature, which is the check this example is meant to show. A malformed field can fail schema validation earlier and does not exercise the same check.

## Revocation is a separate outcome

Revocation means a producer's key has been withdrawn, for example after it was stolen. Checking for it needs a list of withdrawn keys, so the result reports it separately.

Without a store or bundle, the result reports `no_check_performed`. A supplied bundle that cannot establish status can produce `unverified_for_revocation`; it does not necessarily raise. If your policy requires a current revocation check, inspect the result and refuse to proceed unless that requirement is satisfied.

See [checking revocation status](https://trace.agentrust-io.com/docs/verification/#checking-revocation-status) for store and bundle inputs, freshness bounds, and implementation limits.

## Appraisal and hardware claims

A signed `appraisal.status` proves the producer said the evidence was checked; it does not prove the check happened. This function does not independently verify the hardware report, expected measurement, policy execution, or transcript contents. Do not treat `affirming` or a non-software platform string as sufficient evidence to act.

For cMCP's `RuntimeClaim`, use [cmcp-verify](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/). That envelope is different from standalone TRACE. For the wider distinction, read [hardware evidence](https://trace.agentrust-io.com/docs/tutorials/hardware-attestation-platforms/index.md) and [trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md).

## Failure handling

Any error means the record failed. `InvalidSignature` rejects a signature mismatch. `ValueError` rejects other supported verification failures, such as malformed input, an unsupported profile, an untrusted/mismatched key, stale timestamps, or configured nonce/revocation failures. Do not return a successful verification result when either is raised.

The returned verification result still needs the recipient's acceptance policy. A signed statement is not proof of task completion, hardware isolation, or complete audit history.
