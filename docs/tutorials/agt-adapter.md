# Build a TRACE Record from AGT Session Inputs

Map policy bytes and audit entries into a signed software record. This local example uses synthetic inputs; it does not run AGT, call a model, or appraise hardware.

## Setup

Use the source installation from the [quick start](../quickstart.md). Save the complete block below as `adapter_example.py` and run `python adapter_example.py`.

```python
import hashlib
from agentrust_trace import generate_key, sign_record, verify_record
from agentrust_trace.adapters import AGTSessionResult, TraceAGTAdapter

policy = b'permit(principal, action, resource);'
entries = [{"tool": "demo.read", "decision": "allow"}]
session = AGTSessionResult(
    agent_did="spiffe://example.test/agent/demo",
    policy_bundle_bytes=policy,
    audit_entries=entries,
    merkle_chain_tip="0" * 64,
)
adapter = TraceAGTAdapter(
    model_provider="example", model_id="synthetic-demo",
    build_provenance_digest="sha256:" + "e" * 64,
    transparency="https://example.test/unused",
)
record = adapter.build_trust_record(session)
# The adapter currently requires a URI argument but performs no registration.
record.pop("transparency")
# Synthetic input has not been appraised; do not keep the adapter's default verdict.
record["appraisal"]["status"] = "none"
key = generate_key()
trusted_key = key.public_key()
signed = sign_record(record, key)
verify_record(signed, public_key_or_jwk=trusted_key)
assert signed["runtime"]["platform"] == "software-only"
assert signed["policy"]["bundle_hash"] == "sha256:" + hashlib.sha256(policy).hexdigest()
assert signed["tool_transcript"]["call_count"] == 1
assert "transparency" not in signed
print("PASS: mapped and signed synthetic session; no hardware appraisal or registry anchor")
```

The nonzero build digest is illustrative metadata, not verified build provenance. The chain tip is synthetic. The example checks mapping and a software signature only.

## Use real session evidence

Supply the exact policy bytes used for the session, audit entries as plain dictionaries, the session's chain tip, and its authenticated identity. The adapter hashes the audit list with RFC 8785 and the chain-tip string as UTF-8. Its default call count is the list length; supply `call_count` only when your producing profile defines a different count.

The adapter records the configured enforcement mode; it does not enforce that mode or prove the policy was evaluated. Likewise, its default `affirming` appraisal is not an independent assessment. Set the record's claims to the checks actually performed before signing.

## Verify and extend

Recipients obtain the issuer key independently and use [record verification](verifying-a-trust-record.md). Add hardware evidence through a runtime-specific profile and verifier; adding a platform name is insufficient. For Level 2, also follow the [registry anchor format](../../spec/registry-anchor-v1.md). Re-sign after changing signed fields.
