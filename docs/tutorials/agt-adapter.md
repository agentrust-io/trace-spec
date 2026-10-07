# Build a TRACE Record from AGT Session Inputs

This page is for developers who use AGT (the Agent Governance Toolkit, open-source software that checks an AI agent's actions against rules) and want each session to produce a TRACE record. You will turn a session's rule file and its log of tool calls into a signed record on your own computer, in about one minute.

The example uses made-up inputs. It does not run AGT, call an AI model, or check any hardware.

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
    enforcement_mode="declared",  # synthetic input: no policy engine ran
)
record = adapter.build_trust_record(session)
assert record["policy"]["enforcement_mode"] == "declared"
# The adapter currently requires a URI argument but performs no registration.
record.pop("transparency")
# `appraisal.status` defaults to "none", which is correct here: synthetic input has not
# been appraised. Pass appraisal_status only when an appraisal actually happened.
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

The script prints `PASS` when the session has been turned into a record and signed. Some values are placeholders: the build digest (a fingerprint meant to identify how the software was built) is illustrative, and nobody checked it, and the chain tip (the last link in AGT's tamper-evident log) is made up. So the example checks two things only: that the fields were filled in correctly, and that the software signature works.

## Use real session evidence

For a real session, pass in four things: the exact rule file (policy) the session used, byte for byte; the log entries as plain dictionaries; the session's chain tip; and the agent's checked identity. The adapter turns the log and the chain tip into fingerprints (hashes) that go into the record. By default it counts one call per log entry.

The record says which enforcement mode you configured, meaning whether the rules were meant to block actions or only to be noted. Writing the mode down does not prove the rules ran. That is why the adapter has no default and makes you choose the mode yourself. This tutorial passes `"declared"` because no rule engine ran on the made-up input. Pass the mode your deployment really ran under.

The appraisal status (whether anyone checked the evidence) starts as `none` for the same reason. Building a record is not checking it. Before signing, set each claim to match the checks that really happened.

??? info "Technical detail: how the adapter hashes its inputs and why the defaults are what they are"
    The adapter hashes the audit list with RFC 8785 and the chain-tip string as UTF-8. Its default call count is the list length; supply `call_count` only when your producing profile defines a different count.

    The adapter records the configured enforcement mode; it does not enforce that mode or prove the policy was evaluated. `enforcement_mode` is required and has no default: a default of `"enforce"` would claim an evaluation nobody saw, and spec section 4.3 says `"declared"` must not be a default. This does not change runtime enforcement defaults or behavior.

    `appraisal.status` defaults to `none` because the field is the verifier's (spec section 3.3.1).

## Verify and extend

Whoever receives the record should get your public key through their own trusted channel, then follow [record verification](verifying-a-trust-record.md). To add hardware evidence, use a profile and checker built for that hardware; writing a hardware name into the record proves nothing by itself. For Level 2 (records also published to a public log), follow the [registry anchor format](../../spec/registry-anchor-v1.md). If you change any signed field, sign the record again.
