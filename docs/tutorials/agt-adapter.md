# TraceAGTAdapter: One-line AGT → TRACE upgrade

Replace ~50 lines of manual field wiring with a single `build_trust_record()` call.

## What you'll learn

- How `TraceAGTAdapter` maps AGT session data to TRACE Trust Record fields
- How to collect the three inputs AGT exposes (`policy_bundle_bytes`, `audit_entries`, `merkle_chain_tip`)
- How to sign and validate the resulting record
- How to upgrade from Level 0 (software-only) to Level 2 (hardware-rooted) inside cMCP

## Prerequisites

```bash
pip install agentrust-trace
```

---

## The problem: 50 lines of boilerplate per project

Every project that integrates AGT with TRACE has to wire the same field mappings by hand:

```python
import hashlib, json, time
from agentrust_trace import (
    TrustRecord, ModelInfo, RuntimeInfo, PolicyInfo,
    ToolTranscript, BuildProvenance, Appraisal, ConfirmationKey, JWK,
)

# Hash the Cedar bundle
bundle_bytes = Path("policy.cedar").read_bytes()
bundle_hash = "sha256:" + hashlib.sha256(bundle_bytes).hexdigest()

# Hash the audit entries
entries_json = json.dumps(audit_entries, sort_keys=True, separators=(",", ":"))
transcript_hash = "sha256:" + hashlib.sha256(entries_json.encode()).hexdigest()

# Hash the Merkle chain tip
measurement = "sha256:" + hashlib.sha256(chain_tip.encode()).hexdigest()

# Build the record manually
record = TrustRecord(
    eat_profile="tag:agentrust.io,2026:trace-v0.1",
    iat=int(time.time()),
    subject=agent_did,
    model=ModelInfo(provider="anthropic", model_id="claude-sonnet-4-6", version="20251001"),
    runtime=RuntimeInfo(platform="software-only", measurement=measurement),
    policy=PolicyInfo(bundle_hash=bundle_hash, enforcement_mode="enforce"),
    data_class="confidential",
    tool_transcript=ToolTranscript(hash=transcript_hash, call_count=len(audit_entries)),
    build_provenance=BuildProvenance(slsa_level=2, digest="sha256:e5f6..."),
    appraisal=Appraisal(status="affirming", verifier="https://agentrust.io/verify"),
    transparency="https://registry.agentrust.io/claim/...",
    cnf=ConfirmationKey(jwk=JWK(kty="OKP", crv="Ed25519", x="...")),
)
```

`TraceAGTAdapter` encapsulates all of this.

---

## The solution: TraceAGTAdapter

```python
from pathlib import Path
from agentrust_trace.adapters import TraceAGTAdapter, AGTSessionResult
from agentrust_trace import sign_record, load_signing_key, TrustRecord

# 1. Configure once per deployment
adapter = TraceAGTAdapter(
    model_provider="anthropic",
    model_id="claude-sonnet-4-6",
    model_version="20251001",
    build_provenance_digest="sha256:e5f6a7b8...",
    transparency="https://registry.agentrust.io/claim/...",
)

# 2. Collect AGT session data after govern_fn.close_session()
session = AGTSessionResult(
    agent_did="spiffe://trust.example.org/agent/my-agent",
    policy_bundle_bytes=Path("policy.cedar").read_bytes(),
    audit_entries=govern_fn.get_audit_entries(),   # list[dict]
    merkle_chain_tip=govern_fn.chain_tip,           # hex string
)

# 3. Build and sign
record = adapter.build_trust_record(session)
key = load_signing_key()                           # reads TRACE_PRIVATE_KEY_PEM env var
signed = sign_record(record, key)

# 4. Validate structure before writing
TrustRecord.model_validate(signed)

import json
Path("session.trace.json").write_text(json.dumps(signed, indent=2))
```

---

## Field mapping reference

| TRACE field | Source |
|---|---|
| `subject` | `AGTSessionResult.agent_did` |
| `policy.bundle_hash` | `sha256(policy_bundle_bytes)` |
| `policy.enforcement_mode` | `TraceAGTAdapter(enforcement_mode=...)` (default: `enforce`) |
| `tool_transcript.hash` | `sha256(canonical_json(audit_entries))` |
| `tool_transcript.call_count` | `len(audit_entries)` or `AGTSessionResult.call_count` override |
| `runtime.platform` | Always `software-only` (Level 0) |
| `runtime.measurement` | `sha256(merkle_chain_tip)` |
| `appraisal.status` | Always `affirming` (Phase 1) |
| `model`, `data_class`, `build_provenance` | `TraceAGTAdapter(...)` constructor params |
| `iat`, `appraisal.timestamp` | `AGTSessionResult.iat` (default: current time) |

---

## Collecting the three inputs from AGT

### `policy_bundle_bytes`

Read the Cedar bundle from disk immediately after calling `govern()`. The hash must match what the session evaluated against.

```python
from pathlib import Path

policy_bundle_bytes = Path(config.policy_path).read_bytes()
```

### `audit_entries`

AGT's `govern()` returns a wrapped callable with `.get_audit_entries()`. Call it after `.close_session()`:

```python
governed_fn = govern(my_tool, agent_did=agent_did, config=config)
result = governed_fn(input_data)
governed_fn.close_session()

audit_entries = governed_fn.get_audit_entries()  # list of Merkle AuditEntry dicts
```

### `merkle_chain_tip`

The Merkle chain tip is the hash of the last `AuditEntry` in the chain:

```python
chain_tip = governed_fn.chain_tip  # hex string, e.g. "deadbeef..."
```

---

## Adapting to different enforcement modes

```python
adapter = TraceAGTAdapter(
    ...
    enforcement_mode="advisory",  # "enforce" | "advisory" | "silent"
)
```

`enforce` (default) means policy decisions are binding — tool calls blocked by a `forbid` rule do not execute. `advisory` means decisions are logged but not enforced. The mode appears in `policy.enforcement_mode` in the TRACE record so verifiers know what the policy actually did.

---

## Upgrading to Level 2 (hardware-rooted)

`TraceAGTAdapter` produces Level 0 records — `runtime.platform` is `software-only` and the signing key is not TEE-bound. For Level 2:

1. Deploy your AGT-governed agent inside cMCP on an Azure DCasv5 (SEV-SNP) or DCesv6 (TDX) VM, or GCP N2D (SEV-SNP) or C3 (TDX)
2. cMCP measures the Cedar policy bundle into the TEE hardware at startup
3. The cMCP runtime generates a TEE-bound key and emits a Level 2 TRACE record that supersedes the Level 0 record for the same session
4. Both records share `subject` and `tool_transcript.hash` and are mutually verifiable

The Level 0 record from `TraceAGTAdapter` remains valid — it is evidence of policy enforcement at the software layer. The Level 2 record from cMCP adds hardware attestation on top.

→ [Deploy on Azure](deploy-azure.md) — `Standard_DC2as_v5` (SEV-SNP) or `Standard_DC2es_v6` (TDX)  
→ [Deploy on GCP](deploy-gcp.md) — `n2d-standard-4` (SEV-SNP) or `c3-standard-4` (TDX)

---

## Summary

`TraceAGTAdapter` turns 50 lines of manual field wiring into three calls: configure the adapter once, collect the three AGT session values (`policy_bundle_bytes`, `audit_entries`, `merkle_chain_tip`) after each session, call `build_trust_record()`. The record is structurally valid and ready for `sign_record()` without any additional construction.
