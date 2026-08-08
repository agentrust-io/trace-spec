# Integration: sandboxed agent runtimes

A sandboxed agent runtime confines one agent on one machine. Filesystem, process and
network isolation at the kernel, an egress policy, and credentials injected so the agent
never holds them. That answers what a single agent may touch.

It does not answer, on its own, three questions that arrive next:

- **Across the estate.** Which agent, on which of the two hundred machines, took that
  action, and under whose authority?
- **From a regulator.** Not what the policy said, but what actually ran, evidenced.
- **From a sovereign or on-prem buyer.** The same answer on a machine with a TPM, or a
  confidential VM, or no secure hardware at all.

`TraceSandboxAdapter` answers them from what the runtime already has at session close.
It requires no change to the runtime.

## Install

```
pip install agentrust-trace
```

## Quick start

```python
from pathlib import Path
from agentrust_trace import TrustRecord, load_signing_key, sign_record
from agentrust_trace.adapters import SandboxSessionResult, TraceSandboxAdapter

# Configure once per deployment.
adapter = TraceSandboxAdapter(
    model_provider="anthropic",
    model_id="claude-sonnet-4-6",
    data_class="confidential",
)

# Per session, from what the runtime already knows at close.
session = SandboxSessionResult(
    sandbox_id="spiffe://runtime.example.org/sandbox/code-review-7f2a",
    image_digest="sha256:5e8b2d1a...",
    policy_bundle_bytes=Path("sandbox-policy.yaml").read_bytes(),
    decisions=runtime.decision_log(),
)

record = sign_record(adapter.build_trust_record(session), load_signing_key())
TrustRecord.model_validate(record)
```

That record is Level 0: signed, offline-verifiable, and honest that no hardware backed
it. `runtime.platform` reads `software-only`.

## Adding a root of trust

Pass a `SandboxAttestation` and the same call emits Level 1. Nothing else changes.

```python
from agentrust_trace.adapters import SandboxAttestation

session = SandboxSessionResult(
    ...,
    attestation=SandboxAttestation(
        platform="tpm2",                       # or amd-sev-snp, intel-tdx, nvidia-h100, ...
        measurement="sha256:3b4c2a1f...",      # supplied by the platform, not computed here
        firmware_version="7.85",
    ),
)
```

This is the point of the adapter spanning both levels. A sandbox runs wherever the
customer runs it, and the deployments that most need evidence are often the ones with
the least hardware. One code path covers a developer laptop and a confidential VM.

**The adapter will not let you claim hardware you do not have.** `platform` is only ever
set from a supplied attestation; an attestation may not name `software-only`; the
platform is checked against the enum on `RuntimeInfo` rather than a copy of it; and the
measurement must be a `sha256:` or `sha384:` digest. A record that says `tpm2` therefore
carries a measurement something other than this process produced.

## Field mapping

| Record field | Source |
|---|---|
| `subject` | `sandbox_id`, a SPIFFE URI or DID |
| `build_provenance.digest` | `image_digest` |
| `policy.bundle_hash` | SHA-256 of `policy_bundle_bytes` |
| `tool_transcript.hash` | SHA-256 of the RFC 8785 canonical form of `decisions` |
| `tool_transcript.call_count` | `len(decisions)`, or `call_count` if given |
| `runtime.platform` | `software-only`, or the attestation's platform |
| `runtime.measurement` | `sha256(image_digest + "\n" + bundle_hash)`, or the attestation's measurement |

The hash helpers are public static methods, so a runtime written in another language can
reproduce them: `TraceSandboxAdapter.bundle_hash`, `.transcript_hash`,
`.software_measurement`.

## Three things worth getting right

**The policy bundle must be bytes you can reproduce.** The bundle hash is the load
bearing field: edit the policy and the record changes. Where a runtime composes policy
from several files, concatenate them in a defined order and keep that order stable. A
hash both sides derive differently proves nothing.

**The decision log is canonicalised with JCS, not `json.dumps(sort_keys=True)`.** The two
agree on ASCII and diverge on non-ASCII strings and number formatting, and a decision log
carries paths and hostnames. Using the same canonicalisation as the signature pre-image
keeps the record reproducible across implementations.

**An unappraised record says so.** `appraisal.status` defaults to `"none"`. Building a
record does not appraise it, and stamping `affirming` on an unappraised record puts a
verdict in the field a consumer reads to find out whether anybody checked. Set it only
when an appraisal actually happened.

## Levels

| Level | What you pass | `runtime.platform` |
|---|---|---|
| 0 | nothing extra | `software-only` |
| 1 | a `SandboxAttestation` | the attested platform |
| 2 | Level 1 plus `transparency=` a SCITT receipt URI | the attested platform |

`transparency` defaults to `None`, which leaves the key out of the record. That is
correct below Level 2: an unanchored record has no receipt to name.

Note: `schema/trace-claim.json` still lists `transparency` in `required`, so an
unanchored record validates against the model and not against the published JSON Schema.
That divergence is tracked in `tests/test_sandbox_adapter.py` and is not introduced by
this adapter.

## Worked example

`examples/sandbox-runtime.json` is a TPM 2.0 rooted record produced by this adapter,
validating as-is against the schema.

## Related

- [Integration: AGT](agt.md)
- [Integration: cMCP](cmcp.md)
- [Trust levels](../trust-levels.md)
