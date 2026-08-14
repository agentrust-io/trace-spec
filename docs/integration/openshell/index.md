# Integration: NVIDIA OpenShell

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) is a sandbox runtime that enforces filesystem, process, network, and inference policy. OpenShell emits machine-readable OCSF events for observable sandbox behavior. A TRACE adapter can bind those events to an execution record without treating a control-plane log as hardware attestation.

## Assurance boundary

An OpenShell import has the following mandatory TRACE signals:

| TRACE field        | Value                        |
| ------------------ | ---------------------------- |
| `origin.kind`      | `third-party-control-plane`  |
| `origin.producer`  | `nvidia-openshell/<version>` |
| `runtime.platform` | `software-only`              |
| `appraisal.status` | `none`                       |

Docker, Podman, Kubernetes, or MicroVM isolation does not establish a TRACE hardware platform. A record may claim a hardware platform only when it carries the corresponding quote, freshness binding, workload measurement, and independent appraisal.

## Evidence inputs

Use the complete OCSF JSONL export, not the shorthand stream returned by `openshell logs`. The gateway stream is bounded and volatile. The JSONL files inside the sandbox contain full OCSF objects, rotate daily, and retain three files, so a production collector must export them continuously.

The adapter requires:

1. Effective OpenShell policy bytes and revision.
1. AGT Agent Control Specification manifest bytes.
1. Complete OCSF JSONL for the execution interval.
1. ACS application-policy decisions for the same sandbox execution.
1. Sandbox identifier and immutable workload or image digest.
1. Operator-supplied workload identity, model identity, data class, and public record-signing key.

## Policy binding

OpenShell and ACS enforce different layers. Bind both into one canonical policy bundle:

```
{
  "format": "agentrust.openshell-policy-bundle.v1",
  "openshell": {
    "revision": "42",
    "enforcement_mode": "enforce",
    "content": "<base64 exact effective policy bytes>"
  },
  "agt_acs": {
    "enforcement_mode": "enforce",
    "content": "<base64 exact ACS manifest bytes>"
  }
}
```

`policy.bundle_hash` is the digest of the canonical bundle bytes. The record's single `policy.enforcement_mode` is the weakest mode among the layers:

- `enforce` only when both layers enforce;
- `advisory` when either layer evaluates without blocking;
- `silent` when a layer enforces while suppressing operational logs.

## Transcript binding

`tool_transcript.hash` commits to a canonical envelope containing:

- sandbox identifier;
- capture start and end;
- completeness assertion and source-file digest;
- composite policy bundle hash;
- ordered ACS decisions;
- ordered full OCSF event objects.

Reordering an event, changing a policy revision, or changing an ACS decision changes the transcript commitment. An incomplete capture must not be emitted as a complete TRACE transcript.

## Implementation

The `agentrust-trace-adapters` package exposes `OpenShellEvidence` and `build_openshell_record`. Evidence assembly returns an unsigned Level 0 record; signing remains a separate `agentrust_trace.sign_record` operation so callers cannot accidentally conflate collection with key custody.

See the runnable integration in [`agentrust-io/integrations`](https://github.com/agentrust-io/integrations/tree/main/integrations/openshell).
