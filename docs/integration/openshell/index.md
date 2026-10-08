# Integration: NVIDIA OpenShell

This page is for teams that run agents inside NVIDIA OpenShell and want a TRACE record of what happened in each sandbox. It lists the inputs the adapter needs, how the policies and logs are tied into the record, and what the record can and cannot prove.

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) is a sandbox runtime: it runs an agent in a confined space and enforces rules about which files, processes, network addresses and AI models the agent may use. OpenShell logs what it sees as security events in OCSF, a standard machine-readable event format. A TRACE adapter can tie those events to a record of the run, while keeping clear that a log from the software managing the sandbox is not hardware attestation (a signed report from the processor itself).

## Assurance boundary

Because the evidence comes from OpenShell's own logs and not from hardware, every imported record says so in four fields. An OpenShell import has the following mandatory TRACE signals:

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

Two sets of rules apply: OpenShell's sandbox policy, and the agent's application rules written for AGT's Agent Control Specification (ACS). The adapter puts both into one policy bundle, written in a fixed byte form, so one hash covers both:

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
- `advisory` when either layer evaluates without blocking, or enforces while suppressing operational logs, since no mode states that combination and `advisory` understates it rather than overstating it;
- `silent` when either layer runs in `silent` mode.

## Transcript binding

The record's transcript hash covers everything below, so a verifier with the original files can recompute it. `tool_transcript.hash` commits to a canonical envelope containing:

- sandbox identifier;
- capture start and end;
- completeness assertion and source-file digest;
- composite policy bundle hash;
- ordered ACS decisions;
- ordered full OCSF event objects.

Reordering an event, changing a policy revision, or changing an ACS decision changes the transcript commitment. An incomplete capture must not be emitted as a complete TRACE transcript.

## Implementation

The `agentrust-trace-adapters` package exposes `OpenShellEvidence` and `build_openshell_record`. Assembling the evidence returns an unsigned Level 0 record. Signing is a separate `agentrust_trace.sign_record` call, so collecting evidence and holding the signing key stay separate steps that a caller cannot mix up by accident.

See the runnable integration in [`agentrust-io/integrations`](https://github.com/agentrust-io/integrations/tree/main/integrations/openshell).
