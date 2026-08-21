---
title: Hardware-attested receipts for AI agent actions
description: TRACE is an open specification for hardware-attested AI agent governance records. A Trust Record states what ran, where, under which policy, touching which data, calling which tools, in a form any third party can verify without trusting the operator.
---

# TRACE

TRACE (Trust, Runtime Attestation, and Compliance Evidence) is an open specification for hardware-attested AI agent governance records. It defines the record format, the anchoring protocol, and the verification rules for cryptographic evidence that an AI agent ran under a specific policy, in a verified hardware environment, on a given data class, invoking identified tools, all bound into a single signed artifact rooted in silicon attestation.

**A Trust Record answers what ran, where, under which policy, touching which data, and calling which tools, in a form any third party can verify without trusting the operator.**

!!! tip "TL;DR"
    - An audit log is written by the system being audited. A Trust Record is signed inside a TEE and checked against a hardware root, so the operator cannot author it after the fact.
    - The current specification is **v0.2**, with a [conformance test suite](https://tests.agentrust-io.com) that scores a record by level.
    - Install with `pip install agentrust-trace` and sign your first record in a few minutes.
    - TRACE Specification is hosted at the Linux Foundation as its own series, [TRACE Specification, a Series of LF Projects, LLC](https://www.linuxfoundation.org/).

```bash
pip install agentrust-trace
```

```python
from agentrust_trace import TrustRecord, sign_record

record = TrustRecord(
    subject="spiffe://trust.example.org/agent/payments-processor",
    model_id="claude-sonnet-4-6",
    platform="amd-sev-snp",
    policy_hash="sha256:b2c3d4...",
)
signed = sign_record(record, key=signing_key)
```

## What a Trust Record proves

Each question maps to a claim a third party can check without asking you.

| Question | TRACE claim |
|---|---|
| What model ran? | `model.model_id` + `model.weights_digest` |
| Where did it run? | `runtime.platform` + `runtime.measurement` |
| Under which policy? | `policy.bundle_hash` + `policy.enforcement_mode` |
| What data did it touch? | `data_class` |
| Which tools were called? | `tool_transcript.hash` + `tool_transcript.call_count` |
| Is the record independently anchored? | `anchoring.receipt_uri` (SCITT) |

## Where to start

<div class="grid cards" markdown>

-   __Run it__

    ---

    Sign a record, verify it, and see what a failed check looks like.

    [Quickstart](docs/quickstart.md)

-   __Read it__

    ---

    The normative specification, with the claim set, the anchoring protocol, and the verification rules.

    [TRACE v0.2](spec/trace-v0.2.md)

-   __Test it__

    ---

    Score an implementation against the spec by conformance level before claiming compliance.

    [Conformance suite](https://tests.agentrust-io.com)

-   __Integrate it__

    ---

    Emit and consume Trust Records from AGT, cMCP, and sandboxed agent runtimes.

    [Integration guides](docs/integration/agt.md)

</div>

## What it is built on

TRACE profiles existing IETF and IRTF work rather than replacing it: [RFC 9711 (EAT)](https://www.rfc-editor.org/rfc/rfc9711) for the claim envelope, [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334) for the attester, verifier, and relying-party roles, and the SCITT draft for transparency-ledger anchoring. A related standardization track runs in [CoSAI WS4](https://github.com/oasis-open-projects/coalition-for-secure-ai).

## Status and governance

The specification is a **Developer Preview**. v0.2 is current and published with a conformance test suite. Read [Limitations](LIMITATIONS.md) for the scope boundaries before relying on it in production.

TRACE Specification is an [LF Project](https://www.linuxfoundation.org/), hosted at the Linux Foundation as its own series, "TRACE Specification, a Series of LF Projects, LLC", under [LF Projects policies](https://lfprojects.org/policies/). See [Governance](GOVERNANCE.md) for how decisions are made and [Contributing](CONTRIBUTING.md) for how to propose a change.
