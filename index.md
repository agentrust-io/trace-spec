# TRACE: Trust, Runtime Attestation, and Compliance Evidence

[Specification](https://trace.agentrust-io.com/spec/trace-v0.2.md)  |  [Schema](https://trace.agentrust-io.com/schema/trace-claim.json)  |  [Examples](https://trace.agentrust-io.com/examples/index.md)  |  [Test Suite](https://github.com/agentrust-io/trace-tests)  |  [Reference Impl](https://github.com/agentrust-io/cmcp)

> **Developer Preview.** Launching at Confidential Computing Summit, June 23 2026.

An open specification for hardware-attested AI agent governance records. TRACE defines the format, anchoring protocol, and verification rules for cryptographically provable evidence that an AI agent ran under a specific policy, in a verified hardware environment, on classified data, invoking identified tools, all bound into a single signed artifact rooted in silicon attestation.

A TRACE Trust Record answers: *what ran, where, under which policy, touching which data, calling which tools*, in a form any third party can verify without trusting the operator.

## What a Trust Record proves

Each question maps to a claim a third party can check for themselves.

| Question                              | TRACE claim                                           |
| ------------------------------------- | ----------------------------------------------------- |
| What model ran?                       | `model.model_id` + `model.weights_digest`             |
| Where did it run?                     | `runtime.platform` + `runtime.measurement`            |
| Under which policy?                   | `policy.bundle_hash` + `policy.enforcement_mode`      |
| What data did it touch?               | `data_class`                                          |
| Which tools were called?              | `tool_transcript.hash` + `tool_transcript.call_count` |
| Is the record independently anchored? | `anchoring.receipt_uri` (SCITT)                       |

## Quick start

```
pip install agentrust-trace
```

```
from agentrust_trace import TrustRecord, sign_record

record = TrustRecord(
    subject="spiffe://trust.example.org/agent/payments-processor",
    model_id="claude-sonnet-4-6",
    platform="amd-sev-snp",
    policy_hash="sha256:b2c3d4...",
)
signed = sign_record(record, key=signing_key)
```

## Resources

|                             |                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------- |
| 📖 Full documentation       | [trace.agentrust-io.com](https://trace.agentrust-io.com)                          |
| 📄 Specification            | [spec/trace-v0.2.md](https://trace.agentrust-io.com/spec/trace-v0.2/index.md)     |
| 🔍 Schema                   | [schema/trace-claim.json](https://trace.agentrust-io.com/schema/trace-claim.json) |
| 📦 PyPI                     | [agentrust-trace](https://pypi.org/project/agentrust-trace/)                      |
| 🧪 Test suite               | [trace-tests](https://github.com/agentrust-io/trace-tests)                        |
| 🗂 Registry                  | `trace-registry` (not public yet)                                                 |
| 🔗 Reference implementation | [cmcp](https://github.com/agentrust-io/cmcp)                                      |
| 💬 Discussions              | [GitHub Discussions](https://github.com/orgs/agentrust-io/discussions)            |
| 📋 Changelog                | [CHANGELOG.md](https://trace.agentrust-io.com/CHANGELOG/index.md)                 |

## Standards alignment

Being formed at the Linux Foundation as its own series, "TRACE Specification, a Series of LF Projects, LLC". Related standardization track in [CoSAI WS4](https://github.com/oasis-open-projects/coalition-for-secure-ai). Builds on [RFC 9711 (EAT)](https://www.rfc-editor.org/rfc/rfc9711), [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334), and SCITT draft-22.

## Frequently asked questions

### What is TRACE?

TRACE (Trust, Runtime Attestation, and Compliance Evidence) is an open specification for hardware-attested AI agent governance records. It defines the record format, the anchoring protocol, and the verification rules for cryptographic evidence that an AI agent ran under a specific policy, in a verified hardware environment, on a given data class, invoking identified tools.

### What does a TRACE Trust Record prove?

A single signed Trust Record answers, in a form any third party can verify without trusting the operator: what model ran, where it ran, under which policy, what data class it touched, which tools were called, and whether the record is independently anchored to a SCITT transparency ledger.

### What standards is TRACE built on?

TRACE builds on open IETF and IRTF standards: RFC 9711 (CBOR Web Token / EAT) for the claim envelope, RFC 9334 (RATS) for the attester, verifier, and relying-party roles, and the SCITT draft for transparency-ledger anchoring. It is designed for CoSAI WS4 interoperability.

### How do I create and verify a Trust Record?

Install the Python library with `pip install agentrust-trace`, sign a record with `TrustRecord.sign(claims, signing_key)`, anchor it to a SCITT ledger with `record.anchor()`, and check it with `record.verify(verifying_key)`.

### How does TRACE relate to AGT and cMCP?

TRACE is the evidence format. AGT and cMCP produce and consume Trust Records, so you can connect them into an end-to-end agent governance pipeline. See the integration guides for details.

### What is the current status of TRACE?

The current specification is TRACE v0.2, published with a conformance test suite. See the Limitations page for scope boundaries before relying on it in production.

## Contributing

See [CONTRIBUTING.md](https://trace.agentrust-io.com/CONTRIBUTING/index.md) and [GOVERNANCE.md](https://trace.agentrust-io.com/GOVERNANCE/index.md). All contributors must agree to the [ANTITRUST.md](https://trace.agentrust-io.com/ANTITRUST.md) policy.
