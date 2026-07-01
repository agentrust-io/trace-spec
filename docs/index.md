# TRACE

**Trust Runtime Attestation and Compliance Evidence** — an open specification for hardware-attested AI agent governance records.

TRACE defines the format, anchoring protocol, and verification rules for cryptographically provable evidence that an AI agent ran under a specific policy, in a verified hardware environment, on classified data, invoking identified tools — bound into a single signed artifact rooted in silicon attestation.

TL;DR

TRACE is an open standard for signed, hardware-attested records that prove how an AI agent actually ran: which model, in which verified hardware environment, under which policy, on what data class, and which tools it called. Anyone can verify a Trust Record without trusting the operator. Install the Python library with `pip install agentrust-trace`.

______________________________________________________________________

- **Get Started**

  Install the library, sign your first Trust Record, and verify it end-to-end in minutes.

  [Quickstart →](https://trace.agentrust-io.com/docs/quickstart/index.md)

- **Specification**

  The normative TRACE v0.1 specification — envelope format, claim types, signing rules, and verification algorithm.

  [Read the spec →](https://trace.agentrust-io.com/spec/trace-v0.1/index.md)

- **Integration**

  Connect TRACE to AGT and cMCP for end-to-end agent governance pipelines.

  [Integration guides →](https://trace.agentrust-io.com/docs/integration/agt/index.md)

- **Conformance Tests**

  197 tests across 7 modules. Verify your implementation against the spec.

  [Test suite →](https://tests.agentrust-io.com)

## What a Trust Record proves

A TRACE Trust Record answers — in a form any third party can verify without trusting the operator:

| Question                              | TRACE claim                                           |
| ------------------------------------- | ----------------------------------------------------- |
| What model ran?                       | `model.model_id` + `model.weights_digest`             |
| Where did it run?                     | `runtime.platform` + `runtime.measurement`            |
| Under which policy?                   | `policy.bundle_hash` + `policy.enforcement_mode`      |
| What data did it touch?               | `data_class`                                          |
| Which tools were called?              | `tool_transcript.hash` + `tool_transcript.call_count` |
| Is the record independently anchored? | `anchoring.receipt_uri` (SCITT)                       |

## Standards alignment

TRACE is built on open IETF/IRTF standards and designed for CoSAI WS4 interoperability:

- **RFC 9711** — CBOR Web Token (CWT) / EAT claim envelope
- **RFC 9334** — RATS architecture (attester, verifier, relying-party roles)
- **SCITT draft-22** — transparency ledger anchoring
- **CoSAI WS4** — AI agent digital lifecycle controls (contributed spec language)

## Quick reference

```
pip install agentrust-trace
```

```
from agentrust_trace import TrustRecord

record = TrustRecord.sign(claims, signing_key)
receipt = record.anchor()            # SCITT ledger
record.verify(verifying_key)         # raises on invalid
```

[Full API reference →](https://trace.agentrust-io.com/docs/schema/index.md) · [Changelog →](https://trace.agentrust-io.com/CHANGELOG/index.md) · [GitHub →](https://github.com/agentrust-io/trace-spec)

## Frequently asked questions

### What is TRACE?

TRACE (Trust Runtime Attestation and Compliance Evidence) is an open specification for hardware-attested AI agent governance records. It defines the record format, the anchoring protocol, and the verification rules for cryptographic evidence that an AI agent ran under a specific policy, in a verified hardware environment, on a given data class, invoking identified tools.

### What does a TRACE Trust Record prove?

A single signed Trust Record answers, in a form any third party can verify without trusting the operator: what model ran, where it ran, under which policy, what data class it touched, which tools were called, and whether the record is independently anchored to a SCITT transparency ledger.

### What standards is TRACE built on?

TRACE builds on open IETF and IRTF standards: RFC 9711 (CBOR Web Token / EAT) for the claim envelope, RFC 9334 (RATS) for the attester, verifier, and relying-party roles, and the SCITT draft for transparency-ledger anchoring. It is designed for CoSAI WS4 interoperability.

### How do I create and verify a Trust Record?

Install the Python library with `pip install agentrust-trace`, sign a record with `TrustRecord.sign(claims, signing_key)`, anchor it to a SCITT ledger with `record.anchor()`, and check it with `record.verify(verifying_key)`.

### How does TRACE relate to AGT and cMCP?

TRACE is the evidence format. AGT and cMCP produce and consume Trust Records, so you can connect them into an end-to-end agent governance pipeline. See the integration guides for details.

### What is the current status of TRACE?

The current specification is TRACE v0.1, published with a conformance test suite. See the Limitations page for scope boundaries before relying on it in production.
