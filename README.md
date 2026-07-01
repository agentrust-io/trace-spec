<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="TRACE"/>
</p>

# TRACE: Trust Runtime Attestation and Compliance Evidence

<p align="center">
  <a href="https://trace.agentrust-io.com">
    <img src="https://img.shields.io/badge/%F0%9F%93%96_Full_Documentation-trace.agentrust--io.com-8251EE?style=for-the-badge&logoColor=white" alt="Full Documentation" height="40">
  </a>
</p>

<p align="center">
  <a href="spec/trace-v0.1.md">Specification</a> &nbsp;|&nbsp;
  <a href="schema/trace-claim.json">Schema</a> &nbsp;|&nbsp;
  <a href="examples/">Examples</a> &nbsp;|&nbsp;
  <a href="https://github.com/agentrust-io/trace-registry">Registry</a> &nbsp;|&nbsp;
  <a href="https://github.com/agentrust-io/trace-tests">Test Suite</a> &nbsp;|&nbsp;
  <a href="https://github.com/agentrust-io/cmcp">Reference Impl</a>
</p>

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/Spec-v0.1-0ea5e9)](spec/trace-v0.1.md)
[![PyPI](https://img.shields.io/pypi/v/agentrust-trace)](https://pypi.org/project/agentrust-trace/)
[![CI](https://github.com/agentrust-io/trace-spec/actions/workflows/ci.yml/badge.svg)](https://github.com/agentrust-io/trace-spec/actions/workflows/ci.yml)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white&style=flat)](https://discord.gg/grgzFEHgkj)

> **Developer Preview.** Launching at Confidential Computing Summit, June 23 2026.

An open specification for hardware-attested AI agent governance records. TRACE defines the format, anchoring protocol, and verification rules for cryptographically provable evidence that an AI agent ran under a specific policy, in a verified hardware environment, on classified data, invoking identified tools — bound into a single signed artifact rooted in silicon attestation.

A TRACE Trust Record answers: _what ran, where, under which policy, touching which data, calling which tools_ — in a form any third party can verify without trusting the operator.

## Quick start

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

## Resources

| | |
|---|---|
| 📖 Full documentation | [trace.agentrust-io.com](https://trace.agentrust-io.com) |
| 📄 Specification | [spec/trace-v0.1.md](spec/trace-v0.1.md) |
| 🔍 Schema | [schema/trace-claim.json](schema/trace-claim.json) |
| 📦 PyPI | [agentrust-trace](https://pypi.org/project/agentrust-trace/) |
| 🧪 Test suite | [trace-tests](https://github.com/agentrust-io/trace-tests) |
| 🗂 Registry | [trace-registry](https://github.com/agentrust-io/trace-registry) |
| 🔗 Reference implementation | [cmcp](https://github.com/agentrust-io/cmcp) |
| 💬 Discussions | [GitHub Discussions](https://github.com/orgs/agentrust-io/discussions) |
| 📋 Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Standards alignment

Targeting the [Agentic AI Foundation (AAIF)](https://agenticai.foundation) at the Linux Foundation. Active standardization track in [CoSAI WS4](https://github.com/oasis-open-projects/coalition-for-secure-ai). Builds on [RFC 9711 (EAT)](https://www.rfc-editor.org/rfc/rfc9711), [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334), and SCITT draft-22.

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

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is TRACE?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "TRACE (Trust Runtime Attestation and Compliance Evidence) is an open specification for hardware-attested AI agent governance records. It defines the record format, the anchoring protocol, and the verification rules for cryptographic evidence that an AI agent ran under a specific policy, in a verified hardware environment, on a given data class, invoking identified tools."
      }
    },
    {
      "@type": "Question",
      "name": "What does a TRACE Trust Record prove?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "A single signed Trust Record answers, in a form any third party can verify without trusting the operator: what model ran, where it ran, under which policy, what data class it touched, which tools were called, and whether the record is independently anchored to a SCITT transparency ledger."
      }
    },
    {
      "@type": "Question",
      "name": "What standards is TRACE built on?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "TRACE builds on open IETF and IRTF standards: RFC 9711 (CBOR Web Token / EAT) for the claim envelope, RFC 9334 (RATS) for the attester, verifier, and relying-party roles, and the SCITT draft for transparency-ledger anchoring. It is designed for CoSAI WS4 interoperability."
      }
    },
    {
      "@type": "Question",
      "name": "How do I create and verify a Trust Record?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Install the Python library with pip install agentrust-trace, sign a record with TrustRecord.sign(claims, signing_key), anchor it to a SCITT ledger with record.anchor(), and check it with record.verify(verifying_key)."
      }
    },
    {
      "@type": "Question",
      "name": "How does TRACE relate to AGT and cMCP?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "TRACE is the evidence format. AGT and cMCP produce and consume Trust Records, so you can connect them into an end-to-end agent governance pipeline. See the integration guides for details."
      }
    },
    {
      "@type": "Question",
      "name": "What is the current status of TRACE?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The current specification is TRACE v0.1, published with a conformance test suite. See the Limitations page for scope boundaries before relying on it in production."
      }
    }
  ]
}
</script>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md). All contributors must agree to the [ANTITRUST.md](ANTITRUST.md) policy.
