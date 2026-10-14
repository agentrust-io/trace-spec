<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="TRACE"/>
</p>

# TRACE: Trust, Runtime Attestation, and Compliance Evidence

<p align="center">
  <a href="https://trace.agentrust-io.com">
    <img src="https://img.shields.io/badge/%F0%9F%93%96_Full_Documentation-trace.agentrust--io.com-8251EE?style=for-the-badge&logoColor=white" alt="Full Documentation" height="40">
  </a>
</p>

<p align="center">
  <a href="spec/trace-v0.2.md">Specification</a> &nbsp;|&nbsp;
  <a href="schema/trace-claim.json">Schema</a> &nbsp;|&nbsp;
  <a href="examples/">Examples</a> &nbsp;|&nbsp;
  <a href="https://github.com/agentrust-io/trace-tests">Test Suite</a> &nbsp;|&nbsp;
  <a href="https://github.com/agentrust-io/cmcp">Reference Impl</a>
</p>

[![Specification: Community Specification License 1.0](https://img.shields.io/badge/Specification-Community_Specification_License_1.0-blue.svg)](Governance/COMMUNITY-SPECIFICATION-LICENSE.md)
[![Code: Apache 2.0](https://img.shields.io/badge/Code-Apache_2.0-lightgrey.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/Spec-v0.2-0ea5e9)](spec/trace-v0.2.md)
[![PyPI](https://img.shields.io/pypi/v/agentrust-trace)](https://pypi.org/project/agentrust-trace/)
[![CI](https://github.com/agentrust-io/trace-spec/actions/workflows/ci.yml/badge.svg)](https://github.com/agentrust-io/trace-spec/actions/workflows/ci.yml)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white&style=flat)](https://discord.gg/grgzFEHgkj)

<p align="center">
  <strong>TRACE Specification is an <a href="https://www.linuxfoundation.org/">LF Project</a></strong>, hosted at the Linux Foundation as its own series, "TRACE Specification, a Series of LF Projects, LLC".
</p>

> **Developer Preview.** Launched at Confidential Computing Summit, 23 June 2026. Spec v0.2 is current. See [LIMITATIONS.md](LIMITATIONS.md) before relying on it in production.

An open specification for verifiable AI-agent governance evidence. TRACE defines the record format, anchoring protocol, and verification rules that bind runtime, policy, data-class, tool, and provenance assertions into a signed artifact. Hardware-rooted deployments can add attestation that materially strengthens those assertions; software-only Level 0 records do not independently prove that the claimed execution occurred.

A TRACE Trust Record answers: _what does this signed record assert about what ran, where, under which policy, touching which data, and calling which tools: and which of those assertions did this verifier actually establish?_

## What a Trust Record binds

Each question maps to a signed claim a verifier can inspect. The assurance strength depends on trust level, attestation, appraisal, revocation status, and the checks actually performed.

| Question | TRACE claim |
|---|---|
| What model ran? | `model.model_id` + `model.weights_digest` |
| Where did it run? | `runtime.platform` + `runtime.measurement` |
| Under which policy? | `policy.bundle_hash` + `policy.enforcement_mode` |
| What data did it touch? | `data_class` |
| Which tools were called? | `tool_transcript.hash` + `tool_transcript.call_count` |
| Is the record independently anchored? | `transparency` (SCITT receipt URI) |

## Quick start

```bash
pip install agentrust-trace
```

```python
import time
from agentrust_trace import generate_key, sign_record

key = generate_key()

record = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": int(time.time()),
    "subject": "spiffe://trust.example.org/agent/payments-processor",
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
    "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
}

signed = sign_record(record, key)
```
See the [Quickstart guide](https://trace.agentrust-io.com/docs/quickstart/) for key persistence, validation, and anchoring the record to a transparency log.

For relying-party verification that must retain exactly what was checked, use the bounded report API:

```python
from agentrust_trace import verify_record_report

result = verify_record_report(
    signed_record,
    trusted_jwk,
    revocation=current_revocation_store,
)

print(result["record"]["canonical_sha256"])
print(result["trusted_key"]["jwk_thumbprint"])
print(result["checks"]["revocation"]["status"])
```

`verify_record_report()` only returns a success statement after the existing fail-closed `verify_record()` path succeeds. It distinguishes checks that ran from optional checks that were not requested and states the resulting trust boundaries explicitly.


## Resources

| | |
|---|---|
| 📖 Full documentation | [trace.agentrust-io.com](https://trace.agentrust-io.com) |
| 📄 Specification | [spec/trace-v0.2.md](spec/trace-v0.2.md) |
| 🔍 Schema | [schema/trace-claim.json](schema/trace-claim.json) |
| 📦 PyPI | [agentrust-trace](https://pypi.org/project/agentrust-trace/) |
| 🧪 Test suite | [trace-tests](https://github.com/agentrust-io/trace-tests) |
| 🗂 Registry | `trace-registry` (not public yet) |
| 🔗 Reference implementation | [cmcp](https://github.com/agentrust-io/cmcp) |
| 💬 Discussions | [GitHub Discussions](https://github.com/orgs/agentrust-io/discussions) |
| 📋 Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Standards alignment

Hosted at the Linux Foundation as its own series, "TRACE Specification, a Series of LF Projects, LLC", under [LF Projects policies](https://lfprojects.org/policies/). The Linux Foundation [announced the contribution](https://www.linuxfoundation.org/press/linux-foundation-welcomes-trace-to-advance-verifiable-runtime-evidence-for-ai-workloads) on 25 August 2026, developed with AMD, Intel, Microsoft, OPAQUE and TII. The technical workstream is hosted by CoSAI; see [CoSAI WS4](https://github.com/oasis-open-projects/coalition-for-secure-ai). Builds on [RFC 9711 (EAT)](https://www.rfc-editor.org/rfc/rfc9711), [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334), and SCITT draft-22.

## Frequently asked questions

### What is TRACE?

TRACE (Trust, Runtime Attestation, and Compliance Evidence) is an open specification for verifiable AI-agent governance evidence. It defines the record format, anchoring protocol, and verification rules for signed assertions about runtime, policy, data class, tools, and provenance. Hardware-attested profiles can strengthen those assertions beyond software-only records.

### What does a TRACE Trust Record establish?

A single signed Trust Record answers, in a form any third party can verify without trusting the operator: what model ran, where it ran, under which policy, what data class it touched, which tools were called, and whether the record is independently anchored to a SCITT transparency ledger.

### What standards is TRACE built on?

TRACE builds on open IETF and IRTF standards: RFC 9711 (CBOR Web Token / EAT) for the claim envelope, RFC 9334 (RATS) for the attester, verifier, and relying-party roles, and the SCITT draft for transparency-ledger anchoring. It is designed for CoSAI WS4 interoperability.

### How do I create and verify a Trust Record?

Install the Python library with `pip install agentrust-trace`, sign a record with `TrustRecord.sign(claims, signing_key)`, anchor it to a SCITT ledger with `record.anchor()`, and check it with `record.verify(verifying_key)`.

### How does TRACE relate to AGT and cMCP?

TRACE is the evidence format. AGT and cMCP produce and consume Trust Records, so you can connect them into an end-to-end agent governance pipeline. See the integration guides for details.

### What is the current status of TRACE?

The current specification is TRACE v0.2, published with a conformance test suite. See the Limitations page for scope boundaries before relying on it in production.

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
        "text": "TRACE (Trust, Runtime Attestation, and Compliance Evidence) is an open specification for hardware-attested AI agent governance records. It defines the record format, the anchoring protocol, and the verification rules for cryptographic evidence that an AI agent ran under a specific policy, in a verified hardware environment, on a given data class, invoking identified tools."
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
        "text": "The current specification is TRACE v0.2, published with a conformance test suite. See the Limitations page for scope boundaries before relying on it in production."
      }
    }
  ]
}
</script>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md). All contributors must agree to the [ANTITRUST.md](ANTITRUST.md) policy.
