# Sign a runtime record. Check its evidence.

TRACE is an open specification for portable, signed runtime evidence. Its record format connects workload identity, policy, data classification, and tool-transcript commitments. A verifier checks the signature and the evidence required by its trust policy.

[Create and verify your first record](https://trace.agentrust-io.com/docs/quickstart/index.md) [Understand the trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md)

The first example needs Python 3.11+ and no cloud account. It signs synthetic declarations in software, verifies with a separately retained key, and demonstrates tamper detection. Hardware provenance and registry inclusion require additional evidence and checks.

## What the record contains

| Question                      | Fields to inspect  | What the verifier still needs                                       |
| ----------------------------- | ------------------ | ------------------------------------------------------------------- |
| Which workload is named?      | `subject`, `model` | An authenticated issuer and evidence binding the workload           |
| What runtime is claimed?      | `runtime`          | Valid attestation and approved measurements for hardware provenance |
| Which policy is named?        | `policy`           | Independently approved policy inputs                                |
| What data class is declared?  | `data_class`       | Evidence supporting the producer's classification                   |
| What transcript is committed? | `tool_transcript`  | Transcript evidence when individual calls matter                    |
| Was evidence anchored?        | `transparency`     | A verified receipt and the required log trust policy                |

A signed field is a producer's claim. Signature verification alone does not establish that the described execution occurred or that a policy was enforced. See the [verification protocol](https://trace.agentrust-io.com/docs/verification/index.md) for the full evaluation path.

## Where to start

- **Run it**

  ______________________________________________________________________

  Sign a record, verify it, and see what a failed check looks like.

  [Quickstart](https://trace.agentrust-io.com/docs/quickstart/index.md)

- **Read it**

  ______________________________________________________________________

  The normative specification, with the claim set, the anchoring protocol, and the verification rules.

  [TRACE v0.2](https://trace.agentrust-io.com/spec/trace-v0.2/index.md)

- **Test it**

  ______________________________________________________________________

  Score an implementation against the spec by conformance level before claiming compliance.

  [Conformance suite](https://tests.agentrust-io.com)

- **Integrate it**

  ______________________________________________________________________

  Emit and consume Trust Records from AGT, cMCP, and sandboxed agent runtimes.

  [Integration guides](https://trace.agentrust-io.com/docs/integration/agt/index.md)

## What it is built on

TRACE profiles existing IETF and IRTF work rather than replacing it: [RFC 9711 (EAT)](https://www.rfc-editor.org/rfc/rfc9711) for the claim envelope, [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334) for the attester, verifier, and relying-party roles, and the SCITT draft for transparency-ledger anchoring. A related standardization track runs in [CoSAI WS4](https://github.com/oasis-open-projects/coalition-for-secure-ai).

## Status and governance

The specification is a **Developer Preview**. v0.2 is current and published with a conformance test suite. Read [Limitations](https://trace.agentrust-io.com/LIMITATIONS/index.md) for the scope boundaries before relying on it in production.

TRACE Specification is an [LF Project](https://www.linuxfoundation.org/), hosted at the Linux Foundation as its own series, "TRACE Specification, a Series of LF Projects, LLC", under [LF Projects policies](https://lfprojects.org/policies/). See [Governance](https://trace.agentrust-io.com/GOVERNANCE/index.md) for how decisions are made and [Contributing](https://trace.agentrust-io.com/CONTRIBUTING/index.md) for how to propose a change.
