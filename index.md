[04 · Evidence: can a third party verify all of it offline, years later?](https://agentrust-io.com/#chain)

# Evidence a third party can check, years later

TRACE is a free, open format for a signed receipt of what an AI agent did: which program ran, under which rules, on what kind of data, and which tools it called. Anyone holding the receipt can check it on their own computer, with no access to the system that produced it. This site is for engineers who produce or check these receipts, and for anyone deciding how much a receipt can be trusted ([the terms, in plain English](https://agentrust-io.com/#plain-terms)).

[Create and verify your first record](https://trace.agentrust-io.com/docs/quickstart/index.md) [What this proves, and what it does not](https://trace.agentrust-io.com/LIMITATIONS/index.md)

TL;DR

With spec v0.2 and the [agentrust-trace](https://pypi.org/project/agentrust-trace/) 0.11.0 Python library you can sign and check records on a laptop, with no cloud account. A v0.2 signature proves who made a record and that nobody changed it afterwards; what the record says about the hardware is still only the producer's word until the proposed [runtime evidence profile](https://trace.agentrust-io.com/docs/rfcs/runtime-evidence-profile/index.md) adds checkable hardware reports, and its top "attested" grade is specified but not yet demonstrated.

- **Run it**

  ______________________________________________________________________

  Sign a record, check it with a key kept somewhere else, and see what a failed check looks like.

  [Quickstart](https://trace.agentrust-io.com/docs/quickstart/index.md)

- **What it proves, and what it does not**

  ______________________________________________________________________

  A signature tells you who said something, not that it is true. The verification page lists what a checker still has to confirm on its own.

  [Verification protocol](https://trace.agentrust-io.com/docs/verification/index.md)

- **Hardware evidence**

  ______________________________________________________________________

  Some processors can produce a signed report of what is running on them (attestation). TRACE carries those reports to existing checkers; the runtime evidence profile uses agent-manifest's checker for Intel TDX reports. Check a real TDX report at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

  [Runtime evidence profile](https://trace.agentrust-io.com/docs/rfcs/runtime-evidence-profile/index.md)

- **The chain**

  ______________________________________________________________________

  TRACE is the evidence step, the last of four. Publish records to the public [TRACE Registry](https://agentrust-io.com/registry/) and test an implementation with the [conformance suite](https://tests.agentrust-io.com).

  [See the chain](https://agentrust-io.com/#chain)

## What the record contains

Each row is a question a reader might ask about an agent run, the part of the record that answers it, and what a checker needs beyond the signature before believing the answer.

| Question                      | Fields to inspect  | What the verifier still needs                                       |
| ----------------------------- | ------------------ | ------------------------------------------------------------------- |
| Which workload is named?      | `subject`, `model` | An authenticated issuer and evidence binding the workload           |
| What runtime is claimed?      | `runtime`          | Valid attestation and approved measurements for hardware provenance |
| Which policy is named?        | `policy`           | Independently approved policy inputs                                |
| What data class is declared?  | `data_class`       | Evidence supporting the producer's classification                   |
| What transcript is committed? | `tool_transcript`  | Transcript evidence when individual calls matter                    |
| Was evidence anchored?        | `transparency`     | A verified receipt and the required log trust policy                |

Every field is the producer's claim. A valid signature alone does not show that the run happened as described or that the rules were actually applied. The [verification protocol](https://trace.agentrust-io.com/docs/verification/index.md) walks through the full set of checks.

## Where to go next

- [TRACE v0.2](https://trace.agentrust-io.com/spec/trace-v0.2/index.md): the specification itself, with the fields, the publishing protocol and the checking rules.
- [Conformance suite](https://tests.agentrust-io.com): test an implementation, level by level, before saying it complies.
- [Integration guides](https://trace.agentrust-io.com/docs/integration/agt/index.md): produce and read Trust Records from AGT, cMCP and sandboxed agent runtimes.

## What it is built on

TRACE reuses published internet standards instead of inventing new ones: [RFC 9711 (EAT)](https://www.rfc-editor.org/rfc/rfc9711) for the claim envelope, [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334) for the attester, verifier, and relying-party roles, and the SCITT draft for transparency-ledger anchoring.

## Status and governance

The specification is a **Developer Preview**: usable now, and still expected to change. v0.2 is current and ships with a conformance test suite. Read [Limitations](https://trace.agentrust-io.com/LIMITATIONS/index.md) for what it does not cover before relying on it in production.

TRACE Specification is an [LF Project](https://www.linuxfoundation.org/), hosted at the Linux Foundation as its own series, "TRACE Specification, a Series of LF Projects, LLC", under [LF Projects policies](https://lfprojects.org/policies/). It has also been proposed to the Agentic AI Foundation at the Sandbox stage ([aaif/project-proposals #42](https://github.com/aaif/project-proposals/issues/42), opened 14 September 2026). See [Governance](https://trace.agentrust-io.com/GOVERNANCE/index.md) for how decisions are made and [Contributing](https://trace.agentrust-io.com/CONTRIBUTING/index.md) for how to propose a change.

**Status:** spec v0.2 · agentrust-trace 0.11.0 · specification under the Community Specification License 1.0, code under Apache 2.0 · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
