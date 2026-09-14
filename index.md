[04 · Evidence: can a third party verify all of it offline, years later?](https://agentrust-io.com/#chain)

# Evidence a third party can check, years later

TRACE specifies the record, anchoring protocol and verification rules that tie an agent run to its workload, policy, data class and tool transcript, so anyone holding the record can verify it offline.

[Create and verify your first record](https://trace.agentrust-io.com/docs/quickstart/index.md) [What this proves, and what it does not](https://trace.agentrust-io.com/LIMITATIONS/index.md)

TL;DR

Spec v0.2 and the [agentrust-trace](https://pypi.org/project/agentrust-trace/) 0.10.0 reference library sign and verify records in software with no cloud account, and a v0.2 signature proves who produced a record and that it has not changed while every hardware field in it is still the producer's claim. The proposed [runtime evidence profile](https://trace.agentrust-io.com/docs/rfcs/runtime-evidence-profile/index.md) grades inlined quotes as platform-attested or attested, and the attested grade is specified but not yet demonstrated.

- **Run it**

  ______________________________________________________________________

  Sign a record, verify it with a separately retained key, and see what a failed check looks like.

  [Quickstart](https://trace.agentrust-io.com/docs/quickstart/index.md)

- **What it proves, and what it does not**

  ______________________________________________________________________

  A signed field is a producer's claim. The verification protocol sets out what a verifier still has to check.

  [Verification protocol](https://trace.agentrust-io.com/docs/verification/index.md)

- **Hardware evidence**

  ______________________________________________________________________

  TRACE carries evidence to verifiers that already exist; the runtime evidence profile uses agent-manifest's TDX verifier. Check a real TDX quote at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

  [Runtime evidence profile](https://trace.agentrust-io.com/docs/rfcs/runtime-evidence-profile/index.md)

- **The chain**

  ______________________________________________________________________

  TRACE is the evidence step. Anchor records in the [TRACE Registry](https://agentrust-io.com/registry/) and score them with the [conformance suite](https://tests.agentrust-io.com).

  [See the chain](https://agentrust-io.com/#chain)

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

## Where to go next

- [TRACE v0.2](https://trace.agentrust-io.com/spec/trace-v0.2/index.md): the normative specification, with the claim set, the anchoring protocol, and the verification rules.
- [Conformance suite](https://tests.agentrust-io.com): score an implementation by conformance level before claiming compliance.
- [Integration guides](https://trace.agentrust-io.com/docs/integration/agt/index.md): emit and consume Trust Records from AGT, cMCP, and sandboxed agent runtimes.

## What it is built on

TRACE profiles existing IETF and IRTF work rather than replacing it: [RFC 9711 (EAT)](https://www.rfc-editor.org/rfc/rfc9711) for the claim envelope, [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334) for the attester, verifier, and relying-party roles, and the SCITT draft for transparency-ledger anchoring.

## Status and governance

The specification is a **Developer Preview**. v0.2 is current and published with a conformance test suite. Read [Limitations](https://trace.agentrust-io.com/LIMITATIONS/index.md) for the scope boundaries before relying on it in production.

TRACE Specification is an [LF Project](https://www.linuxfoundation.org/), hosted at the Linux Foundation as its own series, "TRACE Specification, a Series of LF Projects, LLC", under [LF Projects policies](https://lfprojects.org/policies/). It has also been proposed to the Agentic AI Foundation at the Sandbox stage ([aaif/project-proposals #42](https://github.com/aaif/project-proposals/issues/42), opened 14 September 2026). See [Governance](https://trace.agentrust-io.com/GOVERNANCE/index.md) for how decisions are made and [Contributing](https://trace.agentrust-io.com/CONTRIBUTING/index.md) for how to propose a change.

**Status:** spec v0.2 · agentrust-trace 0.10.0 · specification under the Community Specification License 1.0, code under Apache 2.0 · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
