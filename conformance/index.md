[04 · Evidence: can a third party verify all of it offline, years later?](https://agentrust-io.com/#chain)

# Score a TRACE record against the specification

The suite checks one record and the evidence supplied with it, reports the highest conformance level reached, and writes a report anyone can reproduce from the record digest and suite version. A passing report does not establish that an entire implementation meets every requirement of the [TRACE specification](https://trace.agentrust-io.com).

[Score your first record](https://trace.agentrust-io.com/conformance/docs/quickstart/index.md) [What this proves, and what it does not](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md)

TL;DR

[agentrust-trace-tests](https://pypi.org/project/agentrust-trace-tests/) 0.6.2 (Apache-2.0) runs eight modules against a record on your machine and writes a report carrying the record digest, the suite version and the command to reproduce it. A pass describes the record and says nothing about the agent, and TR-RTE checks the shape of attestation fields without verifying a quote against AMD or Intel roots.

- **Run it**

  ______________________________________________________________________

  Score a record, read the failures, and produce a report from the same run.

  [Getting Started](https://trace.agentrust-io.com/conformance/docs/quickstart/index.md)

- **What it proves, and what it does not**

  ______________________________________________________________________

  The report is not evidence, and it says so on its face. Each result's scope is set out module by module.

  [Limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md)

- **Hardware evidence**

  ______________________________________________________________________

  Quote verification happens outside the suite. Check a real Intel TDX quote at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

  [Runtime module](https://trace.agentrust-io.com/conformance/docs/modules/tr-rte/index.md)

- **The chain**

  ______________________________________________________________________

  The suite scores TRACE records, the evidence step. The specification is at [trace.agentrust-io.com](https://trace.agentrust-io.com), and records can be anchored in the [TRACE Registry](https://agentrust-io.com/registry/).

  [See the chain](https://agentrust-io.com/#chain)

The [eight modules](https://trace.agentrust-io.com/conformance/docs/modules/index.md) cover envelope, signature, runtime, policy, appraisal, transcript, transparency, and provenance checks. Read the [limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md) to interpret what each result establishes.

```
pip install agentrust-trace-tests
trace-tests verify --record path/to/trust-record.jwt --level 1
```

## A report you can hand to someone else

```
trace-tests report --record trust-record.json --html report.html --json report.json --badge trace.svg
```

- `verify` answers a question for the person running it. `report` produces an artifact for somebody who was not there.
- `report` runs every level up to `--max-level`, because the useful answer is the highest level a record reaches, not whether it cleared the level someone happened to pick.
- The HTML report is self-contained: no scripts, no fonts, no external CSS, no badge service, nothing fetched when it is opened.

Use `--fail-under 1` to gate CI on a level. Without it the command always exits `0`, which is what you want when you are producing an artifact rather than enforcing a threshold. `report.json` is stable under `schema: agentrust-io/trace-tests/report/1` for dashboards and CI.

CLI reports add an independently versioned `obligation_accounting` member for a bounded three-obligation pilot: `TR-APR-001`, `TR-POL-003`, and `TR-SCA-002`. The rows and findings come from one execution snapshot, and the report refuses an incomplete pilot matrix. This does not claim complete TRACE accounting. The extension treats `report/1` as additively extensible; compatibility with consumers requiring the exact historical top-level key set is not established. See [Known limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md) for the trust and replay boundary.

A conformance report that looks authoritative and cannot be checked is the same shape of thing as a control plane writing its own log. So the report tells a reader who does not trust the sender to go and check the record instead, and gives them what they need to do it.

## Where to go next

- [Conformance Levels](https://trace.agentrust-io.com/conformance/docs/levels/index.md): what each level requires, and what a record has to carry to reach it.
- [Test Modules](https://trace.agentrust-io.com/conformance/docs/modules/index.md): the eight modules, the `TR-*` error codes they emit, and what each one checks.
- [CI integration](https://trace.agentrust-io.com/conformance/docs/tutorials/ci-integration/index.md): gate a pipeline on a level, and write your own conformance tests against the suite.

## Test modules

| Module       | ID       | Tests                                                       |
| ------------ | -------- | ----------------------------------------------------------- |
| Envelope     | `TR-ENV` | EAT structure, required fields, `iat` validity              |
| Signature    | `TR-SIG` | ES256/ES384/EdDSA, key binding, chain                       |
| Runtime      | `TR-RTE` | TEE platform, measurement format, RIM URI                   |
| Policy       | `TR-POL` | Bundle hash, enforcement mode, TEE binding                  |
| Appraisal    | `TR-APR` | Appraisal status, verifier URI, policy reference, timestamp |
| Transcript   | `TR-TXN` | Tool-call transcript hash binding (Phase 2+)                |
| Transparency | `TR-ANC` | SCITT receipt URI, inclusion proof                          |
| Provenance   | `TR-SCA` | SLSA level, builder URI, digest format                      |

The suite tracks [TRACE Spec v0.2](https://trace.agentrust-io.com). See [Changelog](https://trace.agentrust-io.com/conformance/CHANGELOG/index.md) for what moved between suite versions.

**Status:** agentrust-trace-tests 0.6.2 · Apache-2.0 · tracks TRACE Spec v0.2 · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
