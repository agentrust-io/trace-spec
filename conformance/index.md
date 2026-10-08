[04 · Evidence: can a third party verify all of it offline, years later?](https://agentrust-io.com/#chain)

# Score a TRACE record against the specification

TRACE is an open format for signed receipts that say what an AI agent ran and what it did ([the terms, in plain English](https://agentrust-io.com/#plain-terms)). This suite takes one of those receipts, called a TRACE record, checks it against the [TRACE specification](https://trace.agentrust-io.com), and tells you the highest conformance level it reaches. It writes a report anyone can reproduce from the record's digest (a fingerprint of its exact bytes) and the suite version. A pass covers that one record; it does not show that a whole product meets every requirement of the specification.

[Score your first record](https://trace.agentrust-io.com/conformance/docs/quickstart/index.md) [What this proves, and what it does not](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md)

TL;DR

[agentrust-trace-tests](https://pypi.org/project/agentrust-trace-tests/) 0.6.2 (Apache-2.0) runs eight modules, each a group of related checks, against a record on your own machine, and writes a report with the record digest, the suite version and the command to reproduce it. A pass describes the record and says nothing about how the agent behaved, and the runtime module (TR-RTE) only checks that the hardware fields are well formed: it does not verify a hardware attestation report (the processor's signed statement of what code it ran) against AMD or Intel.

- **Run it**

  ______________________________________________________________________

  Install the suite, check a sample record, see what failed and why, and produce a report from the same run.

  [Getting Started](https://trace.agentrust-io.com/conformance/docs/quickstart/index.md)

- **What it proves, and what it does not**

  ______________________________________________________________________

  The report is not proof on its own, and it says so on its face. The limitations page sets out, check by check, what a result does and does not tell you.

  [Limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md)

- **Hardware evidence**

  ______________________________________________________________________

  The suite does not check the processor's signed report itself; other tools do that. You can check a real Intel TDX report in your browser at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

  [Runtime module](https://trace.agentrust-io.com/conformance/docs/modules/tr-rte/index.md)

- **The chain**

  ______________________________________________________________________

  AgenTrust covers four steps: the model, the agent, its actions, and the evidence. This suite scores TRACE records, the evidence step. The specification is at [trace.agentrust-io.com](https://trace.agentrust-io.com), and records can be entered in a public, append-only log, the [TRACE Registry](https://agentrust-io.com/registry/).

  [See the chain](https://agentrust-io.com/#chain)

The [eight modules](https://trace.agentrust-io.com/conformance/docs/modules/index.md) each look at one part of a record: the envelope (the outer wrapper and its basic fields), the signature, the runtime (the hardware it says it ran on), the policy (the rules the agent ran under), the appraisal (a verifier's verdict on the hardware evidence), the transcript (the log of tool calls), transparency (proof the record was entered in a public log) and provenance (how the software was built). Read the [limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md) to see what each result does and does not tell you.

```
pip install agentrust-trace-tests
trace-tests verify --record path/to/trust-record.jwt --level 1
```

## A report you can hand to someone else

`verify` prints results for you. `report` writes files you can give to someone who was not there, such as an auditor or a customer.

```
trace-tests report --record trust-record.json --html report.html --json report.json --badge trace.svg
```

- `report` tries every level up to `--max-level`, so the answer is the highest level the record reaches, whichever level you happened to ask about.
- The HTML report is a single file that loads nothing else: no scripts, no fonts, no outside stylesheets, no badge service, nothing fetched when it is opened.

To make a CI pipeline (the automated checks that run on every code change) fail below a level, add `--fail-under 1`. Without it the command always exits `0`, which is what you want when you only need the report. `report.json` keeps a stable layout, `schema: agentrust-io/trace-tests/report/1`, for dashboards and CI.

CLI reports also carry a small pilot section that accounts for three specific checks one by one. It covers those three only, not all of TRACE.

Technical detail: the obligation_accounting pilot

CLI reports add an independently versioned `obligation_accounting` member for a bounded three-obligation pilot: `TR-APR-001`, `TR-POL-003`, and `TR-SCA-002`. The rows and findings come from one execution snapshot, and the report refuses an incomplete pilot matrix. This does not claim complete TRACE accounting. The extension treats `report/1` as additively extensible; compatibility with consumers requiring the exact historical top-level key set is not established. See [Known limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md) for the trust and replay boundary.

Anyone can edit a report, so a report that looks official but cannot be checked is no better than a system vouching for itself. The report therefore tells a reader who does not trust the sender to check the record directly, and gives them what they need to do it.

## Where to go next

- [Conformance Levels](https://trace.agentrust-io.com/conformance/docs/levels/index.md): what each level requires, and what a record has to carry to reach it.
- [Test Modules](https://trace.agentrust-io.com/conformance/docs/modules/index.md): the eight modules, the `TR-*` error codes they emit, and what each one checks.
- [CI integration](https://trace.agentrust-io.com/conformance/docs/tutorials/ci-integration/index.md): gate a pipeline on a level, and write your own conformance tests against the suite.

## Test modules

The table uses the specification's own terms. Each module's page explains them.

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
