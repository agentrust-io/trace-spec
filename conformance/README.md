<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="TRACE Tests"/>
</p>

# TRACE Conformance Test Suite

Community updates and contributor highlights: [AgenTrust on LinkedIn](https://www.linkedin.com/company/agentrust-io/).

### Check a TRACE record and see which conformance level it reaches

<p align="center">
  <a href="https://trace.agentrust-io.com/conformance/">
    <img src="https://img.shields.io/badge/%F0%9F%93%96_Full_Documentation-tests.agentrust--io.com-C17817?style=for-the-badge&logoColor=white" alt="Full Documentation" height="40">
  </a>
</p>

<p align="center">
  <a href="docs/quickstart.md">Quick Start</a> &nbsp;|&nbsp;
  <a href="docs/modules.md">Test Modules</a> &nbsp;|&nbsp;
  <a href="docs/levels.md">Conformance Levels</a> &nbsp;|&nbsp;
  <a href="CHANGELOG.md">Changelog</a>
</p>

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![TRACE Spec](https://img.shields.io/badge/TRACE-Spec_v0.2-0ea5e9)](https://github.com/agentrust-io/trace-spec)
[![Tests](https://img.shields.io/badge/Conformance_Tests-8_modules-green)](docs/modules.md)
[![CI](https://github.com/agentrust-io/trace-spec/actions/workflows/conformance-ci.yml/badge.svg)](https://github.com/agentrust-io/trace-spec/actions/workflows/conformance-ci.yml)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white&style=flat)](https://discord.gg/grgzFEHgkj)

> Tracks [TRACE Spec v0.2](https://github.com/agentrust-io/trace-spec).

Check a TRACE record, inspect the findings, and produce a reproducible conformance report. The suite checks the record and supplied evidence; a passing report does not establish that an entire implementation meets every specification requirement.

Eight modules cover envelope, signature, runtime, policy, appraisal, transcript, transparency, and provenance checks. Read the [limitations](LIMITATIONS.md) to interpret their results.

## Quick start

```bash
pip install agentrust-trace-tests
trace-tests verify --record path/to/trust-record.jwt --level 1 \
  --expected-nonce "$VERIFIER_CHALLENGE"
```

## A report you can hand to someone else

`verify` answers a question for the person running it. `report` produces an artifact for
somebody who was not there: an auditor, a counterparty, an acquirer.

```bash
trace-tests report --record trust-record.json   --html report.html --json report.json --badge trace.svg
```

It runs **every** level up to `--max-level` rather than one, because the useful answer for
a reader is the highest level the record reaches, not whether it cleared the level someone
happened to pick. The HTML is self-contained: no scripts, no fonts, no external CSS, no
badge service, nothing fetched at open time.

Use `--fail-under 1` to gate CI on a level. Without it the command always exits `0`, which
is what you want when you are producing an artifact rather than enforcing a threshold.

**The report is not evidence, and it says so on its face.** It is unsigned HTML describing
one run of one suite version, and anybody can edit it. So it carries the record's digest,
the suite and library versions, and the exact command to reproduce the result. A reader who
does not trust the sender is told, in the artifact, to go check the record instead. A
conformance report that looks authoritative and cannot be checked is the same shape of
thing as a control plane writing its own log.

`report.json` is stable under `schema: agentrust-io/trace-tests/report/1` for dashboards
and CI. Reports produced by the CLI include an additive, version-tagged
`obligation_accounting` object for the bounded `TR-APR-001`, `TR-POL-003`, and
`TR-SCA-002` pilot. During supported report construction, its rows are reconciled
against the executable registry identified by `registry_id` and `registry_sha256`.
The operational `TR-POL-003` rule is identified separately from schema fragments
that support its field shape. Every source locator carries a digest of the exact
resolved value so a reader holding the pinned trace-spec bytes can re-resolve and
compare it. Accounted JSON, HTML, badge, and verdict projections consume one
immutable execution-derived snapshot. A JSON-only request does not pre-render
unrequested formats; when multiple formats are requested, they are emitted in the
CLI's existing order. The existing contribution policy continues to determine the
report verdict.
The tag identifies this emitted object shape; the repository does not currently
ship a separate formal JSON Schema for it.

This treats `report/1` as additively extensible: existing members retain their meaning,
and `obligation_accounting` is the sole new top-level member. Compatibility with
consumers that require the exact historical key set is not established. The report
remains an unsigned self-report; see [Known Limitations](LIMITATIONS.md).

## Test modules

| Module | ID | Tests |
|---|---|---|
| Envelope | `TR-ENV` | EAT structure, required fields, `iat` validity |
| Signature | `TR-SIG` | ES256/ES384/EdDSA, key binding, chain |
| Runtime | `TR-RTE` | TEE platform, measurement format, RIM URI |
| Policy | `TR-POL` | Bundle hash, enforcement mode, TEE binding |
| Transcript | `TR-TXN` | Tool-call transcript hash binding (Phase 2+) |
| Transparency | `TR-ANC` | SCITT receipt URI, inclusion proof |
| Provenance | `TR-SCA` | SLSA level, builder URI, digest format |

## Resources

| | |
|---|---|
| 📖 Full documentation | [tests.agentrust-io.com](https://trace.agentrust-io.com/conformance/) |
| 📄 TRACE Specification | [trace-spec](https://github.com/agentrust-io/trace-spec) |
| 🗂 Test schemas | [schemas/](schemas/) |
| 💬 Discussions | [GitHub Discussions](https://github.com/orgs/agentrust-io/discussions) |
| 📋 Changelog | [CHANGELOG.md](CHANGELOG.md) |
| ⚠️ Known limitations | [LIMITATIONS.md](LIMITATIONS.md) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New test cases must include a normative spec reference, a positive case, and a negative case with a structured error code (`TR-<MODULE>-<NNN>`).

## From a source checkout

```bash
git clone https://github.com/agentrust-io/trace-spec.git
cd trace-spec/conformance
pip install --require-hashes -r requirements/test.txt
pip install --no-deps -e .
python -m pytest
```

The package name and CLI remain unchanged. The original repository retains historical commits used by obligation-accounting source locators. See [the migration record](../docs/repository-consolidation.md) for publishing and documentation cutover work.
