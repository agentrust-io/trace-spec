# Retained verifier context: replay experiment

Status: experimental; not a TRACE conformance claim.

## Boundary
This work is verifier-side only. Do not add verifier-local policy, keys, resolver outputs, or verification time to the producer-signed Trust Record. Preserve the call-local VerificationResult contract.

## Proposed evidence contract
A durable replay envelope MUST bind: record digest; effective verification time; maximum age and future skew; expected challenge nonce (including explicit absent state); verifier implementation/version; accepted profiles; policy identity and digest; trusted key/root identifiers and immutable digests; revocation source, validity window and evidence digest; resolver URI, immutable resolved-bytes digest and resolution status; and per-check outcomes with stable reason codes. The envelope SHOULD be signed by the verifier and independently stored.

A hash alone does not supply missing evidence. Offline replay is NOT ESTABLISHED when required bytes or configuration are unavailable. Producer signature validity, verifier appraisal, revocation, and replay reproducibility remain separate conclusions.

## Minimum adversarial corpus
- time exactly at freshness boundary and one second beyond
- missing/implicit verification time
- absent nonce versus mismatched nonce
- substituted trust roots and policy digest
- missing, stale, malformed and contradictory revocation evidence
- manifest resolver bytes changed under the same URI
- unresolved evidence with no silent success
- verifier version/profile drift
- reference/independent verifier disagreement, preserving both outputs
- mutation controls demonstrating each rule is load-bearing

## Release gate
Pin upstream commit SHA, both verifier commits, fixtures and toolchains. Run reference and independent implementations without shared verifier libraries or ambient network. Capture input/evidence hashes, both outputs, mismatches, error classification and independent observation. Never report PASS based solely on fixture self-consistency.

Related upstream issues: #342, #407, #446, #483; PRs #376 and #487 require pinned diff review before relying on their precise implementation details.

## Development process capture (non-attested)

The captured_observer.capture helper launches an exact allowlisted argv without
a shell, checks the checked-out repository commit, observes child exit status,
and hashes stdout/stderr. A caller cannot supply the observed exit status.
The signing key and host label are provided by the caller. This does NOT
establish independently enrolled authority, hardware-verified process identity,
authenticated host identity, immutable environment or network isolation.
External trusted enrollment and measured capture remain release blockers.

### Optional Linux network namespace (development only)

capture(..., isolate_network=True) requires bubblewrap and launches the exact
allowlisted command through bwrap --unshare-net. Missing bwrap or a failed child
run causes refusal rather than a signed successful observation. The receipt
records that the namespace was requested. This is a host-local test facility,
NOT a claim of an independently attested sandbox, authenticated kernel, or
confidential execution. Its read-only root still exposes host-readable data;
do not run untrusted code or interpret this as comprehensive isolation.


## About / Trust : software TPM and software TEE lab

This is an **experimental verifier-side test lab** for the TRACE v0.2
retained-context problem. It uses actual `swtpm` (IBM-origin TPM 2.0 emulator)
and `tpm2-tools` commands to generate RSA attestation keys, PCR extensions,
TPM2 signed quotes, and quote/PCR validation. It separately executes a
deterministic source/nonce measurement using `bubblewrap` process isolation,
records the observed process and output digests, and signs that observation
using a development Ed25519 key.

The lab **never** reports these as hardware-backed attestation. Its exact
output statuses are `verified-simulation-only` for the two adapters and
`simulated-evidence-validated` for the joint replay. A software TPM's
Endorsement Key is not a hardware-certified EK, and a Bubblewrap namespace
is not a confidential-computing trusted execution environment.

The `simulation_gate.py` command creates an offline replay bundle containing:
a TRACE record signed with an **ephemeral test-only key**, policy bytes,
trusted public root, revocation snapshot, resolver snapshot, software TPM
quote and PCR event evidence, and separately observed software-execution
evidence. The private keys are **not exported** in the bundle. The manifest
SHA-256 is to be communicated **out of band** to the other verifier.
That hash proves integrity only relative to the trusted communicated value;
it is not an external authority or independent third-party certification.

### Rootless execution

Install the following software from **your operating system's signed package
repositories**, or extract the corresponding distribution packages into a
private directory without using root: `swtpm`, `swtpm-libs`, `libtpms0`,
`tpm2-tools` and any required `libtss2-*` runtime packages. Ensure
`bubblewrap` is available. Their libraries and binary paths are environment
specific; do not vendor these binaries into this repository.

Run, using a clean committed checkout and a new private output directory:

```sh
python simulation_gate.py create \
  --repo /path/to/clean/trace-spec \
  --tools-dir /path/to/tpm2-tool-binaries \
  --swtpm /path/to/swtpm \
  --output /path/to/new/private-evidence-bundle \
  --host operator-controlled-host-label

python simulation_gate.py verify \
  --bundle /path/to/received/private-evidence-bundle \
  --pin sha256:OUT_OF_BAND_MANIFEST_DIGEST \
  --checkquote /path/to/tpm2_checkquote
```

The creator starts a **loopback-only**, user-owned, disposable swtpm instance,
captures real TPM2 quote bytes, executes its process inside a read-only
network-isolated Bubblewrap environment, observes the result, and tears down
its emulator. The verifier uses the actual `tpm2_checkquote` executable
without connecting to the producer's TPM socket. Run the verify command on
another machine, and **reverse the producer/consumer roles**.

Optional live integration tests require `TRACE_SWTPM_BINARY`,
`TRACE_SWTPM_TOOL_DIR`, `TRACE_SWTPM_TCTI` (an independently started fresh
software TPM), and `TRACE_REPLAY_REPO`; absent the integration environment,
the hardware-simulation integration cases explicitly skip rather than
fabricate a pass. A full EDRG run must provision them and demand no new
skips, other than the pre-existing source-tree/distribution version test.

### Scope and exclusions

The software-only pipeline establishes format checking, cryptographic quote
integrity, AK identity relative to a pinned key, challenge binding, PCR
event replay and reference value consistency, signed process observations,
bounded freshness, deterministic output comparison, explicit verification
time, and cross-host differential replay. No external AI model or
production credential is involved.

**Not established:** genuine TPM hardware manufacturer EK certification,
real host measured-boot firmware event logs, physical processor isolation,
SGX/TDX/SEV-SNP attestation chains, approved trusted reference-value
authorities, external auditor key enrollment, independent timestamp service,
or formal TRACE hardware conformance. This limitation is substantive, not
an optional label.

### Licensing, attribution and IP boundary

This fork is based on **agentrust-io/trace-spec** under its repository
`LICENSE`: TRACE normative specification material and the normative
schema are covered by the **Community Specification License 1.0**;
source code, SDKs, tests, and examples are covered by **Apache License 2.0**
unless a file states otherwise. The experimental Python additions are
source/test code within that boundary. `swtpm`, `libtpms`,
`tpm2-tools`, `Bubblewrap`, OpenSSL and Python cryptography dependencies
remain separately owned and licensed by their respective upstream projects;
this repository neither embeds nor relicenses their binaries.

The Frequency/DDC methodologies, private deployment credentials, and code
outside this fork are not distributed or licensed through this experiment.
A simulated quote, self-signed test root, source-level verification, or
operator-generated receipt may not be described as upstream TRACE
certification, independent third-party audit, or hardware attestation.

### Technical glossary

| Experiment / Frequency term | Established technical equivalent |
| --- | --- |
| Frequency EDRG | Evidence-based software release acceptance gate |
| Edge sprint | Bounded implementation and adversarial regression cycle |
| Retained verifier context | Durable snapshot of effective verifier inputs |
| Verifier envelope | Verification input/output provenance manifest |
| Immutable evidence | Content-addressed integrity-checked artifacts |
| Trust root | Out-of-band authenticated public key or certificate authority |
| Reference value | Trusted expected platform measurement (RATS / RFC 9334) |
| Required-layer selection | Effective appraisal policy and PCR selection |
| PCR extension | TPM Platform Configuration Register extend operation |
| Signed quote | TPM2_Quote attestation with signing key and nonce |
| Replay | Re-evaluation of retained bytes and explicit effective time |
| Independent verification | Separate implementation / differential oracle |
| Software TEE | OS namespace sandbox; **not a confidential TEE** |
| Simulated TPM | `swtpm` TPM2 command emulator with software-held keys |
| Observer receipt | Signed process observation / test-execution attestation |
| Not established | Indeterminate / insufficient-evidence decision |
| Fail closed | Reject or withhold positive approval when checks are absent |
| Proof of hardware identity | Vendor/hardware certificate-backed attestation, out of scope |


### Verifier-owned operational enrollment (strict gate)

The initial `simulation_gate.py verify` evaluates a historical replay with
trust selectors retained in its envelope. This is useful for reproducibility
but is **not authorization** of those selectors.

The `verify-enrolled` action requires a **separate, verifier-owned policy
registry** (`frequency-verifier-policy-v1`) whose exact SHA-256 digest
must be supplied to the verifier from an independent channel. The registry
contains allowlisted producer commit and host, record public-key digest,
policy and resolver digests, observer public-key digest, TPM attestation
public-key digest, expected PCR0 value, challenge, allowed maximum freshness
window and policy validity interval. The verifier refuses:

- absent or modified registry pin; non-software assurance status; expired
  or future-dated policy and observation; missing policy fields;
- any substituted signing key, attestation key, source commit, resolver,
  policy, host, reference PCR, or challenge; and
- otherwise cryptographically valid evidence whose effective verification
  time has expired relative to the verifier's current clock.

```sh
python simulation_gate.py verify-enrolled \
  --bundle /path/to/received-evidence \
  --pin sha256:PINNED_EVIDENCE_MANIFEST \
  --checkquote /path/to/tpm2_checkquote \
  --registry /path/to/verifier-owned-policy.json \
  --registry-pin sha256:PREAPPROVED_REGISTRY_DIGEST \
  --verification-time 1792000000
```

**Critical:** The producer must never be permitted to generate or approve the
verifier's registry. Computing a registry from the received evidence afterward
is **test-only trust on first use**, not external enrollment. The live
`test_enrolled_live.py` intentionally uses such a disposable fixture to
prove field enforcement, not independent source authorization. Actual
production enrollment requires an out-of-band operator-approved policy,
a separate owner for its signing/enrollment keys, authenticated provenance,
explicit revocation, and reissuance. There is no automatic enrollment
command, because treating producer values as authorized would defeat the
purpose of the gate.

This path returns `simulation-enrolled-verified`, never
`hardware-attested` or `production-conformant`. It is an additional
**simulation-only operational acceptance condition**. For historical
forensic replay, use the original non-operational replay and retain its
effective verification time; do not rebrand historical replay as fresh
operational authority.
