# TRACE retained-context replay: Gap-First EDRG register

Scope: draft PR #2; this register does not assert production acceptance.
Reference: Frequency/docs/GAP-FIRST-EDRG-0001.md (proposed workflow).
Baseline commit: fc05160469b6dd4f1846c48e2afe8f5d107e33da.

| ID | Requirement / evidence | Missing or uncertain condition | Status |
| --- | --- | --- | --- |
| T01 | Exact allowlisted subprocess, committed source, clean Git status and observed output digests | In-process source/executable TOCTOU, ignored/untracked ignored paths, transient mutation | OPEN |
| T02 | Optional Bubblewrap net, pid, IPC, UTS namespaces and capability drop live-tested on VPS | Host-read-only root bind exposes host-readable files; no narrowly scoped filesystem mounts | OPEN |
| T03 | VPS Ed25519 receipt verified from Prometheus; fingerprint-pinned local public key with negative tests | Initial enrollment from self-operated VPS is not independent, host label self-asserted | OPEN |
| T04 | Existing VPS development PEM key signs captures | Hardware/key-service custody, rotation, revocation and access audit unproven | OPEN |
| T05 | Real two-host signing and signature/tamper rejection demonstrated | Authenticated remote observation origin and independently governed verifier not demonstrated | OPEN |
| T06 | Full local pytest baseline 1,100 passed, 1 skipped on 8978126; live namespace launch tested on fc05160 | Hosted CI/CodeQL and suite must be rerun on every final SHA; skipped test requires explanation | OPEN |
| T07 | Retained receipt format carries commit, command, exit, output digests | Pinned runtime, OS/container measurement, build/dependency provenance and time freshness not enforced | OPEN |
| T08 | Fork PR #2 remains draft | External upstream review, license/attribution/About/glossary and release documentation assessment needed | OPEN |
| T09 | Production approval | No independent external trust authority designated or enrolled | EXTERNALLY-BLOCKED |

## Live smoke observation: Prometheus, 2026-10-15

A restricted Bubblewrap command was executed on Prometheus, using an empty
sandbox root, runtime-only /usr, /bin, /lib, /lib64 binds and a read-only
Frequency checkout bind. The observed Python process reported that
/etc/passwd was absent and the checkout README was present. A second
runtime-only launch also succeeded. These are operator-origin smoke
observations, not signed, independently captured evidence. They do not
verify the TRACE observer's full execution path, hostile workloads, races,
signer custody, external trust, or the VPS. T02 remains OPEN pending
end-to-end sandbox and negative tests on the exact release artifact.


## Executable operator acceptance: Prometheus, 2026-10-15

On the authorized Prometheus Ubuntu host, a clean, depth-one checkout at commit
61d193be45b1d338c35e4253734e3cb789ea8be2 was used for a bounded test.
The current experiment's retained-evidence, observer and reference-adapter
unit suites passed 19/19 under local Python 3.14.4.

The actual captured_observer.capture code (not only a manually constructed
Bubblewrap command) ran /usr/bin/true with isolation requested and returned
exit 0. An ephemeral Ed25519 test signing key produced a receipt that verified
with the matching public key. Additional permitted-process checks established
that /etc/passwd was not visible and that a socket connection to 1.1.1.1:443
was refused inside the isolated process. A process attempting to overwrite
the checkout README was refused without a signed successful observation.
These checks used an operator-controlled host, key and test procedure.

Evidence classification: OPERATOR-LIVE, not independent. No signed artifact
bundle, trusted timestamp, externally enrolled public key, third-party
observer, hardware measurement or VPS peer has been established. This
observation proves bounded execution on the tested SHA, not general sandbox
escape resistance, source TOCTOU protection, or independent acceptance.
T01, T02 and T05 remain OPEN; T09 remains EXTERNALLY-BLOCKED.

## Persistent operator-key trial: 2026-10-15

A persistent Ed25519 observer signing key was created on the VPS under a
restricted user-owned key directory; the corresponding 32-byte public key
was pinned in a separate restricted directory on Prometheus. Its SHA-256
fingerprint was f1a5093adb64d7e1710bd9bd25b59c1b96d986f239e649e05875d32752c524e8.
The private key was not transferred to Prometheus or placed in this repo.

At the pinned source revision
aed444729430b01c92ff44e86894d8d7d3ba48fe, the actual observer on
the VPS ran the allowlisted /usr/bin/true workload under Bubblewrap and
signed the exit-zero observation with that persistent key. Prometheus
verified the receipt through verify_pinned with the enrolled public-key
fingerprint, expected source commit and asserted host label. Four
negative cases were rejected: tampered exit code, wrong host label,
wrong source commit and wrong pinned fingerprint.

This is OPERATOR-KEY-CONTINUITY evidence only. Both endpoints, key
creation and enrollment are operator-controlled. No independent
authority approved the enrollment, no trusted clock or replay-resistant
challenge was verified, and no TPM/TEE attestation was produced.
The private key is stored in user-controlled software storage, not a
hardware-protected signing service. T03/T04/T05/T09 therefore remain
open or externally blocked at the stronger production-assurance level.

## Mandatory negative acceptance

Wrong public key, wrong fingerprint, wrong commit/host, modified receipt,
expired/revoked key, untrusted checkout, dependency absent, sandbox refusing,
network access attempts, filesystem escape, process and IPC escape, interrupted
run, race against source/executable, stale replay, and altered retained evidence.
Each requires an executable test and pinned evidence; otherwise NOT-EVALUATED.

## Candidate implementation approaches

A. Harden Bubblewrap with minimal read-only executable/runtime mounts, an
isolated worktree, no ambient host-home mount, privilege drop, tmpfs and bounded
resource limits, paired with a keyring-backed signer and separately enrolled key.

B. An existing OCI/WASI constrained runtime with measured image digest, separate
signing service, and remotely provisioned verification policy. Evaluate available
toolchain and actual host permissions before selecting or deploying either.

Do not conflate separate user-operated VPS/Prometheus with an independent third
party. Neither approach alone supplies third-party attestation.

## Release decision

BLOCKED: T01-T09 are not all verified; green CI does not override this gate.
