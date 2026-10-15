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
