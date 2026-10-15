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
