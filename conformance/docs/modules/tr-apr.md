# TR-APR — Appraisal

Tests the evidence appraisal the record carries: the verifier's verdict, who
issued it, which policy it was issued under, and when.

## Required at Level 0+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-APR-001 | `appraisal.status` is one of the four values `schemas/trace-claim.json` enumerates | `affirming`, `warning`, `contraindicated`, `none` | `"verified"`, `"AFFIRMING"`, `7`, absent; also an absent or non-object `appraisal` |
| TR-APR-002 | `appraisal.verifier` is an absolute URI | `https://verifier.example.org` | `nvidia-openshell/0.3.0` (no scheme), a URI carrying whitespace or a control character, absent |
| TR-APR-003 | `appraisal.policy_ref`, when present, is an absolute URI | `https://policies.example.org/appraisal/v3`; absent (optional, skipped) | `./policies/v1`, `ht tp://x` |
| TR-APR-004 | `appraisal.timestamp`, when present, is an integer of epoch seconds and is not in the future | a past epoch second; absent (optional, skipped) | `"1748000042"` (string), a float, a boolean, an epoch second in the future |

## Required at Level 1+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-APR-005 | `appraisal.status` is `affirming` | `affirming` | `none`, `warning`, `contraindicated` |

At Level 0 this check is skipped rather than passed. `docs/levels.md`'s own
minimum conformant Level 0 record carries `"status": "none"`, so a Level 0
record is not asked to affirm.

## Absent optional fields skip, and a skip is not a pass

`policy_ref` and `timestamp` are optional. When either is absent TR-APR reports
a skip, which says the check was not performed. Reporting a pass would say the
field was examined and found sound, and nothing was examined.

## What TR-APR does not do

**It never resolves anything.** TR-APR performs no network access and no
filesystem access, and it takes no resolver. TR-APR-003 checks the *shape of the
name* of the appraisal policy; it does not fetch that policy and does not
compare it against anything.

Resolving a cited object against a declared digest is TR-POL-003's work, on a
different field: `policy.policy_uri` resolved against `policy.bundle_hash`. The
record carries a digest for the enforced policy bundle and no digest for the
appraisal policy, so there is nothing here for a second verifier to compare a
retrieved bundle against. Two fields, two objects, no overlapping assertion.

Because nothing here has a referent to lose, no TR-APR code can report
`UNVERIFIED`, and none appears in the unverified-level table in
`docs/levels.md`. Every check either passes, fails, or skips.

`appraisal.provenance_depth_verified` is not checked. The schema admits it and
no published sentence states what a verifier must do with it, so enforcing
anything about it would be this suite inventing a requirement rather than
testing one.
