# TR-POL: Policy

Checks the record's link to the policy bundle, the file of rules the agent ran under (written in Cedar, a policy language). The record carries the bundle's digest (a fingerprint of its bytes) and how strictly the rules were applied; when you supply the bundle, the suite confirms the fingerprint matches.

## Required at Level 0+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-POL-001 | `policy.bundle_hash` is a valid `sha256:` or `sha384:` digest | `sha256:` + 64 hex chars, `sha384:` + 96 hex chars | missing, wrong prefix, wrong length |
| TR-POL-002 | `policy.enforcement_mode` is `enforce`, `advisory`, `silent`, or `declared` | `enforce` | `strict`, `monitor`, absent |
| TR-POL-003 | `policy.policy_uri` is an absolute URI, and the bundle it resolves to has the digest `policy.bundle_hash` declares; when the verifier supplies an expected policy hash, the declared policy is that one | absent `policy_uri`; or a resolved bundle whose digest matches | relative reference, whitespace in the URI, resolved bundle with a different digest, a policy other than the expected one |

## Resolving the bundle

TR-POL-003 needs somewhere to fetch the bundle from. The resolver is supplied
by the caller and never derived from the record, because a record that named its own
resolver could name one that agrees with it. From the CLI that is `--policy-dir
DIR`, where `DIR/resolutions.json` maps each `policy_uri` to a relative path
inside `DIR`:

```
trace-tests verify --record record.json --policy-dir ./bundles
```

Without it the resolution part of the check skips, so offline verification
stays a first-class use rather than a degraded one. An expected policy hash, if
supplied, is still compared offline (see below).

## Checking the expected policy

A matching digest shows the resolved bundle is the one the record cited. It
does not show that bundle is the policy the verifier expects, which is what
specification §3.3 step 5 asks. That expectation is verifier context, like the
resolver, and is supplied the same way:

```
trace-tests verify --record record.json --policy-dir ./bundles \
    --expected-policy-hash sha256:<hex of the expected bundle>
```

TR-POL-003 then fails a record that declares any other policy, even one whose
digest matches what `policy_uri` resolves to. Digests using the same algorithm
are compared before resolution, even without `policy_uri`. When the algorithms
differ, the comparison requires resolved bytes, and missing bytes do not
establish a match. The finding says the expectation was not compared. Without
`--expected-policy-hash` the check behaves as it always has.

**A malformed `policy_uri` is reported with or without a resolver.** A
reference the record got wrong is a defect in the record, visible with no
network at all, exactly like the digest shape TR-POL-001 tests. A referent that
could not be fetched is not: that is reported as unverified, and only when a
resolver was supplied and failed.
