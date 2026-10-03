# TR-POL — Policy

Tests Cedar policy bundle binding.

## Required at Level 0+

| Test ID    | Description                                                                                                        | Positive Case                                                  | Negative Case                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| TR-POL-001 | `policy.bundle_hash` is a valid `sha256:` or `sha384:` digest                                                      | `sha256:` + 64 hex chars, `sha384:` + 96 hex chars             | missing, wrong prefix, wrong length                                                |
| TR-POL-002 | `policy.enforcement_mode` is `enforce`, `advisory`, `silent`, or `declared`                                        | `enforce`                                                      | `strict`, `monitor`, absent                                                        |
| TR-POL-003 | `policy.policy_uri` is an absolute URI, and the bundle it resolves to has the digest `policy.bundle_hash` declares | absent `policy_uri`; or a resolved bundle whose digest matches | relative reference, whitespace in the URI, resolved bundle with a different digest |

## Resolving the bundle

TR-POL-003 needs somewhere to fetch the bundle from. The resolver is supplied by the caller and never derived from the record — a record that named its own resolver could name one that agrees with it. From the CLI that is `--policy-dir DIR`, where `DIR/resolutions.json` maps each `policy_uri` to a relative path inside `DIR`:

```
trace-tests verify --record record.json --policy-dir ./bundles
```

Without it the resolution part of the check skips, so offline verification stays a first-class use rather than a degraded one.

**A malformed `policy_uri` is reported with or without a resolver.** A reference the record got wrong is a defect in the record, visible with no network at all, exactly like the digest shape TR-POL-001 tests. A referent that could not be fetched is not: that is reported as unverified, and only when a resolver was supplied and failed.
