# Sign Your First Trust Record

Sign a complete standalone TRACE record, then verify it using a separately retained public key. Start with the [quick start](../quickstart.md), which includes the source installation, complete script, expected output, and an edited-record rejection.

## What the signature covers

`sign_record(record, key)` adds the public confirmation key and signs the RFC 8785 canonical representation of every field except `signature`. The confirmation key is part of the signed preimage. Changing the subject, policy hash, transcript, appraisal, or transparency reference requires a new signature.

`json.dumps(sort_keys=True)` is not a substitute for RFC 8785 canonicalization. Use the SDK signing function so non-ASCII strings and numeric constraints follow the same rules as verification.

## Keep trust separate

Retain the public key when creating your local demo authority. A recipient of a production record obtains its trusted issuer key through an approved channel; the incoming record cannot choose that authority.

The embedded `cnf.jwk` supports key binding. It does not remove the need to distribute trust. `verify_record` requires a trusted key by default and performs schema/profile validation as well as signature verification. The explicit embedded-key option checks internal consistency only.

## Describe the evidence honestly

The quick-start record contains synthetic claims and software signing. It does not run an agent, enforce policy, produce hardware attestation, or submit to a registry. `appraisal.status="none"` records that no appraisal was performed. Set `affirming` only for an appraisal actually performed by an authorized producer under a stated policy.

A software measurement can be a documented commitment to inputs. Use an all-zero measurement only when no commitment is offered. Do not add a placeholder registry URI and describe it as an anchor.

Continue to [verify a received record](verifying-a-trust-record.md), [hardware evidence](hardware-attestation-platforms.md), or [transparency anchoring](anchoring-to-the-registry.md).
