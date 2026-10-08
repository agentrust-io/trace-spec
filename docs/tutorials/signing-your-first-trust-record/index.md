# Sign Your First Trust Record

This page is for developers producing their first TRACE record, a signed file describing one AI agent run. It explains what the signature protects and what it does not, so you can describe your record honestly.

The steps themselves are in the [quick start](https://trace.agentrust-io.com/docs/quickstart/index.md): install, run one complete script, see the expected output, and watch an edited record get rejected. You sign a record, then check it with a copy of the public key you kept aside.

## What the signature covers

The signature covers every field in the record, plus the public key that matches the signing key. Change anything (the agent's name, the policy fingerprint, the tool-call log, the appraisal, the registry link) and the record needs a new signature.

Technical detail: what exactly gets signed

`sign_record(record, key)` adds the public confirmation key and signs the RFC 8785 canonical representation of every field except `signature`. The confirmation key is part of the signed preimage.

`json.dumps(sort_keys=True)` is not a substitute for RFC 8785 canonicalization. Use the SDK signing function so non-ASCII strings and numeric constraints follow the same rules as verification.

## Keep trust separate

Keep a copy of the public key when you create your demo signing key. In real use, whoever receives a record gets the producer's public key through a channel they already trust. The record cannot tell them which key to trust, since a forger would simply name their own.

The record carries its own copy of the public key (`cnf.jwk`), which ties the record to the key. That does not replace getting the key from a trusted source. `verify_record` asks for a trusted key by default, and checks the record's structure as well as its signature. The option to use the key inside the record only shows the record agrees with itself.

## Describe the evidence honestly

The quick-start record contains made-up claims and a software signature. It does not run an agent, apply any rules, produce a hardware report, or publish to a registry. `appraisal.status="none"` says nobody checked the evidence. Set `affirming` only when an authorized producer really checked it under stated rules.

A software measurement can be a documented fingerprint of the inputs. Use an all-zero measurement only when no commitment is offered. Do not add a placeholder registry URI and describe it as an anchor.

Continue to [verify a received record](https://trace.agentrust-io.com/docs/tutorials/verifying-a-trust-record/index.md), [hardware evidence](https://trace.agentrust-io.com/docs/tutorials/hardware-attestation-platforms/index.md), or [transparency anchoring](https://trace.agentrust-io.com/docs/tutorials/anchoring-to-the-registry/index.md).
