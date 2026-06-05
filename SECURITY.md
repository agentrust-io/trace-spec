# Security Policy

## Scope

This repository contains a specification and machine-readable schema. Security issues fall into two categories:

**Specification vulnerabilities** — flaws in the TRACE spec that would allow an attacker to forge a valid Trust Record, bypass verification, break the cryptographic chain, or make verifiable claims that are structurally false. These are the most serious and are treated as critical.

**Implementation vulnerabilities** — flaws in reference examples or schema that could mislead implementors into producing insecure Trust Records. Report these here.

Vulnerabilities in the reference implementation (cMCP) should be reported at [agentrust-io/cmcp](https://github.com/agentrust-io/cmcp) using its security policy.

## Reporting

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by email to: **security@opaque.co**

Include:
- A description of the vulnerability and the affected spec section or schema path
- The attack scenario: what can an attacker do, what invariant is broken
- Whether you believe this affects existing Trust Records produced by conformant implementations
- Your preferred disclosure timeline

## Response SLAs

| Severity | Initial response | Fix target |
|---|---|---|
| Critical (forgeable Trust Record, broken verification chain) | 24 hours | 7 days |
| High (misleading schema, incorrect normative text) | 48 hours | 14 days |
| Medium / Low (editorial, non-normative) | 5 business days | Next spec patch |

## Disclosure

We follow coordinated disclosure. We will work with reporters to agree on a disclosure timeline before publishing any advisory. We will credit reporters in the changelog unless they prefer to remain anonymous.

## Supported versions

| Version | Supported |
|---|---|
| v0.1 (current) | Yes |
| Earlier drafts | No |
