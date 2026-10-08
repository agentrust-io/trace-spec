# RFC Proposal: composite component appraisal, and knowing which part failed

Today a TRACE record gives one verdict for the whole agent. This proposal gives each part (the code, the model, the policy, the processor, the tools) its own verdict, so that when something fails the reader can see which part and fix the right thing. It is for people who write verifiers or set access rules for agents. It is a draft and binds nothing yet.

**Status:** Draft proposal. Binds nothing. **Scope:** Components with stable IDs, a status per component, digest-bound evidence references, freshness, two relationship methods, delegated component appraisers, and a composite result the verifier derives rather than reads. Additive; every v0.2 record stays valid. **Target:** the verifier-issued token in the companion proposal, [`verifier-issued-trace-profile.md`](https://trace.agentrust-io.com/docs/rfcs/verifier-issued-trace-profile/index.md), and `spec/` only if both are adopted. **Conformance material:** [`examples/verifier-token-conformance/`](https://github.com/agentrust-io/trace-spec/tree/main/examples/verifier-token-conformance): 110 component vectors out of 218, `codes.json` with 54 reason codes, and `coverage.json` mapping each requirement to its vectors and causal test. **Implementations:** a Python reference in `prototype/verifier_token.py`, and a second verifier in JavaScript, [`tools/independent-verifier/`](https://github.com/agentrust-io/trace-spec/tree/main/tools/independent-verifier). **Experimental text:** [`docs/verifier-token-experimental.md`](https://trace.agentrust-io.com/docs/verifier-token-experimental/index.md), including the sections "Delegated component appraisal" and "Relationship methods".

Requirement keywords are lowercase throughout, deliberately, on the line `CONTRIBUTING.md` draws: normative text lives in `spec/`, informative text binds no implementation. If these rules are adopted they become uppercase there and this file becomes a pointer to where they went. A proposal that writes itself in the imperative is a specification nobody agreed to.

______________________________________________________________________

## 1. What exists today

A v0.2 Trust Record has one `runtime` object, one `measurement` and one `appraisal`. That is one answer for the whole agent.

An agent is several things at once: the code that ran, the model, the policy, the CPU platform under it, maybe an accelerator, the MCP servers it calls and the tool catalog they serve. Each of these has its own evidence, its own appraiser and its own expiry. When one of them goes bad, the relying party needs to know which one, because the fix is different. A stale tool catalog means re-scan. A CPU below the vendor firmware floor means move the workload.

Here is the case that made this concrete for us. On 30 September an agent on an Azure SEV-SNP VM produced execution evidence (vTPM quote, UEFI event log, IMA log), and the verifier appraised the code that ran as the approved build. The same packet, appraised for platform collateral, showed the host at `TCB[SNP]` 24 against a vendor floor of 27. The code was right and the platform was below the floor. A single `appraisal.status` cannot say both, and whichever one it picks hides the other.

So the record needs, for each part: an ID the relying party can write policy against, a status, the evidence it rests on, who appraised it, until when, and how it is tied to the other parts. The companion proposal gives the verifier a signed, holder-bound token. This proposal is what goes inside that token.

## 2. Components

A component is one appraised part of the agent, as the verifier saw it:

```
{
  "component_id": "runtime.cpu",
  "component_type": "runtime",
  "profile": "amd-snp-collateral-experimental-v1",
  "authority": "https://verifier.example.test",
  "instance": "azure-vm/ca2...",
  "status": "contraindicated",
  "appraised_at": 1790683200,
  "fresh_until": 1790683500,
  "evidence_refs": [
    {
      "profile": "amd-snp-collateral-experimental-v1",
      "media_type": "application/vnd.agentrust.azure-snp-execution+json",
      "digest": "sha256:a3e76f386d3ab1a15dcdbf827b6c9e987ea5d909ac5c81cc7ec10ebad6f2afe7",
      "resolver": null
    }
  ],
  "observed_digest": null,
  "reasons": ["tcb_snp_below_floor"]
}
```

That object is not illustrative. It is what `snp_collateral.tcb_component` produces for the saved Genoa packet from 29 September, with the instance truncated, and it is the `runtime.cpu` in the worked example in §7.

| Member                        | Required | Meaning                                                                                        |
| ----------------------------- | -------- | ---------------------------------------------------------------------------------------------- |
| `component_id`                | yes      | stable, case-sensitive, opaque; unique within the token                                        |
| `component_type`              | yes      | one of ten categories, below                                                                   |
| `profile`                     | yes      | the appraisal profile that produced the status                                                 |
| `authority`                   | yes      | who appraised it; the token issuer unless delegated (§5)                                       |
| `instance`                    | yes      | the workload instance the evidence came from; must equal the token's                           |
| `status`                      | yes      | one of six values, below                                                                       |
| `appraised_at`, `fresh_until` | yes      | the component's own validity interval                                                          |
| `evidence_refs`               | yes      | profile, media type and SHA-256 digest of each evidence object; `resolver` is an optional hint |
| `observed_digest`             | no       | what was observed, when a requirement pins an expected value                                   |
| `reasons`                     | yes      | stable, minimally revealing reason codes                                                       |
| `appraisal`                   | no       | a delegated appraiser's signed copy of this component (§5)                                     |

The schema, `schema/trace-token-experimental-v1.json`, closes each of these objects with `additionalProperties: false`.

**IDs.** `component_id` matches `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$` and is compared byte for byte. A relying party does not infer trust from a prefix: `runtime.cpu` means nothing more than a key the requirements also use. Duplicates are rejected with `duplicate_component`, and a case variant such as `Runtime.cpu` does not satisfy a requirement for `runtime.cpu`. The ID vectors cover a case variant, an empty ID and a Unicode-confusable pair.

**Categories.** `identity`, `code`, `model`, `policy`, `runtime`, `accelerator`, `mcp-server`, `tool-catalog`, `guardrail`, `data-state`. The set is closed in this experiment: an unknown category is `malformed_payload`, on a required component and on an optional one. How new categories get registered is an open question (§11).

**Status.** `affirming`, `warning`, `contraindicated`, `unverifiable`, `missing`, `not-appraised`. The four that are not `affirming` or `warning` never count as affirming. `unverifiable` and `contraindicated` are kept apart on purpose: "I could not check it" and "I checked it and it is wrong" lead to different operator actions.

**Evidence references.** Each reference carries a digest of the evidence object the appraiser actually held. An `affirming` or `warning` component with no reference is rejected with `evidence_missing`. A reference whose profile differs from its component's profile is `evidence_profile_mismatch`. A reference is a pointer the verifier signed, and the verifier signing it proves only that the verifier referred to it. §9 says what that does and does not establish.

**Freshness.** `appraised_at` must not be later than the token's `iat` (`component_interval`), and `fresh_until` must not exceed `appraised_at` plus the requirement's `maximum_age_seconds` (`component_age_bound`). A component that is fresh at issuance and stale a minute later cannot hide behind a fresh token, because §6 bounds the token by it.

## 3. Requirements come from the relying party

The token does not say what was required. The relying party does, in locally trusted requirements (`schema/trace-requirements-experimental-v1.json`):

```
{
  "components": [
    {"component_id": "application.code", "component_type": "code", "required": true,
     "accepted_profiles": ["azure-snp-vtpm-ima-execution-experimental-v1"],
     "accepted_authorities": ["https://verifier.example.test"],
     "maximum_age_seconds": 300},
    {"component_id": "runtime.cpu", "component_type": "runtime", "required": true,
     "accepted_profiles": ["amd-snp-collateral-experimental-v1"],
     "accepted_authorities": ["https://verifier.example.test"],
     "maximum_age_seconds": 300}
  ],
  "bindings": [
    {"source": "runtime.cpu", "target": "application.code",
     "relationship": "same-workload", "method": "same-evidence-v1"}
  ],
  "allow_warnings": false
}
```

The required set is every component marked `required`, plus both ends of every required binding. A component in the token that no requirement declares is `undeclared_component`; a binding nobody asked for is `undeclared_binding`. An optional component that is absent is not a failure, and an optional component's earlier `fresh_until` does not shorten the composite.

A signed Agent Manifest can contribute requirements. The experimental bridge intersects its accepted profiles and authorities with the relying party's own and uses the tighter age limit, so a signed declaration can narrow what is accepted and cannot introduce a trust anchor.

## 4. Relationships

Two components that are each fine can still come from different machines. A binding says two components belong to one workload, and names the method that checks it:

```
{
  "source": "runtime.cpu",
  "target": "application.code",
  "relationship": "same-workload",
  "method": "same-evidence-v1",
  "status": "affirming",
  "digest": "sha256:790d573e030c43e66e05c7c80f85ba90d067c6235d027642ef10faddf1988974",
  "fresh_until": 1790683500
}
```

`relationship` has one value today, `same-workload`. `method` has two.

**`same-instance-v1`.** Both endpoints must be present, both `instance` values must equal the token's `instance` (`mixed_instance` otherwise), the binding's `fresh_until` must not exceed either endpoint's (`binding_interval`), and `digest` must recompute. This authenticates the issuer's statement that the two belong together. It does not prove a hardware relationship.

**`same-evidence-v1`.** Everything `same-instance-v1` checks, and then the source and target must each list an `evidence_refs` entry with the same `digest`. If the two digest sets do not intersect, the token is rejected with `binding_evidence_disjoint`. Only the digest is compared. The two entries may name different profiles and media types, because two appraisal profiles can read one evidence object, and in §7 they do. The method is part of the binding's identity, so a requirement for `same-evidence-v1` is not met by a `same-instance-v1` binding.

**The binding digest.** SHA-256 over the JCS form of `{"method", "source", "target"}`, where `source` and `target` are the two component objects exactly as they appear in the signed payload. A verifier adds no defaults: an optional member absent from the wire stays absent from the preimage. The digest therefore changes if either component changes after the binding was computed, including its status, its evidence and its `appraisal` member.

**A missing endpoint.** A required binding whose source or target is absent evaluates as `missing`, and its digest is not evaluated. The token stays well formed and its composite cannot be `affirming`.

The last two rules were not in the first draft of the experimental text. §8.1 is where they came from.

## 5. Delegated component appraisers

The token issuer is not always the right party to appraise every part. A platform collateral service knows TCB floors and CRLs. A model registry knows weights. By default the token issuer is the only accepted authority, and a component whose `authority` is anyone else is `unverifiable`. A relying party may also configure trusted appraisers next to its trusted issuers.

Each entry is keyed by `(authority, kid)`, where `kid` is SHA-256 of the raw 32-byte Ed25519 public key, and grants a non-empty set of evidence profiles, a non-empty set of component types and a validity interval `[valid_from, valid_until)`. With no entries, nothing changes.

A delegated component carries an `appraisal` member: canonical unpadded base64url, 1 to 16384 characters, of a COSE_Sign1 envelope with profile `urn:agentrust:trace:component-appraisal:experimental-v1`. The envelope rules are the token's. The payload is closed:

```
{"profile": "urn:agentrust:trace:component-appraisal:experimental-v1",
 "iss": "<appraiser authority>",
 "component": {"<the component exactly as carried, without appraisal>": "..."}}
```

The verifier evaluates it after the component's type, observation, instance, interval, age and evidence checks:

1. No `appraisal`: nothing further. A component whose authority is not `iss` stays `unverifiable`.
1. `appraisal` present on a component the token issuer appraised: `component_appraisal_unexpected`.
1. Strict base64url decode, then envelope and closed-payload rules. Any failure: `component_appraisal_malformed`.
1. Look up the configured appraiser by the component's `authority` and the protected `kid`. None, or `now` outside its interval: `unverifiable`, not a rejection.
1. Signature under that key. Failure: `component_appraisal_signature_invalid`.
1. The signed `iss` must equal the carried `authority`, and the signed `component` must equal the carried component minus `appraisal`. Otherwise `component_appraisal_mismatch`.
1. The component's profile and type must be inside the grant. Otherwise `unverifiable`.

A component that passes all seven counts as appraised by an accepted authority. It is still subject to the requirement's `accepted_profiles` and `accepted_authorities`; delegation never widens them.

The component is nested rather than merged, because it already has its own `profile` member. The signed component's `instance` must equal the token's, so the appraisal cannot move to another workload. It is deliberately not bound to the carrying issuer: any trusted issuer may carry it, and the appraiser signed the result. The relying party trusts the appraiser for its grant the way it trusts an issuer.

## 6. The composite is derived, never read

The token carries a `composite_appraisal`:

```
{"status": "contraindicated",
 "required_components": ["application.code", "runtime.cpu"],
 "policy": {"id": "https://verifier.example.test/policy", "version": "1", "digest": "sha256:cccc..."},
 "fresh_until": 1790683320}
```

The verifier recomputes all four members from the requirements, the component results, the binding results and the policy, and rejects the token with `composite_inconsistent` if any member differs. The issuer's composite is a claim the relying party checks, and it has no authority of its own.

The derivation:

- A required component that is absent is `missing`. One whose profile or authority is not accepted, or whose authority is not the issuer and has no accepted delegated appraisal, is `unverifiable`. Otherwise it contributes its own status.
- Each required binding contributes `missing` if absent, else its own status.
- With `allow_warnings` false, a `warning` counts as `contraindicated`.
- The worst status wins, in this order: `contraindicated`, `missing`, `unverifiable`, `not-appraised`.
- The token's `exp` must not exceed the earliest `fresh_until` of any present required component or required binding (`expiry_exceeds_evidence`), and `now` must be before it (`component_expired`). The composite's `fresh_until` is the earliest of the token's `exp` and those same boundaries, so a composite never outlives its token.

`required_components` is rederived too, so an issuer cannot drop a failing component from the list. `COMP-COMP-002` empties it and is rejected.

## 7. Worked example: platform collateral as components

All of this runs on saved captures from real SEV-SNP hardware, not minted bytes.

**Two components from one packet.** The 29 September Azure packet `b1-approved` (in `tests/fixtures/azure-execution-20260929/`) was appraised twice, by two profiles:

- `application.code`, from `azure_execution_binding.execution_component`. The chain is AMD root, VCEK, SNP report, HCL runtime data, vTPM attestation key, then a quote over PCRs 0 to 10, with PCR 10 replayed from the IMA log. It establishes which files were executed since boot. Status `affirming`, `observed_digest` the approved agent build.
- `runtime.cpu`, from `snp_collateral.tcb_component`. It runs after that chain is authenticated and enforces what the chain alone does not: product-line agreement across VCEK, ASK, pinned ARK and CPUID; the VCEK-certified TCB equal to the signed reported TCB; the relying party's TCB floor; a current ARK-signed CRL from AMD KDS with the ASK not on it; and the OS half of a mitigation, proved by the report's mitigation vector or reported as unproved.

Both cite `sha256:a3e76f38...`, the canonical digest of the packet, under different profiles. A `same-evidence-v1` binding between them holds.

**The honest verdict is contraindicated.** The floor is [AMD-SB-3016](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3016.html) (published 2026-04-14): `TCB[SNP] >= 0x1B` for Milan and Genoa, plus an OS update signalled by mitigation vector bit 2.

| Host                         | Report | Reported TCB (bl/tee/snp/ucode) | Firmware | `runtime.cpu`                            |
| ---------------------------- | ------ | ------------------------------- | -------- | ---------------------------------------- |
| Genoa, 29 September          | v3     | 10/0/23/84                      | 1.55.40  | `contraindicated`, `tcb_snp_below_floor` |
| Milan, live run 30 September | v3     | 4/0/24/219                      | 1.55.29  | `contraindicated`, `tcb_snp_below_floor` |

Both hosts are genuine and both are below the floor. Version 3 reports carry no mitigation vector, so the OS half of SB-3016 cannot be proved on these hosts even at the floor. The token for `b1` verifies with a `contraindicated` composite, and the relying party can see that `application.code` is `affirming` and `runtime.cpu` is the reason. That is the answer §1 asked for.

**The affirming path, shown with a counterfactual floor.** With a relying-party floor of `TCB[SNP] 0x17`, which the Genoa host meets, the same pair affirms end to end. This is not a claim that the host meets SB-3016. It shows that the composite moves when, and only when, the component moves.

**Substitution fails.** A `runtime.cpu` appraised from another packet, either the `b2` packet (`sha256:8035ce62...`) or the live Milan packet (`sha256:d9a32379...`), shares no evidence digest with `application.code` from `b1`. Under `same-evidence-v1` the token is rejected with `binding_evidence_disjoint`. Under `same-instance-v1` the same pair is accepted, which is exactly the difference between the two methods: one asserts, the other ties both appraisals to one object.

**Delegation on the same data.** In `test_delegated_collateral_appraisal_and_same_evidence_on_real_data`, a separate collateral appraiser signs `runtime.cpu` and the token issuer carries it. With the appraiser configured, the composite affirms under the counterfactual floor. Without it, the same token claiming `affirming` is `composite_inconsistent`, and the honest composite is `unverifiable`. In `test_carrier_cannot_upgrade_the_delegated_verdict`, the issuer rewrites the appraiser's `contraindicated` to `affirming`, and step 6 rejects it with `component_appraisal_mismatch`. An appraisal outside the grant (wrong component type, wrong profile, not yet valid) comes out `unverifiable`.

**At the gateway.** `tests/test_azure_execution_gateway.py` runs the production cMCP builder with a `runtime.cpu` requirement and a `same-instance-v1` binding. At the SB-3016 floor the `b1` token is refused at admission (`appraisal_not_acceptable`) and nothing reaches transport. With the floor lowered to 23, the same token is admitted and one call goes upstream.

**A second runtime profile.** `prototype/tdx_collateral.py` turns a saved native Intel QVL record (`libsgx-dcap-quote-verify` 1.27.101.1) into a `runtime.cpu` component. It pins the update policy to the Intel-signed TCB evaluation data number, lets only QV result OK affirm (an allowlisted advisory code gives `warning`; result codes per Intel's [`sgx_qve_header.h`](https://github.com/intel/confidential-computing.tee.dcap/blob/main/QuoteGeneration/quote_wrapper/common/inc/sgx_qve_header.h)), and re-derives the TCB level offline against a pinned Intel root. On one historical GCP TDX quote (sha256 `91745a90...`), standard policy (evaluation data number 20) gives UpToDate and early policy (22) gives OutOfDate, `0xa002`. A record that disagrees with the re-derivation is denied with `offline_tcb_disagrees`. Its `instance` names the quote, not a workload, so it cannot be bound to an application component without separate launch evidence.

**The live run.** On 30 September an agent on a disposable Azure SEV-SNP VM held its own holder key and ran admission and one `tools/call` against the production cMCP builder over a tunnel to the gateway's loopback. Secure Boot was off, because the test UKI is unsigned; that is a test configuration, and PCR 7 was pinned to the off value.

| Case                                            | Gateway accepts                             | Result                                      |
| ----------------------------------------------- | ------------------------------------------- | ------------------------------------------- |
| Approved agent                                  | execution profile only                      | admitted, 1 upstream call                   |
| Same component, token signed by an attacker key | execution profile only                      | challenge refused, no call                  |
| Substituted agent, legacy PCR 23 relabelled     | execution profile only                      | admission refused (`unverifiable`), no call |
| Same packet as the previous row                 | execution profile and legacy PCR 23 profile | admitted, 1 upstream call                   |

The last two rows differ only in the accepted profiles. The per-component profile requirement is what kept the relabelled agent out. That run required `application.code` and `tools.catalog` and no `runtime.cpu`. Appraised afterwards for collateral, its Milan host is `contraindicated` in the table above, so a relying party that also required `runtime.cpu` at the SB-3016 floor would have refused the approved agent too.

## 8. Measurement

[`coverage.json`](https://github.com/agentrust-io/trace-spec/blob/main/examples/verifier-token-conformance/coverage.json) maps 22 component requirements, `TR-COMP-*`:

- 20 are portable: each has at least one positive vector, at least two counterexamples, and a causal test in `tests/test_conformance_causal.py` that disables the enforcing check in memory and shows a counterexample admitted.
- 1 is gateway-only, `TR-COMP-MCP-002`: server-to-catalog binding needs a relationship method the token does not define, so the gateway enforces it on the holder-proved action.
- 1 is informative, `TR-COMP-MIN-001`, carry digests rather than raw evidence, checked by a disclosure test.

The component vectors number 110: `COMP-AUTH` 17, `COMP-BIND` 20, `COMP-COMP` 9, `COMP-EVID` 9, `COMP-FRESH` 10, `COMP-ID` 8, `COMP-MCP` 7, `COMP-REQ` 8, `COMP-STAT` 14, `COMP-TYPE` 4, `COMP-WARN` 4. Twelve of the 17 authority vectors are on delegated appraisal, and delegation has six more causal tests, one per gate. The vectors come from `gen_corpus.py`, which builds envelopes, digests and composites from `cbor2`, `rfc8785` and Ed25519 primitives and imports nothing from the reference verifier.

Running both verifiers over all 229 vectors (215 conformance, 14 legacy) on 30 September: every outcome agrees, token result, composite status and proof result alike. `tests/test_stage4_relationships.py` (18 tests), `tests/test_snp_collateral.py` (9), `tests/test_tdx_collateral.py` (60) and `tests/test_azure_execution_gateway.py` (8) pass.

### 8.1 What the second implementation found

The JavaScript verifier was written from the experimental text, the JSON schemas, the vector files and `codes.json`, by an author who did not open the reference or the generator. Its first run agreed on 201 of 207 vectors. The six disagreements were two gaps in the text:

1. **The binding digest preimage.** The reference hashed its normalized model, which filled omitted optional members such as `resolver` with `null`. A wire-level verifier cannot reproduce that. A token that omitted `resolver` verified under one implementation and failed under the other. The reference was wrong, and the rule in §4 now says: the objects exactly as signed, no defaults.
1. **A binding with an absent endpoint.** One implementation reported `binding_digest_mismatch`, the other `composite_inconsistent`. Both rejected, for different reasons. The rule now says `missing`, digest not evaluated.

Neither would have surfaced from one implementation testing itself. The stage 4 additions, delegated appraisal and `same-evidence-v1`, were added to the JavaScript verifier by the same author who wrote the matching reference change. Agreement on those 18 vectors (`COMP-AUTH-006` to `017`, `COMP-BIND-015` to `020`) shows the text is implementable as written. It is weaker evidence than the original clean-room surface, and it is labelled that way in the verifier's README.

### 8.2 One recorded divergence

`COMP-EVID-003` omits `resolver` and is accepted. The requirement as first written made a resolver mandatory; this profile makes it an optional, untrusted hint, because nothing fetches it yet (§9). `coverage.json` records the divergence rather than bending the vector.

### 8.3 Two differences the corpus could not see

Both were found while checking the numbers for this proposal, by reading the two implementations side by side. At the time, no vector caught either.

**Composite freshness.** The reference derives the composite `fresh_until` as the minimum of the token's `exp` and every required component and binding boundary. The JavaScript verifier leaves `exp` out. In all 68 valid vectors `exp` equals the earliest boundary, so the two agree. The §7 token does not: its `exp` is `iat` plus 120 seconds and its components run to `iat` plus 300. The reference accepts it with a composite `fresh_until` of 1790683320. The JavaScript verifier rejects the same bytes with `composite_inconsistent`, and accepts them only when the composite says 1790683500, which the reference in turn rejects.

**Composite precedence.** The reference ranks `contraindicated`, `missing`, `unverifiable`, `not-appraised`. The JavaScript verifier ranks `unverifiable` above `missing`. No vector combines two different non-affirming statuses, so a token with one required component `missing` and another `unverifiable` would be reported differently today.

Both are now settled in the experimental text and pinned by vectors. The composite never outlives the token (`COMP-FRESH-009` and `010`), and `missing` outranks `unverifiable` (`COMP-COMP-008` and `009`). The JavaScript verifier failed all four new vectors before it was changed, which shows the vectors detect the difference; a vector the reference passes by construction would prove nothing. The reasoning for each: a composite is part of the token and should not claim validity past it, and "a required part was never presented" is a harder stop than "a part was presented and could not be checked".

## 9. What this does not do

- **It does not resolve or re-appraise evidence.** Evidence references are digest-bound and never fetched by the relying party. `same-evidence-v1` proves both appraisals cite one object; it does not show that each read the part of the object it claims.
- **It does not prove a physical relationship.** Neither method is a hardware CPU-to-GPU or CPU-to-application binding beyond what the shared evidence object attests.
- **It has no accepted current platform.** Both Azure SNP hosts are below the SB-3016 floor, and the TDX quote with signed collateral is historical and from another instance. The platform adapters are demonstrated on real bytes; an admitted agent on a current, accepted platform is not.
- **It does not define delegation chains or appraiser revocation.** A configured appraiser is trusted for its grant until `valid_until`.
- **It does not appraise MCP servers.** `mcp-server` and `tool-catalog` are distinct categories and `COMP-MCP-*` keeps their results apart, but no remote server appraisal profile or server-to-catalog relationship method exists.
- **It changes no v0.2 field.** Components live in the companion proposal's token, under its own profile URI.

## 10. Alternatives considered

- **More top-level runtime fields.** Does not scale to several instances or to non-runtime parts, and puts vendor fields in the core.
- **One opaque evidence bundle.** A relying party cannot apply per-component policy or see what was omitted without a normalized index.
- **One overall appraisal.** Hides which check ran, which failed and which could not run. §1 is that case.
- **Observed state in the Agent Manifest.** The manifest says what was intended and required. Observations are evidence, appraised later, and carried here.

## 11. Open questions for review

1. **Component type registry and extension routing.** The ten categories are closed in this experiment, and an unknown one is rejected even on an optional component. Should a registry allow profile-defined subtypes, and should an unknown optional category be ignored instead of rejected?
1. **Relationship method registry.** Two methods, one relationship value. What does a third method need to register: a digest preimage, a check a second implementation can run, and vectors?
1. **Should `resolver` be required?** The requirement as first written said yes. This profile says no, because a required hint nobody fetches adds a field without adding a check. If evidence resolution is specified, the answer may change.
1. **Evidence resolution.** Who fetches, from where, with what retention, and what status a relying party reports when the fetch fails. The original design said `unverifiable`, not `contraindicated`, unless other evidence contradicts the claim. Nothing implements it yet.
1. **Delegation chains and appraiser revocation.** Can an appraiser delegate further, and how does a relying party learn that an appraiser key was withdrawn before `valid_until`?
1. **MCP server components.** What evidence an `mcp-server` component rests on (artifact provenance, endpoint identity, transport key binding), and a relationship method that binds a catalog to the server that served it. For the catalog half, [`tool-catalog-observed-digest.md`](https://trace.agentrust-io.com/docs/rfcs/tool-catalog-observed-digest/index.md) states one derivation of a `tool-catalog` component's `observed_digest` from the served `tools/list`, with pinned bytes and `COMP-MCP-004` to `006`; it answers neither the server half nor the relationship method.
1. **Composite precedence and freshness (§8.3).** The experiment settles both: the token's `exp` bounds the composite, and `missing` outranks `unverifiable`. Both readings were defensible, and a reviewer may still invert either one. If so, the four vectors that pin them change with the text.
1. **Binding-only endpoints.** A binding endpoint with no entry in `requirements.components` is required but undeclared, so such a configuration can never affirm. Should requirement loading reject it?

The checks behind all of this can be run from a checkout: `node tools/independent-verifier/verify.mjs examples/verifier-token-conformance/vectors/*.json` prints one outcome per vector, and `python -m pytest tests/test_stage4_relationships.py` runs the worked example in §7 on the saved packets.
