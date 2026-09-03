# RFC Proposal: runtime evidence, and what a verifier may conclude without it

**Status:** Draft proposal. Binds nothing.
**Scope:** A `runtime.evidence` member, the rules for checking it, and the grades a verifier may report. Additive; every v0.2 record stays valid.
**Target:** `spec/trace-v0.2.md` §3.1 and §5, for v0.3.
**Conformance material:** [`examples/runtime-evidence/`](../../examples/runtime-evidence/): 8 vectors, generator, and reference rules, built on a genuine Intel TDX quote rather than a minted one.
**Draft schema:** [`schema/trace-claim-v0.3-draft.json`](../../schema/trace-claim-v0.3-draft.json), generated from `schema/trace-claim.json` so the diff is one member deep.

Requirement keywords are lowercase throughout, deliberately, on the line `CONTRIBUTING.md` draws: normative text lives in `spec/`, informative text binds no implementation. If these rules are adopted they become uppercase there and this file becomes a pointer to where they went. A proposal that writes itself in the imperative is a specification nobody agreed to.

---

## 1. What exists today

A Trust Record states a hardware platform and a measurement:

```json
"runtime": {
  "platform": "intel-tdx",
  "measurement": "sha384:9bf86e62...",
  "rim_uri": "https://...",
  "nonce": "..."
}
```

`schema/trace-claim.json` closes the object with `additionalProperties: false`, so those five members are the whole of it. There is no field for the quote, the certificate chain, or the report signature. `appraisal` carries a status enum and a `verifier` URI, which is a pointer to a party who says they checked.

`agentrust_trace.verify_record()` checks the profile URI, the schema, the record signature, freshness, and revocation. It performs no attestation verification of any kind, and the package contains none: the string `quote` appears in `src/agentrust_trace/` only inside comments. That is not an implementation gap. There is nothing in the record for such code to consume.

So the chain available to a relying party holding a v0.2 record is:

| Claim | What the record offers | What a verifier can establish |
|---|---|---|
| a TD ran | `platform: "intel-tdx"` | nothing; a string the issuer wrote |
| it measured X | `measurement: "sha384:..."` | nothing; a string the issuer wrote |
| someone checked | `appraisal.verifier` | nothing; a URI naming a third party |
| the issuer said all this | `signature` over `cnf.jwk` | this, and only this |

The record is signed, and the signature is sound. It attests authorship. Every hardware claim inside it is the issuer's word, and a verifier that reports "TEE-attested" on that basis is reporting the issuer's assertion in the verifier's voice.

### 1.1 The requirement that was already made, and never made checkable

This is not a new idea being introduced. `docs/trust-levels.md` line 50 already states the property:

> Level 1 requires that the signing key be generated inside a verified TEE (AMD SEV-SNP, Intel TDX, NVIDIA H100, or TPM2).

Nothing in the schema represents that binding and nothing in the SDK checks it. `spec/trace-v0.2.md` §5 maps `runtime` to "RATS Evidence + vendor RIM" in the claim table, and the record carries no RATS evidence. The requirement, the mapping, and the schema disagree, and the schema is what runs.

### 1.2 The asymmetry this closes

The specification already reasons carefully about assurance laundering, and reasons about it in one direction only.

§3.1.1 makes `origin` mandatory for assembled records and forces `platform: "software-only"` with it, because "an importer holding someone else's log has no quote to present". §3.1.2 rule 3 forbids a verifier from treating a resolved `references` entry as attested evidence, because "a reference that counted as evidence would be the assurance laundering §3.1.1 exists to prevent". §3.1.1 states the principle outright: the block "cannot raise a record: nothing about naming your producer makes unattested evidence attested."

Both rules govern pointers to things outside the record. Neither governs `runtime`, where the same move is not merely possible but is the only thing available: `rim_uri` is a pointer, `measurement` is a transcription, `appraisal.verifier` names someone else's verdict. A record cannot launder assurance through `references`, and can through `runtime`, by writing a platform string.

The specification's own doctrine, applied to the block it was never applied to, is this proposal.

## 2. The verification model

A verifier is given a record and context. Context is what no record can supply, and it is enumerated rather than assumed:

| Context | Why it cannot come from the record |
|---|---|
| `trusted_root_keys` | a record naming its own key as trusted is not evidence |
| `platform_verifiers` | the code that checks a quote, which TRACE does not ship and should not |
| `accepted_measurements` | which MRTD or PCR set is the workload you meant is a deployment decision |
| `now` | freshness bounds, per §3.2.2 |

The last row of that table is the important one for what follows. Verifying a quote establishes that genuine silicon reported a measurement. Whether that measurement is the workload the relying party intended is a separate question that no quote answers, and this proposal does not answer it either.

## 3. The block

```json
"runtime": {
  "platform": "intel-tdx",
  "measurement": "sha384:9bf86e62...",
  "evidence": {
    "format": "tdx-quote-v4",
    "quote": "BAACAIEAAAAAAAAAk5pyM...",
    "collateral": "embedded",
    "binds": "cnf-key"
  }
}
```

| Member | Required | Meaning |
|---|---|---|
| `format` | yes | selects the verifier and the rule for extracting a measurement |
| `quote` | one of | the evidence as the platform emitted it, base64url, no padding |
| `quote_digest` | one of | digest of the evidence, for the by-reference form |
| `quote_uri` | no | where the by-reference form may be fetched |
| `collateral` | no | `embedded` when everything needed travels in the quote; `required` when the verifier must supply it out of band |
| `collateral_uri` | no | where that collateral lives when it is `required` |
| `binds` | no | what the guest committed to in the guest-controlled field |

`binds` is a producer's statement of intent and a verifier recomputes rather than reads it. It exists so a record can be triaged before the cryptography runs, and so a producer that does not know can say `unspecified` instead of guessing. Nothing in §4 consults it.

`collateral: "embedded"` is not decoration. A TDX v4 quote carries its full PCK chain, and the Intel SGX Root CA is a pinned constant, so verification needs no fetch. An SEV-SNP report does not carry its VCEK, so an SNP record is `required` and cannot be verified offline from the record alone. That difference is a property of the platforms and the record should say which one it is rather than leave a verifier to discover it by failing.

## 4. The rules

1. **The envelope is checked first.** Schema, then the record signature over the canonical form with `signature` absent. The evidence is a member of the record, so the record signature is what binds a quote to this record rather than to any record. Verifying the quote first would check hardware that this record never committed to.
2. **The evidence is verified by a platform verifier for its `format`.** A verifier that has no implementation for a format treats the record as if the block were absent, per rule 5, and does not reject it: not being able to read evidence is not the same as evidence being bad.
3. **`platform` and the evidence must agree.** A record claiming `amd-sev-snp` while carrying a TDX quote is refused.
4. **`measurement` must equal the measurement extracted from the evidence.** For `tdx-quote-v4` that is the MRTD. A valid quote establishes that a TD ran; it says nothing about which measurement this record is entitled to claim until the two are compared. Disagreement is a rejection, not a downgrade, because the record made a specific false statement.
5. **Evidence that is absent, by-reference, or in an unsupported format grades `unattested`.** Not a rejection. A record with no evidence is a record with no evidence, and v0.2 records are all of them. The by-reference form is included here on purpose: TRACE's stated property is offline verifiability, and a verifier holding a URI has verified nothing. A pointer earns what §3.1.2 rule 3 already says a pointer earns.
6. **The guest-controlled field is compared against the record's `cnf` key.** Where the platform's guest-controlled field commits to the record-signing key, the record grades `attested`. Where it does not, `platform-attested`. §5.2 is why this is the line.
7. **A grade on the record does not propagate to the claims inside it.** §6.

## 5. Decisions that had to be settled

These were not read out of the existing text. Each was hit while writing a vector, and in each case the current text supports both branches.

### 5.1 Inline or by reference

Both are expressible; only one earns a grade. A record whose evidence must be fetched cannot be verified offline, and offline verifiability by any party is the property §1 of the specification leads with. Permitting the by-reference form and grading it `unattested` keeps a producer honest who genuinely cannot inline 8 KB, without letting a URI stand in for evidence.

The cost is real and measured rather than estimated. A TDX v4 quote is 8,000 bytes, 10,667 characters in base64url, and it takes the accept vector from 1,184 bytes to 11,923: an order of magnitude, on the corpus in §7. That is the price of the record being evidence rather than a claim about evidence, and it is paid once per record.

### 5.2 Which binding separates the grades

Three candidates. The record digest is circular, since the evidence is inside the record. A nonce works only for online verification, where the verifier issued it, and TRACE's model is offline. That leaves the record-signing key.

Binding the guest-controlled field to the `cnf` key gives the chain the specification already describes in §3.2 ("workload attestation key (TEE-bound) → record-signing key") an actual check: silicon signs the quote, the quote commits to the key, the key signs the record, so every claim in the record is transitively rooted in silicon. Nothing weaker gets there.

**This diverges from what the reference producer does today.** `agent-manifest`'s TDX provider binds `sha256(manifest_pre_image)` into `REPORT_DATA`, not the record-signing key. Two implementations were asked the same question and gave different answers, which is the measurement worth having: the divergence names a sentence that is missing rather than a bug in either. Reconciling it is work this proposal creates and does not do.

### 5.3 Why a middle grade exists at all

The obvious ladder has two rungs. A third was forced by the artifacts: a record can carry a real, fully verifying quote and still not connect it to whoever signed the record, and both collapses lose something. Folding it up into `attested` is exactly the overstatement the proposal exists to prevent. Folding it down into `unattested` discards a fact the verifier did establish, which is that genuine silicon reported this measurement.

## 6. Grades, and what each one licenses

| Grade | Established | Not established |
|---|---|---|
| `unattested` | the issuer authored the record | anything about an execution environment |
| `platform-attested` | genuine silicon reported this measurement, and this record's issuer holds a quote proving it | that this record's signer ran inside that TEE, or that this record describes that execution |
| `attested` | the above, and the record-signing key is committed to inside the TEE | that any particular claim in the record is true, per §6.1 |

The middle row is narrower than it looks and §7.2 shows why.

### 6.1 A grade on the record is not a grade on its claims

`model.weights_digest` is attested where a verifier can **recompute** the binding from the evidence, and self-reported otherwise. A TEE-signed envelope does not make its contents attested; it makes them the issuer's word, carried in a hardware-signed envelope, which is the shape most likely to be read as stronger than it is. The same reasoning applies to `policy.bundle_hash` and `tool_transcript.hash`: hardware attests what was measured, and a value the runtime wrote into a record after the fact was not measured.

This is §3.1.1's principle turned inward. The specification already refuses to let a pointer raise a record. It should equally refuse to let a record raise its own contents.

**Recompute is load-bearing, and the first draft of this proposal got it wrong.** The rule originally read `evidence.binds` to decide the grade, which would have let a producer raise its own model claim by writing `binds: "weights-digest"` into a record. That is precisely the laundering this section forbids, reintroduced inside the section that forbids it. An advisory member that changes a grade is not advisory. `advisory-binds-cannot-raise-a-claim` in §7 is the vector that keeps it honest: it declares the binding, does not have it, and grades self-reported.

The near miss is worth recording rather than quietly fixing. The failure mode was not carelessness about the principle; it was stating the principle in §3 and implementing the opposite forty lines away, which is the shape this whole proposal exists to catch in `runtime`.

## 7. Measurement

[`examples/runtime-evidence/generate.py`](../../examples/runtime-evidence/) implements §4 against two genuine Intel TDX v4 quotes captured from a GCP C3 confidential VM on 2026-07-21, committed at `agentrust-io/agent-manifest`. No quote in the corpus is minted. A synthetic quote is built to the parser's own idea of the layout, so a corpus of them measures a parser against itself.

The verifier is `agent-manifest`'s, imported unmodified. TRACE does not implement attestation and this proposal does not start; it carries evidence to verifiers that already exist.

```
accept-real-quote-platform-attested       platform-attested
downgrade-evidence-absent                 unattested
downgrade-evidence-by-reference           unattested
reject-forged-quote                       reject   evidence signature or PCK chain did not verify
reject-measurement-mismatch               reject   runtime.measurement is not the MRTD in the evidence
limit-substituted-quote-from-the-same-td  platform-attested
reject-evidence-swapped-after-signing     reject   record envelope failed: InvalidSignature
reject-platform-not-the-evidence          reject   platform 'amd-sev-snp' is not what this evidence roots
advisory-binds-cannot-raise-a-claim       platform-attested   model claim: self-reported

9/9 vectors behaved as the profile says they must (1 of them documenting a limit).
```

Each vector asserts both the record grade and the model-claim grade, because §6.1 is a claim about the relationship between the two and a corpus that checked only the first would not test it.

### 7.1 What the corpus found

`limit-substituted-quote-from-the-same-td` was written to be a rejection and is not one.

The two captures come from one TD, so they share an MRTD and differ only in their `REPORT_DATA` binding. Substituting one for the other leaves rule 4 satisfied, because the measurements agree. The swap passes, and it passes on real hardware rather than in a constructed example.

Rule 4 therefore does not do what it appears to do. It binds a record to a *measurement*, never to a *quote*. Any two quotes from one TD are interchangeable under it, which means the middle grade cannot support "this execution" and can support only "genuine silicon reporting this measurement". Separating two quotes from one TD requires a binding in the guest-controlled field, which is what the top grade requires, and this is the argument for the top grade existing.

Had the corpus been synthetic, both quotes would have been minted with different measurements and the vector would have passed. The limit is visible only because the artifacts are real and happen to share a TD.

### 7.2 The top grade is currently unreachable

No capture this project holds binds a record-signing key. Both TDX quotes bind a manifest digest per §5.2, so `attested` is not reachable from any artifact in the repository, and the corpus reports `platform-attested` on its accept vector rather than the grade the profile is ultimately about.

Worse, the pre-image behind those bindings is not recoverable either: the manifest from that capture session was never committed, so `REPORT_DATA` in both quotes is a 32-byte value that verifiably came from the TEE and cannot be opened. A verifier can prove something was bound and not what.

Both are gaps in the capture procedure rather than in the design, and both are cheap to close on the next TDX run: bind the record-signing key, and publish the pre-image alongside the quote. Until then this proposal's top grade is specified and undemonstrated, and saying so is cheaper than discovering it during adoption.

## 8. What this does not do

- **It does not make TRACE an attestation verifier.** `format` selects someone else's verifier. The list of formats is a registry, not an implementation surface.
- **It does not appraise TCB.** `agent-manifest`'s TDX verifier checks signatures and the PCK chain to a pinned root; it does not evaluate TCB or QE identity. "Genuine silicon" is in scope, "current firmware" is not, and a grade must not be read as the second.
- **It does not decide whether a measurement is the right one.** §2.
- **It does not change any existing field, and adds no requirement to any v0.2 record.** Records without `evidence` grade `unattested`, which is a name for what they always were.
- **It does not resolve §5.2.** The reference producer binds something else today, and a profile is not adopted by writing down which side should move.
