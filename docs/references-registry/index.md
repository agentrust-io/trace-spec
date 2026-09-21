# The `references` relation registry

Informative. The registered values of `references[].rel` (§3.1.2), what each one's referenced object is, what a verifier may conclude from a resolved one, and how a name is added.

## What registration does, and does not do

`rel` is open. The schema constrains it to a non-empty string, the reference model does the same, and §3.1.2 calls its values a registry; an unregistered value validates, signs and verifies. §3.1.1 closes the neighbouring `origin.kind` "because the value of the field is that a verifier can key on it", and §3.1.2 deliberately does not say that of `rel`.

A registered value adds one thing: a shared definition of the referenced object, precise enough that two implementations resolve the same thing and compute the same `digest` over it. What a verifier may conclude from a resolved reference is set by the four rules of §3.1.2, which are normative and the same for every relation, registered or not. Rule 3 is the one this document is bounded by:

> A verifier MUST NOT reject a record because an entry in `references` cannot be resolved, and MUST NOT treat a resolved reference as attested evidence. (§3.1.2, rule 3)

A registration cannot add to those rules; a proposal that needs to is a change to §3.1.2.

What a registered value therefore cannot carry: a requirement on a verifier, an effect on whether the record verifies, or a promotion of the target's content into evidence. A proposal that needs any of those is a change to the normative text of §3.1.2 and follows [CONTRIBUTING.md](https://trace.agentrust-io.com/CONTRIBUTING/#spec-changes-normative-text), sponsor included. The two limits §3.1.2 states for the whole block hold for every entry here as well: a reference cannot carry compliance evidence, and cannot carry a pre-execution commitment.

The registry is enforced without being normative: `tests/test_references_block.py::test_the_registered_rel_values_stay_documented_in_all_three_places` fails if `rel` is closed again, and if a registered value stops being named in the schema description, in `docs/schema.md`, or in this document.

## Registered values

| `rel`                 | Referenced object                                                                               | Defined in                                                                                                                                                                | Example                                                                                                          |
| --------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `authorized-intent`   | An authorization decided before execution, held in another system                               | §3.1.2; one mapping in [`crosswalks/nkemba-institutional-reconstruction.md`](https://trace.agentrust-io.com/docs/crosswalks/nkemba-institutional-reconstruction/index.md) | none committed                                                                                                   |
| `approval-outcome`    | An attributable human approval attached to a step-up or defer decision                          | §3.1.2; the CHAP mapping in [`crosswalks/chap-review-decisions.md`](https://trace.agentrust-io.com/docs/crosswalks/chap-review-decisions/index.md)                        | [`examples/chap-approval-outcome/`](https://trace.agentrust-io.com/docs/examples/chap-approval-outcome/index.md) |
| `behavior-trace`      | A behavioural record of what the agent did, of which this record is the environment evidence    | §3.1.2                                                                                                                                                                    | none committed                                                                                                   |
| `condition-appraisal` | An independent check's finding on whether a stated condition is established by a stated subject | This document, below                                                                                                                                                      | [`examples/condition-appraisal/`](https://trace.agentrust-io.com/docs/examples/condition-appraisal/index.md)     |

The first three were registered by the change that introduced the block (#197) and their referenced objects are defined to the extent the documents cited define them. Tightening one is a change to make here, on the same terms as adding a name.

## `condition-appraisal`

### Meaning

The record points at what an independent check found when it held a stated subject against a stated condition. The check is anything whose finding a party is willing to sign: a test suite run over a deliverable, a schema validation over a document, a contract check over an interface, a reviewer's verdict over a change. The three values registered before it cover what was asked (`authorized-intent`), who approved (`approval-outcome`) and what the agent did (`behavior-trace`); this is the fourth question a relying party asks, what a check found. §3.3.3 already names that layer for embodied workflows, as "Controller, monitor, human-review, or safety-system observations". A software deliverable has the same layer, and this relation is that layer with the embodiment removed.

Two neighbours it is not. The `appraisal` in the name is the checker's appraisal of the subject; it is not the verifier's appraisal of the record, which the record carries in its own `appraisal` member and which no reference reaches. And a human reviewer's verdict is a `condition-appraisal` only when it states whether the subject meets named criteria and decides nothing about execution; the decision that lets a step-up or defer proceed is `approval-outcome`, whatever the reviewer also found.

### The referenced object

A signed, content-addressed statement. Its wire format belongs to the issuer, not to this specification; what registration fixes is the set of facts it carries and how the reference's `digest` is taken over it, so that two implementations resolve the same object and check the same bytes.

| Fact          | Carried as                                                                                                              | Why it is required                                                                                                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The condition | An identifier and a digest over the canonical bytes of the criteria the subject was held against                        | A finding with no stated condition is an opinion; two appraisals of one subject under different conditions are incomparable, and the digest is what says so                                  |
| The subject   | An identifier and a digest over the canonical bytes of the deliverable, or of a manifest that names its parts by digest | Binds the finding to exactly the thing checked, so a later version of the deliverable cannot inherit it                                                                                      |
| The issuer    | An identifier for the party that performed the check, and a reference to its verification key                           | §3.3.2's `issuer` and `issuer_key_id`, with the binding to a call replaced by the bindings above                                                                                             |
| The outcome   | A value in the issuer's own closed vocabulary, which the object names, with any detail the issuer chooses               | The finding itself. The vocabulary is the issuer's because the semantics of a check are the issuer's; this specification does not define what `pass` means for a test suite it did not write |
| When          | The time the issuer signed                                                                                              | Separates the finding from the record's `iat`                                                                                                                                                |
| The signature | The issuer's signature over the RFC 8785 canonical form of the object with the signature member absent                  | §3.3.2 step 1, applied to this object                                                                                                                                                        |

The reference's `digest` is over the RFC 8785 canonical form of the complete object, signature included, as the resolver retains it. `id` is the object's identifier within the resolver's system and `resolver` is the party obliged to keep it resolvable, as for every entry.

The committed example, [`examples/condition-appraisal/`](https://trace.agentrust-io.com/docs/examples/condition-appraisal/index.md), shows one concrete shape for these facts; a producer whose checker emits another shape that carries them is within this definition.

### What a verifier may conclude

Three findings, each separable from the others, and a relying party reports all three rather than folding them:

1. **Whether the reference resolves.** If not, the appraisal is unconfirmed. That is a different answer from "no appraisal", and under rule 3 of §3.1.2 it is never a reason to reject the record.
1. **Whether the resolved bytes are the cited bytes.** A digest match establishes identity. A mismatch establishes that what the resolver holds is not what the record cited, which is a finding about the store, not about the record.
1. **Whether the object verifies under its named issuer's key**, when the relying party holds that key. The rule §3.3.2 gives receipts applies unchanged: an issuer key the verifier does not hold makes the object unverified, not invalid.

That is the whole of it, and all three are findings about the object. None reaches the record: it verifies the same whether the reference resolves, matches, or verifies, and nothing in the object becomes attested evidence. The outcome inside the object is reported as the issuer stated it and promotes in neither direction. A `pass` is not attested evidence that the condition held: the record attests that it points at the finding, and the finding is the issuer's. A `fail` is not a finding against the record: the record verifies exactly as it would citing a `pass`, and the example set holds a pass and a fail side by side to keep that so.

What this relation is not. It is not re-execution. A check that is a deterministic function over a pinned closure, a test suite over a deliverable and a suite, a schema validation over a document and a schema, could in principle have its outcome established by the verifier re-running it, under the same `reproduced`, `diverged` and `not-attempted` outcomes §3.1.4 gives for coordination logic. That is an appraisal the verifier performs, never something the reference establishes, and it is a separate proposal from this registration. Nor is it compliance evidence: §3.1.2 says of the whole block that a record pointing at a check attests that it points there, and nothing about whether an obligation was met.

## Adding a name

A registration is a non-breaking spec change of the informative kind under [GOVERNANCE.md](https://trace.agentrust-io.com/GOVERNANCE/#review-periods-by-change-class): an open issue, a minimum of five business days for comment, Maintainer review. It adds no requirement: the list in §3.1.2 grows by a name and every rule there stays as it was, so the sponsor rule of [CONTRIBUTING.md](https://trace.agentrust-io.com/CONTRIBUTING/#spec-changes-normative-text) does not apply. A proposal that does add a requirement is a normative change and follows that rule.

1. **Open an issue.** State the relation's name, the referenced object as the table above does for `condition-appraisal`, in facts rather than in a wire format, and what a verifier may conclude from a resolved one. The answer to the last is rule 3 of §3.1.2 and nothing more; if it is more, the proposal is not a registration. An unregistered `rel` is legal, so a relation one producer emits for its own reader needs no name; register when a second implementation has to resolve the same object.
1. **Open the PR.** It touches the list in §3.1.2 of `spec/trace-v0.2.md`; the `rel` description in `schema/trace-claim.json` and its packaged copy under `src/agentrust_trace/schema/`, with `schema/trace-claim-v0.3-draft.json` regenerated by `scripts/gen_v03_draft_schema.py`; the `rel` row in `docs/schema.md`; and this document, with a section like the one above. `tests/test_references_block.py` checks that the last three name every registered value: add the name to its `registered` tuple and its case table.
1. **Commit an example with recomputable digests.** A set under `examples/<rel>/` whose records verify, whose reference digests recompute from the referenced objects committed beside them, and whose cases include an unresolvable reference and an altered target, so that rule 3 of §3.1.2 is shown rather than asserted. A test under `tests/` recomputes every outcome from the committed bytes, and the set is named in `tests/test_adequacy_all_sets.py` so that nothing on disk goes ungraded.
1. **Record it in `CHANGELOG.md`** under Added, naming the issue and stating that the change is informative.
