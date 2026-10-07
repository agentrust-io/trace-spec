# Known Limitations

What this suite does **not** establish. A conformance report is only useful if the reader knows
what it was never checking, so this is the companion to the report rather than a footnote to it.

## What a pass means

**A pass describes the record, not the agent.**
Conformance means the record is well formed, internally consistent, and carries what its level
requires. It says nothing about whether the agent behaved well, whether the policy it ran under
was a sensible policy, or whether the run should have been allowed. A record of a bad run passes
exactly as cleanly as a record of a good one.

**The suite is one implementation, not the definition.**
[trace-spec](https://github.com/agentrust-io/trace-spec) is normative. Where this suite and the
specification disagree, the specification is what other implementations were written against and
the disagreement is a bug worth reporting here.

## Where the checks stop

**`TR-RTE` checks the shape of the attestation fields, not the attestation.**
It validates that `runtime.platform` is a recognised value, that `runtime.measurement` is a well
formed digest, and that the RIM URI parses. It does not obtain a quote, and it does not verify one
against AMD, Intel or a TPM manufacturer root. A record can satisfy `TR-RTE` at Level 1 carrying a
syntactically perfect measurement that no hardware ever produced. Verifying the quote against the
silicon vendor is the relying party's job, and `cmcp_verify` is where that happens.

**`TR-ANC-002` proves inclusion relative to the receipt you hand it.**
It replays the audit path against the Merkle root carried in that receipt. It does not fetch the
`transparency` URI, and it does not establish that the root is one a public log actually
published. A self-consistent receipt over a tree the submitter built themselves will pass. What
the check rules out is a record that has been modified since anchoring, or that was never in the
tree the receipt commits to. Establishing that the tree is real is a separate step and is not in
scope here.

`TR-ANC-001` is explicit that it checks the pointer rather than the anchor. Supplying no receipt
fails `TR-ANC-002`, so Level 2 cannot be reached on a well formed URI alone.

## Statuses that are easy to misread

**`UNVERIFIED` is about reachability, not correctness.**
It means the check could not be run against the evidence the record cites. The evidence may be
perfectly good and simply out of reach. It is deliberately held apart from a skip so that it can
never be read as a benign omission.

Whether an unverified finding fails a run is decided per code, in
`src/trace_tests/modules/unverified.py`, not by one blanket rule. `TR-POL-003` is tolerated until
Level 2; anything the table does not name fails from Level 1, so a newly added code fails closed
rather than turning a run quietly permissive.

**A `TR-ENV` profile failure is a version mismatch before it is a defect.**
Suite 0.4.0 and later require v0.2 records. Run against a v0.1 record, the profile sentinel
produces a confident failure on a record that is fine. Check the suite and record versions before
believing that result.

**Results are perishable.**
`TR-ENV` validates `iat`, so a record that passes today can fail later with nothing about the
record having changed. A report is a statement about a moment, and it needs its timestamp to be
read correctly.

## Who is asserting what

**Nothing here is independently assessed.**
A report is produced by whoever ran the suite, on evidence they supplied. There is no third-party
assessor and no certification programme behind it. This is why the generated report tells a reader
who does not trust the sender to go and check the record themselves rather than trusting the
summary.

## Bounded obligation accounting

**`accounting_complete` describes the pilot, not all of TRACE.**
The accounting extension covers only `TR-APR-001`, `TR-POL-003`, and `TR-SCA-002`.
Complete means that every attempted level has exactly one reconciled row for each of those three
obligations. It does not mean every TRACE obligation was accounted for, every obligation was
evaluated, or that the report independently proves which code ran or which fields it accessed.
An obligation absent from both the bounded registry and its rows is outside this completeness
claim and cannot be discovered by registry-to-row reconciliation alone.

The pilot records `TR-SCA-002` at Level 0 as applicable but not attempted: the pinned schema
requires `build_provenance.digest`, while the scheduler first runs `TR-SCA` at Level 1. The row
carries that scheduler reason rather than silently presenting the state without an explanation.

Each source locator includes a digest of the exact value resolved at its pinned trace-spec
revision. JSON sources use RFC 6901 pointers and RFC 8785-canonical value bytes. The operational
TR-POL-003 rule uses the unique exact text of verification item 5 in the pinned specification;
its schema fragments are listed separately as structural support. A reader who holds those
pinned bytes can resolve and compare the values. The suite does not fetch or authenticate
trace-spec at report time, and a matching value does not prove that a locator is sufficient or
that its checker is correct.

Findings and accounting share one validated execution snapshot during supported report
construction. The emitted report remains editable and unsigned. Its registry hash identifies
registry content; it does not authenticate the rows, the report, or its producer.

The optional policy resolver is trusted in-process Python code supplied by the caller. The
accounted path isolates nested public runs and freezes ordinary decision inputs, but it is not a
sandbox against a callback that rewrites interpreter globals, functions, classes, or source files.

`producer_branch` is a checker-owned same-execution diagnostic. Some branches with the same
accounting meaning return indistinguishable findings, so the emitted report alone cannot
independently reconstruct every branch label. Applicability, evaluation state, prerequisite,
contribution, findings, and report tallies are revalidated at emission; the label is not
presented as independent proof of checker control flow.
