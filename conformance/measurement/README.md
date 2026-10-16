# Regression-guard measurement

Does this repository's own suite notice when one of its conformance checks stops working?

**None of the checks measured here is wrong.** They behave correctly today. This measures
something narrower: whether a *regression* inside a conformance module would be caught.

It does now, for all 33. When this was first run, ten failure paths were unguarded,
including all three of `TR-TXN-001`, which is the only place the Level 2 tool-transcript
requirement is enforced. Those ten got tests, and the measurement is how they were found.

Re-run it after touching any conformance module. Eight checks sit at margin 1, so a single
deleted test puts one of them back to zero.

[`REPORT.md`](REPORT.md) has the findings, the method, and what the method does not
establish.

## Running it

No dependencies beyond what the suite already needs. Both scripts default to the checkout
they live in, and both exit non-zero on a finding.

```bash
pip install -e ".[dev]"
python measurement/scripts/mutate_modules.py     # regression guards
python measurement/scripts/enum_drift.py         # hand-written enums vs the schema
```

`mutate_modules.py` rewrites one site at a time, runs the suite, restores, and verifies
the restore before moving on. It refuses to start if the baseline is not green, refuses a
rewrite that did not change the file, and refuses an empty site list — each of those
produced a wrong answer while it was being written.

Takes about a minute: 33 sites, one full suite run each.

## Why not read the tests instead

Because reading gives the wrong answer here. Grepping the test files for `TR-xxx-nnn`
codes and diffing against what the modules emit reports 12 unguarded checks; mutation
reports 3. Tests exercise a module through `check(...)` and assert on the findings without
naming codes, so naming is a convention and changing outcome is the property.

The reverse also happens. Five files mention `tool_transcript`, which reads as coverage —
one re-implements the digest check inline instead of calling the module, two assert on the
JSON schema, and one asserts only that the module ran.

## Status

Fork-only, not proposed upstream. Nothing in the suite was modified: every mutation is
reverted and the checkout re-verified green.
