# Behavior-trace vectors

Vectors for the draft format in
[`docs/rfcs/behavior-trace.md`](../../docs/rfcs/behavior-trace.md): signed, hash-linked
blocks recording the steps of one agent run. Nothing here binds an implementation.

## Running them

```
python -m pytest tests/test_behavior_trace.py tests/test_behavior_trace_parity.py \
  tests/test_behavior_trace_mutants.py
npm --prefix trust-record-verify test
```

To regenerate: `python examples/behavior-trace/gen_vectors.py`. The generator uses raw
primitives only, never the reference code, so the vectors check that code instead of
copying it. Keys come from fixed seeds, so the bytes are the same on every run.

## What a vector is

Each file holds `blocks`, the `pinned_keys` trusted for each edge, and `expected`: a
`classification` (`verified`, `truncated` or `rejected`) and the sorted `codes`. There are
51: 7 verified, 2 truncated and 42 rejected, with at
least two vectors for every code.

Vectors 47 to 49 reject empty, 65-character and `a=b` extension names.
Vectors 50 and 51 accept `~` and a 64-character name as boundary controls.
