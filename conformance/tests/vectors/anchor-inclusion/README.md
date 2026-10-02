# Anchor inclusion vectors

Addresses trace-spec#448 row 22: portable TR-ANC-002 examples beyond single-leaf
ASCII receipts. The normative source is
[Registry Anchor Format v1 §§0–3 and 5.1](https://github.com/agentrust-io/trace-spec/blob/4d60e4a775c7e71804d827bed5e7b861e88d45bc/spec/registry-anchor-v1.md).

Each numbered JSON file supplies `claim`, `receipt`, and `expected.tr_anc_002`.
The receipt combines the proof's index/path with the entry's count/root, as
accepted by `trace-tests --receipt`. Expected results concern **only inclusion**,
not the whole record's conformance level. Claims are deliberately small objects;
`signature` is an opaque fixture string, not a cryptographically valid signature.
Inclusion does not authenticate signatures or assert anything about their truth.

Nine positive vectors cover single leaves, both sibling directions, odd trees
of 3/5/9 leaves, repeated right-edge promotion, ASCII escaping of BMP and
supplementary characters, recursive key ordering, and booleans/nulls. Eighteen
negative vectors each name an accepted `positive_twin`: changed body/signature,
wrong root/index, reversed/short/long paths, invalid indices/counts, malformed
hash, absent receipt, and a root computed over a UTF-8 rather than ASCII-escaped
leaf, omitted leaf domain prefix, duplicated odd leaves, and UTF-16 key order.
The Unicode claim has U+E000 and U+1F600 keys; code-point order differs from
UTF-16 order. This is an anchor test, not a proposal to change signing JCS.

Positive `construction` fields expose exact ASCII preimages, leaf hashes, and
ordered batch leaf hashes so another language can reproduce every committed
root and proof. Negative vectors omit construction because their input has been
mutated; the accepted twin provides its original construction.

Run `python tests/vectors/anchor-inclusion/generate.py` to regenerate. The
standard-library generator imports no TRACE verifier code. Its tree/proof
construction uses recursive largest-power-of-two splits, independent of the
verifier's iterative fn/sn algorithm. `tests/test_anchor_vectors.py` checks the
fixed artifacts against the inclusion module and verifies reproducibility and
positive twins. Run `pytest tests/test_anchor_vectors.py` to exercise the set.

An optional second-language check runs with Node.js 18+:

```sh
node tests/vectors/anchor-inclusion/cross_check.mjs
```

It targets this fixture set rather than being a general conformance verifier.
It reads the fixed JSON files directly, implements ASCII escaping and Unicode
code-point ordering in JavaScript, and reconstructs proofs via recursive tree
splits. It checks all 27 outcomes plus the nine positive preimages, leaf hashes,
batch roots, counts and leaf positions. It imports neither the Python generator
nor the verifier. Node is optional and is not added to the Python CI or package
dependencies. Agreement between these implementations is a local cross-check,
not acceptance by an external verifier maintainer or a whole-record verdict.

Limits: no online receipt retrieval, registry append-only check, signature
validation, MMR receipts, or whole-record Level 2 verdict is measured here. This
set does not resolve trace-spec#448 row 21's self-referential transparency issue.
