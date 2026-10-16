#!/usr/bin/python3
"""Fuzz the anchor-receipt path behind TR-ANC-002.

The receipt is the second untrusted file ``trace-tests verify`` reads
(``--receipt``). Two properties:

* ``tr_anc.check`` returns findings for any receipt JSON; ``parse_receipt`` and
  ``verify_inclusion`` raise nothing but ``InclusionError``.
* TR-ANC-002 never passes unless the receipt commits to the genuine Merkle
  root and the claim is the one that root includes. Forging either takes a
  SHA-256 collision, so a PASS on anything else is a defect in the replay.

Half the inputs are raw receipt bytes; the other half start from a genuine
five-leaf receipt and mutate one field, which reaches the replay loop far more
often than random JSON would.
"""
import contextlib
import hashlib
import json
import sys

import atheris

with atheris.instrument_imports():
    from trace_tests.inclusion import (
        InclusionError,
        canonical_claim_bytes,
        parse_receipt,
        verify_inclusion,
    )
    from trace_tests.loader import LoadError, loads_strict
    from trace_tests.modules import tr_anc

_CLAIMS = [
    {"transparency": "https://log.example.com/e/1", "iat": 1_760_000_000 + i, "s": "é"}
    for i in range(5)
]
_TARGET = 3


def _leaf(claim: dict) -> bytes:
    return hashlib.sha256(b"\x00" + canonical_claim_bytes(claim)).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _genuine() -> tuple[dict, bytes]:
    level = [_leaf(c) for c in _CLAIMS]
    path, idx = [], _TARGET
    while len(level) > 1:
        sib = idx ^ 1
        if sib < len(level):
            path.append("sha256:" + level[sib].hex())
        nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])  # promoted unpaired, per registry-anchor-v1
        level, idx = nxt, idx // 2
    receipt = {
        "leaf_index": _TARGET,
        "leaf_count": len(_CLAIMS),
        "audit_path": path,
        "merkle_root": "sha256:" + level[0].hex(),
    }
    return receipt, level[0]


_RECEIPT, _ROOT = _genuine()
if not verify_inclusion(_CLAIMS[_TARGET], *parse_receipt(_RECEIPT)):
    raise SystemExit("fuzz_receipt: the genuine receipt does not verify; the harness is wrong")


def _mutated(fdp: atheris.FuzzedDataProvider) -> object:
    receipt = json.loads(json.dumps(_RECEIPT))
    field = fdp.PickValueInList(sorted(receipt))
    kind = fdp.ConsumeIntInRange(0, 3)
    if kind == 0:
        receipt[field] = fdp.ConsumeIntInRange(-2, 2**64)
    elif kind == 1:
        receipt[field] = fdp.ConsumeUnicode(80)
    elif kind == 2:
        path = receipt["audit_path"]
        op = fdp.ConsumeIntInRange(0, 2)
        if op == 0 and path:
            path.pop(fdp.ConsumeIntInRange(0, len(path) - 1))
        elif op == 1:
            node = "sha256:" + fdp.ConsumeBytes(32).hex()
            path.insert(fdp.ConsumeIntInRange(0, len(path)), node)
        else:
            path.reverse()
    else:
        del receipt[field]
    return receipt


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    claim = _CLAIMS[fdp.ConsumeIntInRange(0, len(_CLAIMS) - 1)]
    if fdp.ConsumeBool():
        receipt = _mutated(fdp)
    else:
        try:
            receipt = loads_strict(fdp.ConsumeBytes(fdp.remaining_bytes()))
        except LoadError:
            return

    with contextlib.suppress(InclusionError):
        verify_inclusion(claim, *parse_receipt(receipt))

    if not isinstance(receipt, dict):
        return
    findings = tr_anc.check(claim, receipt=receipt)
    if any(f.code == "TR-ANC-002" and f.passed() for f in findings):
        assert claim is _CLAIMS[_TARGET], f"inclusion proven for the wrong claim: {receipt!r}"
        root = parse_receipt(receipt)[3]
        assert root == _ROOT, f"inclusion proven under another root: {receipt!r}"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
