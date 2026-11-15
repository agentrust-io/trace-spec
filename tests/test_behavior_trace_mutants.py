"""Near-miss mutants of every behavior-trace rule, in both implementations.

Each mutant weakens one rule the way a careful reviewer might have written it
instead. The vectors must catch every one, and the named vectors must be among
those that catch it. The runner guards against reporting what did not happen:
the unmutated code must pass first, every rewrite must hit exactly one site and
change the source, the code must load from this checkout, and a mutant that
breaks the verifier outright must be reported killed.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import types
from typing import Any

import pytest

from tests.test_trust_record_verify_citations_and_platform import PACKAGE, _ensure_built

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOTYPE = ROOT / "prototype" / "behavior_trace.py"
VECTORS = sorted((ROOT / "examples" / "behavior-trace").glob("*.json"))

# name: (python old, python new, typescript old, typescript new, vectors that must catch it)
MUTANTS: dict[str, tuple[str | None, str | None, str | None, str | None, list[str]]] = {
    "run_start not checked for wrapper": (
        'blocks[starts[0]]["edge"] != "wrapper" or ', "",
        'start.edge !== "wrapper" || ', "",
        ["27-run-start-on-other-edge"]),
    "run_start not checked for seq 0": (
        ' or blocks[starts[0]]["seq"] != 0', "",
        " || start.seq !== 0", "",
        ["12-run-start-seq-not-zero"]),
    "run_id not compared": (
        'if any(b.get("run_id", run_id) != run_id for b in blocks):', "if False:",
        'if (run.some((b) => (own(b, "run_id") ?? runId) !== runId)) {', "if (false) {",
        ["13-run-id-other-run", "14-run-id-on-run-end"]),
    "fork not detected": (
        "if any(len(idx) > 1 for idx in by_seq.values()):", "if False:",
        "if ([...bySeq.values()].some((idx) => idx.length > 1)) {", "if (false) {",
        ["15-fork-cmcp", "16-fork-heartbeat"]),
    "gap not detected": (
        "if sorted(by_seq) != list(range(len(by_seq))):", "if False:",
        "if (seqs.some((seq, i) => seq !== i)) {", "if (false) {",
        ["17-gap-first-block", "18-gap-middle-block"]),
    "first block prev not checked": (
        'want = None if edge == "wrapper" else run_id', "continue",
        'want = edge === "wrapper" ? null : runId;', "continue;",
        ["20-link-first-block-wrong"]),
    "later prev not checked": (
        "want = digests[by_seq[seq - 1][0]]", "continue",
        "want = digests[bySeq.get(seq - 1)[0]];", "continue;",
        ["19-link-skips-a-block"]),
    "parents not resolved": (
        'if any(p not in by_digest for p in b["parents"]):', "if False:",
        "if (b.parents.some((p) => !byDigest.has(p))) {", "if (false) {",
        ["21-parent-unknown", "22-parent-from-other-run"]),
    "heartbeat peer edge not matched": (
        'if d not in by_digest or by_digest[d]["edge"] != edge:', "if d not in by_digest:",
        "if (byDigest.get(peers[edge])?.edge !== edge) {", "if (!byDigest.has(peers[edge])) {",
        ["23-heartbeat-wrong-edge"]),
    "run_end checked by seq only": (
        "if any(terminal != [i] for i in ends) or any(",
        'if any(blocks[i]["edge"] != "wrapper" or blocks[i]["seq"] != max(wrapper)'
        " for i in ends) or any(",
        "ends.some((i) => terminal.length !== 1 || terminal[0] !== i) ||",
        'ends.some((i) => run[i].edge !== "wrapper" || run[i].seq !== last) ||',
        ["36-fork-at-run-end"]),
    "activity after run_end allowed": (
        'end_digests.intersection(b["parents"]) for b in blocks', "False for b in blocks",
        "run.some((b) => b.parents.some((p) => endDigests.has(p)))) {", "false) {",
        ["37-tool-call-after-end", "38-model-call-after-end"]),
    "duplicates not reported": (
        '            codes.add("duplicate_block")\n', "            pass\n",
        'codes.add("duplicate_block");', ";",
        ["28-duplicate-tool-block", "29-duplicate-run-start"]),
    "provenance not resolved": (
        'if not all(_resolves(block, path) for path in block.get("provenance", {})):', "if False:",
        "if (!Object.keys(provenance).every((path) => resolves(b, path))) {", "if (false) {",
        ["31-provenance-missing-member", "35-provenance-index-leading-zero"]),
    "provenance may name a container": (
        "return not isinstance(node, (dict, list))", "return True",
        "return !isPlainObject(node) && !Array.isArray(node);", "return true;",
        ["32-provenance-names-a-container"]),
    "pointer ~0 decoded before ~1": (
        't.replace("~1", "/").replace("~0", "~")', 't.replace("~0", "~").replace("~1", "/")',
        '.map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));',
        '.map((t) => t.replace(/~0/g, "~").replace(/~1/g, "/"));',
        ["33-valid-escaped-pointers"]),
    "array index may have a leading zero": (
        '_INDEX = re.compile(r"(0|[1-9][0-9]*)\\Z")', '_INDEX = re.compile(r"[0-9]+\\Z")',
        "const INDEX = /^(0|[1-9][0-9]*)$/;", "const INDEX = /^[0-9]+$/;",
        ["35-provenance-index-leading-zero"]),
    "key pinned for any edge": (
        'jwk = pinned.get(block["edge"], {}).get(block["sig"]["kid"])',
        'jwk = next((e[block["sig"]["kid"]] for e in pinned.values()'
        ' if block["sig"]["kid"] in e), None)',
        "const key = pinned.get(b.edge)?.get(b.sig.kid);",
        "const key = [...pinned.values()].find((m) => m.has(b.sig.kid))"
        "?.get(b.sig.kid);",
        ["08-key-pinned-for-other-edge"]),
    "signature not checked": (
        "_pubkey_from_jwk(jwk).verify(raw, signed)", "pass",
        "if (raw === null || !(await verifyEd25519(key, raw, signed))) {", "if (raw === null) {",
        ["09-signature-body-changed", "10-signature-from-other-block"]),
    "schema not checked": (
        "if not _validator().is_valid(block):", "if False:",
        "if (!validateBlock(block)) {", "if (false) {",
        ["40-raw-content-in-body", "41-args-not-a-commitment"]),
    "patterns use Python $ semantics": (
        'pattern.replace("$", r"\\Z")', "pattern",
        None, None,  # JavaScript has ECMA-262 semantics natively
        ["06-schema-kid-trailing-newline"]),
}

# Breaks the verifier outright. If this is not killed, the runner measures nothing.
SANITY = (
    'return {"classification": "rejected", "codes": sorted(codes)}',
    'return {"classification": "verified", "codes": []}',
    'return { classification: "rejected", codes: [...codes].sort() };',
    'return { classification: "verified", codes: [] };',
)


def _vectors() -> list[tuple[str, dict[str, Any]]]:
    return [(p.stem, json.loads(p.read_text(encoding="utf-8"))) for p in VECTORS]


def _apply(source: str, old: str, new: str) -> str:
    assert source.count(old) == 1, f"mutant site must occur exactly once: {old!r}"
    mutated = source.replace(old, new)
    assert mutated != source
    return mutated


def _python_failing(source: str) -> set[str]:
    module = types.ModuleType("behavior_trace_mutant")
    module.__file__ = str(PROTOTYPE)  # schema is found next to this checkout
    exec(compile(source, str(PROTOTYPE), "exec"), module.__dict__)  # noqa: S102
    failing = set()
    for name, v in _vectors():
        try:
            if module.verify_run(v["blocks"], v["pinned_keys"]) != v["expected"]:
                failing.add(name)
        except Exception:
            failing.add(name)
    return failing


PY_SOURCE = PROTOTYPE.read_text(encoding="utf-8")


def test_python_baseline_passes_every_vector() -> None:
    assert _python_failing(PY_SOURCE) == set()


def test_python_sanity_mutant_is_killed() -> None:
    assert _python_failing(_apply(PY_SOURCE, SANITY[0], SANITY[1]))


@pytest.mark.parametrize("name", list(MUTANTS))
def test_python_mutant_is_killed(name: str) -> None:
    old, new, _, _, killers = MUTANTS[name]
    assert old is not None and new is not None
    failing = _python_failing(_apply(PY_SOURCE, old, new))
    assert set(killers) <= failing, f"{name}: caught by {sorted(failing)}"


@pytest.fixture(scope="module")
def typescript_failing(tmp_path_factory: pytest.TempPathFactory) -> dict[str, list[str]]:
    _ensure_built()
    dist = PACKAGE / "dist"
    source = (dist / "behavior.js").read_text(encoding="utf-8")
    variants = {"baseline": source, "sanity": _apply(source, SANITY[2], SANITY[3])}
    for name, (_, _, old, new, _) in MUTANTS.items():
        if old is not None and new is not None:
            variants[name] = _apply(source, old, new)
    work = tmp_path_factory.mktemp("ts-mutants")
    dirs = {}
    for i, (name, text) in enumerate(variants.items()):
        copy = work / f"m{i}"
        shutil.copytree(dist, copy)
        (copy / "behavior.js").write_text(text, encoding="utf-8")
        dirs[name] = str(copy / "index.js")
    script = (
        'import { readFileSync, readdirSync } from "node:fs";'
        'import { join } from "node:path";'
        'import { pathToFileURL } from "node:url";'
        "const [dirsPath, vectorDir] = process.argv.slice(1);"
        "const dirs = JSON.parse(readFileSync(dirsPath, 'utf8'));"
        "const vectors = readdirSync(vectorDir).filter((f) => f.endsWith('.json')).sort()"
        "  .map((f) => [f.slice(0, -5), JSON.parse(readFileSync(join(vectorDir, f), 'utf8'))]);"
        "const out = {};"
        "for (const [name, index] of Object.entries(dirs)) {"
        "  const { verifyRun } = await import(pathToFileURL(index).href);"
        "  out[name] = [];"
        "  for (const [vname, v] of vectors) {"
        "    let got;"
        "    try { got = await verifyRun(v.blocks, v.pinned_keys); } catch { got = null; }"
        "    if (JSON.stringify(got) !== JSON.stringify(v.expected)) out[name].push(vname);"
        "  }"
        "}"
        "process.stdout.write(JSON.stringify(out));"
    )
    (work / "dirs.json").write_text(json.dumps(dirs), encoding="utf-8")
    done = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(work / "dirs.json"),
         str(VECTORS[0].parent)],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    result: dict[str, list[str]] = json.loads(done.stdout)
    return result


def test_typescript_baseline_passes_every_vector(typescript_failing: dict[str, list[str]]) -> None:
    assert typescript_failing["baseline"] == []


def test_typescript_sanity_mutant_is_killed(typescript_failing: dict[str, list[str]]) -> None:
    assert typescript_failing["sanity"]


@pytest.mark.parametrize("name", [n for n, m in MUTANTS.items() if m[2] is not None])
def test_typescript_mutant_is_killed(
    name: str, typescript_failing: dict[str, list[str]]
) -> None:
    killers = MUTANTS[name][4]
    failing = set(typescript_failing[name])
    assert set(killers) <= failing, f"{name}: caught by {sorted(failing)}"
