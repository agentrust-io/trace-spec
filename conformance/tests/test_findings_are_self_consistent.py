"""A finding's message must not name an error code other than its own.

`report.py` publishes both: the JSON artifact carries `code` per finding and the HTML
table prints it beside the text. When they disagree, the reader has two codes for one
result and no way to tell which the tooling meant.

They did disagree. `_verify_ed25519` returned messages prefixed with `TR-SIG-001`,
`TR-SIG-002` and `TR-SIG-003`, and two callers attached those messages to findings of
their own: `check` under `TR-SIG-005` and `check_cmcp_runtime` under `TR-SIG-001`. A
record with a malformed signature was published as a TR-SIG-005 finding reading
"TR-SIG-003: invalid base64url signature", so the forwarded report named a code the
suite had not used and the docs describe as something else.

Naming a module's own code in its message is the convention everywhere else here and
is left alone; this only rejects naming a different one.
"""
from __future__ import annotations

import copy
import inspect
import json
import pathlib
import re
from typing import Any

import pytest

from trace_tests.modules import tr_anc, tr_apr, tr_env, tr_pol, tr_rte, tr_sca, tr_sig, tr_txn
from trace_tests.result import Finding

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors"

MODULES = {
    "tr_env": tr_env, "tr_sig": tr_sig, "tr_pol": tr_pol, "tr_rte": tr_rte,
    "tr_txn": tr_txn, "tr_anc": tr_anc, "tr_sca": tr_sca, "tr_apr": tr_apr,
}

_CODE = re.compile(r"TR-[A-Z]{3}-\d{3}")

#: Values chosen to reach the error branches rather than to be exhaustive: a bad
#: base64 key, a key of the wrong length, a signature that decodes but does not
#: verify, and a signature that does not decode at all.
SIGNATURE_CASES: tuple[Any, ...] = ("!!!not-base64!!!", "AAAA", 123, None, "", [1])


def _plain() -> dict[str, Any]:
    raw = json.loads((VECTORS / "signed_root.json").read_text(encoding="utf-8"))
    return dict(raw.get("record", raw))


def _cmcp() -> dict[str, Any]:
    return json.loads((VECTORS / "valid_cmcp_runtime.json").read_text(encoding="utf-8"))


def _call(module: Any, record: dict[str, Any], fmt: str = "trace") -> list[Finding]:
    params = list(inspect.signature(module.check).parameters)
    if params[:3] == ["trace", "record", "fmt"]:
        trace = record.get("trace", record) if fmt == "cmcp-runtime" else record
        return list(module.check(trace, record, fmt, 0))
    if "level" in params:
        return list(module.check(record, 0))
    return list(module.check(record))


def _foreign_codes(findings: list[Finding]) -> list[str]:
    out = []
    for finding in findings:
        for named in _CODE.findall(finding.message):
            if named != finding.code:
                out.append(f"{finding.code} message names {named}: {finding.message}")
    return out


@pytest.mark.parametrize("name", sorted(MODULES))
def test_no_finding_names_a_code_other_than_its_own(name: str) -> None:
    module = MODULES[name]
    offenders: list[str] = []

    records = [_plain()]
    for field in ("signature", "cnf", "runtime", "policy", "appraisal", "transparency"):
        for junk in SIGNATURE_CASES:
            record = _plain()
            record[field] = junk
            records.append(record)
    for junk in SIGNATURE_CASES:
        record = _plain()
        record["cnf"]["jwk"]["x"] = junk
        records.append(record)
        record = _plain()
        record["cnf"]["jwk"] = junk
        records.append(record)
    record = _plain()
    record["cnf"]["jwk"]["d"] = "AAAA"
    records.append(record)

    examined = 0
    for record in records:
        try:
            findings = _call(module, copy.deepcopy(record))
        except Exception:  # noqa: BLE001 - covered by test_modules_never_raise
            continue
        examined += len(findings)
        offenders += _foreign_codes(findings)

    assert not offenders, (
        f"{name} publishes findings whose message names a different code:\n  "
        + "\n  ".join(sorted(set(offenders)))
    )
    # Every record here is skipped when the module raises, so without this the check
    # reports a pass over nothing the moment a module stops returning findings at all.
    assert examined, (
        f"no finding from {name} was examined: every record raised, so this check "
        "looked at nothing and would have reported a pass either way"
    )


def test_the_cmcp_path_also_keeps_its_findings_self_consistent() -> None:
    """The other caller of the same helper, which the parametrised test never reaches.

    ``check`` attaches those messages under TR-SIG-005 and ``check_cmcp_runtime``
    attaches them under TR-SIG-001. A code written in the helper could only ever match
    one of the two, which is the reason it names none.
    """
    offenders: list[str] = []
    examined = 0
    for junk in SIGNATURE_CASES:
        for path in (("signature",), ("trace", "cnf", "jwk", "x")):
            record = _cmcp()
            node: Any = record
            ok = True
            for key in path[:-1]:
                if not isinstance(node.get(key), dict):
                    ok = False
                    break
                node = node[key]
            if not ok:
                continue
            node[path[-1]] = junk
            try:
                findings = _call(tr_sig, record, "cmcp-runtime")
            except Exception:  # noqa: BLE001 - covered by test_modules_never_raise
                continue
            examined += len(findings)
            offenders += _foreign_codes(findings)

    assert not offenders, (
        "the cmcp path publishes findings whose message names a different code:\n  "
        + "\n  ".join(sorted(set(offenders)))
    )
    assert examined, "no cmcp finding was examined: every envelope raised"
