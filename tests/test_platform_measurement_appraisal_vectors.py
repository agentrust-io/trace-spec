"""The platform-measurement appraisal vectors, held to what they say. Spec section 3.1.5.

`examples/platform-measurement-appraisal/` pins two things. The shape rules: both
validators, the schema and the reference model, return the verdict each vector expects,
and a rejected vector fails where its code says it does and nowhere else. One rule,
`measurement_mismatch`, compares two members of the record, which a JSON Schema cannot
do; its vectors say `"schema_sees": false`, and the schema is held to accepting them so
that the claim stays true. And the reading: on every accepting vector, `read_layer`
below, the reading rule 1 of the section fixes, returns the outcome the vector names.

The pairs are what make the reading testable. A reader that refuses everything, one
that takes `appraisal.status` at its word, and one that reads an unlisted layer as
established each fail at least one vector, and the tests at the bottom say which.
"""

from __future__ import annotations

import base64
import json
import pathlib
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from agentrust_trace import TrustRecord, iter_errors
from agentrust_trace.sign import _canonical_bytes, _pubkey_from_jwk

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTOR_DIR = ROOT / "examples" / "platform-measurement-appraisal"
VECTORS = sorted(VECTOR_DIR.glob("*.json"))
IDS = [p.stem for p in VECTORS]

#: Where each code's rejection is reported, and the prefix every error must sit under.
LOCUS: dict[str, tuple[str, str]] = {
    "not_established_without_reason": ("appraisal.platform_measurement.layers",
                                       "appraisal.platform_measurement.layers"),
    "established_with_reason": ("appraisal.platform_measurement.layers",
                                "appraisal.platform_measurement.layers"),
    "layers_empty": ("appraisal.platform_measurement.layers",
                     "appraisal.platform_measurement.layers"),
    "unknown_reason": ("appraisal.platform_measurement.layers",
                       "appraisal.platform_measurement.layers"),
    "tpm_layer_name": ("appraisal.platform_measurement.layers",
                       "appraisal.platform_measurement.layers"),
    "measurement_mismatch": ("", ""),
    "status_none_with_result": ("appraisal.status", "appraisal.status"),
}

Reading = dict[str, str]
Reader = Callable[[dict[str, Any], str], Reading]


def _load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_layer(record: dict[str, Any], layer: str) -> Reading:
    """Rule 1 of section 3.1.5, as a relying party applies it to an accepted record.

    The layer's own outcome when the result lists it; `not-established` with the
    reader's reason `not-listed` when it does not. `appraisal.status` is not consulted:
    rule 2 constrains what a verifier writes there, and a reader that keys on the
    layers needs nothing from it.
    """
    result = record["appraisal"].get("platform_measurement")
    if result is None or layer not in result["layers"]:
        return {"outcome": "not-established", "reason": "not-listed"}
    return dict(result["layers"][layer])


def _accepting() -> list[pathlib.Path]:
    return [p for p in VECTORS if _load(p)["expected"]["outcome"] == "accept"]


def _reading_failures(reader: Reader) -> list[str]:
    failed = []
    for path in _accepting():
        doc = _load(path)
        for layer, want in doc["expected"]["reading"].items():
            if reader(doc["record"], layer) != want:
                failed.append(f"{path.stem}:{layer}")
    return failed


def test_the_corpus_did_not_shrink() -> None:
    """Pinned, so deleting an awkward vector is a visible act rather than a quiet one."""
    assert len(VECTORS) == 44


def test_every_code_is_carried_by_two_vectors() -> None:
    by_code: dict[str, list[str]] = {}
    for path in VECTORS:
        for code in _load(path)["expected"]["codes"]:
            by_code.setdefault(code, []).append(path.stem)
    assert set(by_code) == set(LOCUS), "a code without a locus, or a locus without a code"
    thin = {code: names for code, names in by_code.items() if len(names) < 2}
    assert not thin, f"codes carried by one vector: {thin}"


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_the_schema_returns_the_expected_verdict(path: pathlib.Path) -> None:
    doc = _load(path)
    errors = iter_errors(doc["record"])
    if doc["expected"]["outcome"] == "accept" or doc["expected"].get("schema_sees") is False:
        assert not errors, [e.message for e in errors]
        return
    assert errors, "the schema accepts a record the vector says it refuses"
    (code,) = doc["expected"]["codes"]
    at, under = LOCUS[code]
    paths = {".".join(str(k) for k in e.absolute_path) for e in errors}
    assert any(p == at or p.startswith(at + ".") for p in paths), (
        f"{code} is reported at {at}; the schema reported at {sorted(paths)}")
    outside = sorted(p for p in paths if not (p == under or p.startswith(under + ".")))
    assert not outside, f"{path.stem} is also rejected at {outside}, outside {under}"


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_the_model_returns_the_expected_verdict(path: pathlib.Path) -> None:
    doc = _load(path)
    if doc["expected"]["outcome"] == "accept":
        parsed = TrustRecord.model_validate(doc["record"])
        assert parsed.model_dump() == doc["record"]
        return
    with pytest.raises(ValidationError):
        TrustRecord.model_validate(doc["record"])


def test_the_mismatch_vectors_fail_on_the_mismatch_and_nothing_else() -> None:
    """The model is the only validator that sees this rule, so it must see this rule:
    the same record with the result's measurement set back to runtime.measurement is
    accepted."""
    for path in VECTORS:
        doc = _load(path)
        if doc["expected"]["codes"] != ["measurement_mismatch"]:
            continue
        record = doc["record"]
        with pytest.raises(ValidationError, match="must equal runtime.measurement"):
            TrustRecord.model_validate(record)
        fixed = json.loads(json.dumps(record))
        fixed["appraisal"]["platform_measurement"]["measurement"] = (
            record["runtime"]["measurement"])
        TrustRecord.model_validate(fixed)


@pytest.mark.parametrize("path", VECTORS, ids=IDS)
def test_the_signature_verifies(path: pathlib.Path) -> None:
    record = _load(path)["record"]
    encoded = record["signature"]
    signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    body = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    _pubkey_from_jwk(record["cnf"]["jwk"]).verify(signature, body)


@pytest.mark.parametrize("path", _accepting(), ids=[p.stem for p in _accepting()])
def test_the_reading_is_what_the_vector_names(path: pathlib.Path) -> None:
    doc = _load(path)
    for layer, want in doc["expected"]["reading"].items():
        assert read_layer(doc["record"], layer) == want, layer


def test_every_twin_differs_from_its_case_in_one_layer_only() -> None:
    """A twin that differed in more than its condition could not show which difference
    the reading keyed on."""
    docs = {p.stem[:2]: _load(p) for p in VECTORS}
    twins = [d for d in docs.values()
             if "twin_of" in d and docs[d["twin_of"]]["expected"]["outcome"] == "accept"]
    assert len(twins) == 5
    for twin in twins:
        case = docs[twin["twin_of"]]
        a = json.loads(json.dumps({k: v for k, v in case["record"].items() if k != "signature"}))
        b = json.loads(json.dumps({k: v for k, v in twin["record"].items() if k != "signature"}))
        pa = a["appraisal"].pop("platform_measurement", None)
        pb = b["appraisal"].pop("platform_measurement", None)
        assert a == b, twin["name"]
        if pa is None:
            # The case writes no result at all; the twin's result names pcr:2 only.
            assert pb is not None and set(pb["layers"]) == {"pcr:2"}, twin["name"]
            assert pb["measurement"] == b["runtime"]["measurement"], twin["name"]
        else:
            la, lb = pa.pop("layers"), pb.pop("layers")
            assert pa == pb, twin["name"]
            changed = {k for k in la.keys() | lb.keys() if la.get(k) != lb.get(k)}
            assert changed == {"pcr:2"}, (twin["name"], changed)
        assert case["expected"]["reading"]["pcr:2"]["outcome"] == "not-established"
        assert twin["expected"]["reading"]["pcr:2"]["outcome"] == "established"


def test_the_real_measurements_are_the_published_ones() -> None:
    """The two sourced vectors carry the measurements the #457 vectors carry, which
    cite the same published evidence; a typo here would cite evidence that does not
    say what the vector says."""
    def measurement(directory: str, stem: str) -> str:
        doc = _load(ROOT / "examples" / directory / f"{stem}.json")
        record = doc["record"] if "record" in doc else doc["records"][0]
        return record["runtime"]["measurement"]
    assert measurement("platform-measurement-appraisal", "09-rc13-layer-not-measured") == (
        measurement("platform-measurement", "15-rc13-layer-not-measured"))
    assert measurement("platform-measurement-appraisal", "10-dev-measured-not-appraised") == (
        measurement("platform-measurement", "16-dev-measured-not-appraised"))
    sourced = [p.stem for p in VECTORS if "source" in _load(p)]
    assert sourced == ["09-rc13-layer-not-measured", "10-dev-measured-not-appraised"]
    for path in VECTORS:
        doc = _load(path)
        assert ("source" in doc) != bool(doc.get("synthetic")), path.stem


def test_the_reference_reader_reads_every_vector() -> None:
    assert not _reading_failures(read_layer)


def test_a_reader_that_refuses_everything_fails_the_twins() -> None:
    failed = _reading_failures(
        lambda record, layer: {"outcome": "not-established", "reason": "not-listed"})
    assert {f.split(":")[0] for f in failed} >= {
        "02-layer-not-measured-twin", "04-measured-not-appraised-twin",
        "06-evidence-spans-multiple-boots-twin", "08-layer-not-listed-twin",
        "24-no-result-twin"}


def test_a_reader_that_trusts_the_status_fails_the_cases() -> None:
    """Every case carries a status other than contraindicated; a reader that takes a
    status short of contraindicated as a pass reads every layer established."""
    def by_status(record: dict[str, Any], layer: str) -> Reading:
        if record["appraisal"]["status"] != "contraindicated":
            return {"outcome": "established"}
        return {"outcome": "not-established", "reason": "not-listed"}
    failed = {f.split(":")[0] for f in _reading_failures(by_status)}
    assert failed >= {"01-layer-not-measured", "03-measured-not-appraised",
                      "05-evidence-spans-multiple-boots", "07-layer-not-listed",
                      "23-no-result"}


def test_a_reader_that_takes_an_unlisted_layer_as_established_fails_07_and_23() -> None:
    def lenient(record: dict[str, Any], layer: str) -> Reading:
        result = record["appraisal"].get("platform_measurement") or {"layers": {}}
        return dict(result["layers"].get(layer, {"outcome": "established"}))
    failed = {f.split(":")[0] for f in _reading_failures(lenient)}
    assert {"07-layer-not-listed", "23-no-result"} <= failed


def test_the_two_boot_case_is_not_contraindicated() -> None:
    """Rule 3: a replay mismatch the verifier cannot attribute to one boot is not, on
    that basis alone, contraindicated."""
    doc = _load(VECTOR_DIR / "05-evidence-spans-multiple-boots.json")
    assert doc["record"]["appraisal"]["status"] != "contraindicated"


#: The members a rejection's twin may put right, by the code of the rule it breaks.
TWIN_FIX: dict[str, tuple[str, ...]] = {
    "not_established_without_reason": ("appraisal.platform_measurement.layers",),
    "established_with_reason": ("appraisal.platform_measurement.layers",),
    "layers_empty": ("appraisal.platform_measurement.layers",),
    "unknown_reason": ("appraisal.platform_measurement.layers",),
    "tpm_layer_name": ("appraisal.platform_measurement.layers",),
    "measurement_mismatch": ("appraisal.platform_measurement.measurement",),
    "status_none_with_result": ("appraisal.status",),
}


def _leaves(node: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(node, dict) and node:
        out: dict[str, Any] = {}
        for key, value in node.items():
            out.update(_leaves(value, f"{prefix}.{key}" if prefix else key))
        return out
    return {prefix: node}


def test_every_rejection_has_one_twin_that_differs_only_in_its_rule() -> None:
    """The twin is the rejected record with the one member that breaks the rule put
    right. It is accepted, so a verifier that refuses everything fails it; and nothing
    outside that member differs, so the verdicts of the two can only turn on the rule."""
    docs = {p.stem[:2]: _load(p) for p in VECTORS}
    rejected = {k for k, d in docs.items() if d["expected"]["outcome"] == "reject"}
    twins = {d["twin_of"]: d for d in docs.values()
             if "twin_of" in d and d["twin_of"] in rejected}
    assert set(twins) == rejected, sorted(rejected - set(twins))
    for key, twin in twins.items():
        case = docs[key]
        (code,) = case["expected"]["codes"]
        assert twin["expected"]["outcome"] == "accept", twin["name"]
        a = _leaves({k: v for k, v in case["record"].items() if k != "signature"})
        b = _leaves({k: v for k, v in twin["record"].items() if k != "signature"})
        changed = {p for p in a.keys() | b.keys() if a.get(p, ...) != b.get(p, ...)}
        assert changed, twin["name"]
        outside = sorted(p for p in changed
                         if not any(p == f or p.startswith(f + ".") for f in TWIN_FIX[code]))
        assert not outside, (twin["name"], outside)


def test_a_non_tpm_layer_name_is_accepted() -> None:
    """The TPM naming rule binds tpm2 only; another platform names its layers its own way."""
    doc = _load(VECTOR_DIR / "38-layers-empty-off-tpm-twin.json")
    assert doc["record"]["runtime"]["platform"] != "tpm2"
    assert list(doc["record"]["appraisal"]["platform_measurement"]["layers"]) == ["rtmr:0"]
    assert doc["expected"]["outcome"] == "accept"
