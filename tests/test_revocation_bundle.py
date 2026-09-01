"""The revocation-bundle consumer, held to section 3.2.3 and to its own vectors.

Three groups. The vector runner puts every fixture under `examples/revocation-bundle/`
through `verify_record` and compares what came back to the fixture's `expected`
block, evidence included. The invariant tests pin the properties the module's
docstring claims, each as a run rather than a sentence. The discrimination test
implements the five candidate staleness rules as stubs and shows the age vectors
reject all but tighter-governs, which is the claim made on #190 in a table,
executed.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import pytest

from agentrust_trace import verify_record
from dataclasses import FrozenInstanceError

from agentrust_trace.revocation import NO_CHECK, VerificationResult, check_bundle
from agentrust_trace.sign import jwk_thumbprint

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples" / "revocation-bundle"
FILES = sorted(VECTORS.glob("*.json"))
assert FILES, "no revocation-bundle vectors on disk; the runner would measure nothing"


def _load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run(doc: dict) -> VerificationResult:
    ctx = doc["context"]
    return verify_record(
        doc["records"][0],
        ctx["trusted_key"],
        now=ctx["now"],
        max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
        max_future_skew_seconds=ctx["max_future_skew_seconds"],
        revocation_bundle=ctx["bundle"],
        trusted_bundle_keys=ctx["trusted_bundle_keys"],
    )


# ---- the vectors --------------------------------------------------------------


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_vector(path: pathlib.Path) -> None:
    doc = _load(path)
    expected = doc["expected"]
    if expected["rejected"]:
        with pytest.raises(ValueError, match="revoked"):
            _run(doc)
        return
    result = _run(doc)
    check = result.revocation
    assert check.outcome == expected["outcome"], path.name
    assert check.cause == expected["cause"], path.name
    for key, value in expected["evidence"].items():
        assert check.evidence.get(key) == value, f"{path.name}: evidence[{key!r}]"


def test_every_vector_has_a_stable_id_and_the_ids_are_unique() -> None:
    ids = [_load(p)["id"] for p in FILES]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"TRACE-RBUN-\d{3}", i) for i in ids)


def test_evidence_is_json_serialisable_for_every_vector() -> None:
    """I6 needs the evidence to be retainable beside the record, which means bytes."""
    for path in FILES:
        doc = _load(path)
        if doc["expected"]["rejected"]:
            continue
        json.dumps(_run(doc).revocation.evidence)


# ---- invariants ---------------------------------------------------------------


def _fresh() -> tuple[dict, dict]:
    doc = _load(VECTORS / "01-fresh-well-inside-both-bounds.json")
    return doc, doc["context"]


def test_I1_outcome_is_always_one_of_three_and_never_raised() -> None:
    seen = set()
    for path in FILES:
        doc = _load(path)
        if doc["expected"]["rejected"]:
            continue
        seen.add(_run(doc).revocation.outcome)
    assert seen == {"verified", "unverified_for_revocation", "no_check_performed"}


def test_I2_no_check_performed_iff_no_bundle_and_no_store() -> None:
    doc, ctx = _fresh()
    neither = verify_record(doc["records"][0], ctx["trusted_key"], now=ctx["now"])
    assert neither.revocation == NO_CHECK
    store_only = verify_record(
        doc["records"][0], ctx["trusted_key"], now=ctx["now"], revocation=set()
    )
    assert store_only.revocation.outcome == "verified"
    assert store_only.revocation.evidence == {"source": "store"}
    both = verify_record(
        doc["records"][0], ctx["trusted_key"], now=ctx["now"], revocation=set(),
        revocation_bundle=ctx["bundle"], trusted_bundle_keys=ctx["trusted_bundle_keys"],
        max_bundle_age_seconds=ctx["max_bundle_age_seconds"],
    )
    assert both.revocation.outcome == "verified"
    assert both.revocation.evidence["store"] == "consulted"
    assert "bundle_digest" in both.revocation.evidence, "the bundle governs when both are present"


def test_I4_tighter_governs_is_true_exactly_on_the_intersection() -> None:
    """The four rows of the truth table, each carried by a signed vector.

    A bundle cannot be re-aged in a test without re-signing it, and the generator
    is not imported here, so the rows are read from the committed vectors whose
    bundles were signed over exactly these ages.
    """
    rows = {
        "01-fresh-well-inside-both-bounds": None,
        "04-deployment-bound-tripped-wide": "deployment",
        "06-issuer-bound-tripped-wide": "issuer",
        "08-both-bounds-tripped-wide": "both",
    }
    for name, tripped in rows.items():
        check = _run(_load(VECTORS / f"{name}.json")).revocation
        if tripped is None:
            assert check.outcome == "verified", name
        else:
            got = (check.cause, check.evidence["bound_tripped"])
            assert got == ("bundle_expired", tripped), name


def test_I5_every_expired_outcome_names_which_bound_tripped() -> None:
    for path in FILES:
        doc = _load(path)
        if doc["expected"].get("cause") == "bundle_expired":
            tripped = _run(doc).revocation.evidence["bound_tripped"]
            assert tripped in {"issuer", "deployment", "both"}, path.name


def test_I6_a_second_verifier_reproduces_the_outcome_from_retained_facts() -> None:
    """Same bundle, same retained now and max age, no clock: identical result."""
    for path in FILES:
        doc = _load(path)
        if doc["expected"]["rejected"] or doc["context"]["bundle"] is None:
            continue
        first = _run(doc).revocation
        ev = first.evidence
        second = check_bundle(
            doc["context"]["bundle"],
            trusted_key_identifiers=[jwk_thumbprint(doc["context"]["trusted_key"])],
            trusted_bundle_keys=doc["context"]["trusted_bundle_keys"],
            now=ev.get("now", doc["context"]["now"]),
            max_bundle_age_seconds=ev.get(
                "max_bundle_age_seconds", doc["context"]["max_bundle_age_seconds"]
            ),
            max_future_skew_seconds=doc["context"]["max_future_skew_seconds"],
        )
        assert second == first, path.name


def test_I7_nothing_under_src_or_this_test_reaches_the_network() -> None:
    """Import lines only, with a control that fires in the same call.

    This file is swept too, and the socket-blocking test below has to be blind
    to that sweep by construction rather than by exemption: it names `socket`
    through `monkeypatch.setattr`'s dotted-string form and never imports it, so
    there is no import here to find and nothing for a reader to wonder about.
    """
    pattern = re.compile(
        r"^\s*(import|from)\s+(socket|urllib|http\.client|httpx|requests|aiohttp)\b"
    )
    files = sorted((ROOT / "src" / "agentrust_trace").glob("*.py")) + [pathlib.Path(__file__)]
    hits = [
        f"{path.name}:{n}: {line.strip()}"
        for path in files
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.match(line)
    ]
    assert hits == [], hits
    assert pattern.match("import socket") and pattern.match("from urllib import request")


def test_I8_absence_is_an_outcome_and_only_failing_evidence_raises() -> None:
    doc, ctx = _fresh()
    for name in (
        "15-signature-value-corrupted",
        "17-bundle-key-unknown-to-caller",
        "19-malformed-valid-until-absent",
    ):
        outcome = _run(_load(VECTORS / f"{name}.json")).revocation.outcome
        assert outcome == "unverified_for_revocation", name
    with pytest.raises(ValueError, match="revoked"):
        _run(_load(VECTORS / "11-statement-names-trusted-key-by-thumbprint.json"))


def test_I9_the_module_names_no_appraisal_status_value() -> None:
    source = (ROOT / "src" / "agentrust_trace" / "revocation.py").read_text(encoding="utf-8")
    for value in ("affirming", "warning", "contraindicated", '"none"'):
        assert value not in source.replace("affirming appraisal", ""), value
    assert "affirming appraisal" in source, "the 3.2.3 sentence the module is built around"


def test_I11_an_authenticated_statement_is_read_before_either_time_check() -> None:
    """Vectors 26, 27 and 28 carry the same statement as 11 inside bundles that are
    stale by the issuer, stale by the deployment, and dated in the future. All
    three reject. Their statement-free counterparts (07, 05, 24) report unverified,
    so the ordering is what separates them, and reversing it turns these red."""
    for name in (
        "26-stale-by-issuer-statement-still-rejects",
        "27-stale-by-deployment-statement-still-rejects",
        "28-future-issued-statement-still-rejects",
    ):
        with pytest.raises(ValueError, match="revoked"):
            _run(_load(VECTORS / f"{name}.json"))
    for name, cause in (
        ("07-issuer-bound-tripped-by-one-second", "bundle_expired"),
        ("05-deployment-bound-tripped-by-one-second", "bundle_expired"),
        ("24-issued-in-future-by-a-day", "bundle_issued_in_future"),
    ):
        assert _run(_load(VECTORS / f"{name}.json")).revocation.cause == cause, name


# ---- the truth table, executed -------------------------------------------------


def _stubs(now: int, max_age: int):
    return {
        "min": lambda b: now > b["valid_until"] or now - b["issued_at"] > max_age,
        "issuer": lambda b: now > b["valid_until"],
        "deploy": lambda b: now - b["issued_at"] > max_age,
        "max": lambda b: now > b["valid_until"] and now - b["issued_at"] > max_age,
        "none": lambda b: False,
        # Two shortcuts, not rules: each honours one bound exactly and gives the
        # other a minute of grace. They are what the one-second margin vectors catch.
        "deploy_grace": lambda b: now > b["valid_until"] or now - b["issued_at"] > max_age + 60,
        "issuer_grace": lambda b: now - b["issued_at"] > max_age or now > b["valid_until"] + 60,
    }


AGE_ROWS = {"01", "02", "03", "04", "05", "06", "07", "08", "09"}


def test_the_age_vectors_reject_every_rule_but_tighter_governs() -> None:
    """Seven implementations of "too old", nine vectors, one survivor.

    The five rules are functions of the two booleans, issuer bound tripped and
    deployment bound tripped, so the four wide rows (01, 04, 06, 08) separate
    them completely: this is the table posted on #190, run. The two grace
    shortcuts are not functions of those booleans; they move a threshold by a
    minute, which is exactly why the four rows cannot see them and the one-second
    rows (05, 07) exist. Over all nine, only tighter-governs survives.
    """
    age_vectors = [p for p in FILES if p.name[:2] in AGE_ROWS]
    docs = [_load(p) for p in age_vectors]
    now = docs[0]["context"]["now"]
    max_age = docs[0]["context"]["max_bundle_age_seconds"]
    survivors = []
    for rule, expired in _stubs(now, max_age).items():
        agrees = all(
            expired(d["context"]["bundle"]) == (d["expected"].get("cause") == "bundle_expired")
            for d in docs
        )
        if agrees:
            survivors.append(rule)
    assert survivors == ["min"], survivors


def test_the_margin_vectors_catch_a_shortcut_the_wide_vectors_miss() -> None:
    """The reason 05 and 07 exist, shown. A minute of grace on one bound agrees with
    every wide row and fails on that bound's one-second row."""
    now = _load(FILES[0])["context"]["now"]
    max_age = _load(FILES[0])["context"]["max_bundle_age_seconds"]
    stubs = _stubs(now, max_age)

    def agrees(rule, prefix: str) -> bool:
        doc = next(_load(p) for p in FILES if p.name[:2] == prefix)
        expected = doc["expected"].get("cause") == "bundle_expired"
        return rule(doc["context"]["bundle"]) == expected

    for name, fails_on in (("deploy_grace", "05"), ("issuer_grace", "07")):
        rule = stubs[name]
        assert all(agrees(rule, p) for p in ("04", "06", "08")), f"{name} should survive wide rows"
        assert not agrees(rule, fails_on), f"{name} should fail on {fails_on}"


def test_without_vector_D_max_and_none_are_indistinguishable() -> None:
    """The reason D is kept, shown rather than asserted."""
    docs = [_load(p) for p in FILES if p.name[:2] in {"01", "04", "06"}]
    now = docs[0]["context"]["now"]
    max_age = docs[0]["context"]["max_bundle_age_seconds"]
    stubs = _stubs(now, max_age)
    answers = {rule: [f(d["context"]["bundle"]) for d in docs] for rule, f in stubs.items()}
    assert answers["max"] == answers["none"]


# ---- the shape imran chose, and its stated cost ---------------------------------


def test_a_caller_who_discards_the_result_gets_no_exception_and_no_warning(recwarn) -> None:
    """F1, pinned as a fact, and nothing else: the call is made, the return is
    dropped, and no exception or warning carries the outcome to the caller. The
    outcome itself is asserted in the next test, so a change to the return type
    cannot make this one red for a reason that is not the silence."""
    doc = _load(VECTORS / "14-no-bundle-no-check-performed.json")
    ctx = doc["context"]
    verify_record(doc["records"][0], ctx["trusted_key"], now=ctx["now"])
    assert not [w for w in recwarn if "revocation" in str(w.message).lower()]


def test_the_discarded_result_would_have_said_no_check_performed() -> None:
    """The other half of F1: what the caller above threw away."""
    doc = _load(VECTORS / "14-no-bundle-no-check-performed.json")
    assert _run(doc).revocation.outcome == "no_check_performed"


def test_verification_result_is_immutable() -> None:
    doc, _ = _fresh()
    result = _run(doc)
    with pytest.raises(FrozenInstanceError):
        result.revocation = NO_CHECK  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.revocation.evidence = {}  # type: ignore[misc]


# ---- the packaged schemas ---------------------------------------------------------


@pytest.mark.parametrize("name", ["trace-revocation.json", "trace-revocation-bundle.json"])
def test_packaged_revocation_schema_is_byte_identical_to_its_source(name: str) -> None:
    source = (ROOT / "schema" / name).read_bytes()
    packaged = (ROOT / "src" / "agentrust_trace" / "schema" / name).read_bytes()
    assert source == packaged, f"{name}: the packaged copy has drifted from schema/"


def _refuse_sockets(monkeypatch) -> None:
    """Block every connection this process could open, by name, with no import.

    The dotted-string form resolves inside pytest, so this file carries no
    network import for I7 to find. The replacement is a class, not a function:
    `ssl` does `class SSLSocket(socket)` at import, so a function there breaks
    the fetch path with a TypeError about code objects before any connection
    is attempted, and the red says nothing about the network. Any class can be
    subclassed, so this one need not descend from the real socket class, and
    it refuses on construction. `create_connection` is not patched separately
    because it builds its socket through this same module global; the control
    below goes through it. `test_the_socket_block_is_live` proves the block is
    real.
    """
    class RefusingSocket:
        def __init__(self, *args, **kwargs):
            raise AssertionError("bundle validation opened a socket")

    monkeypatch.setattr("socket.socket", RefusingSocket)


def test_bundle_validation_resolves_the_statement_ref_with_sockets_blocked(monkeypatch) -> None:
    """The $ref is an absolute URL, and on a networked machine a validator without
    the packaged registry fetches it and passes anyway. So the witness blocks
    sockets for the duration: with the registry, validation reaches step 3b; without
    it, this test reds on any machine rather than only on an offline one.
    """
    _refuse_sockets(monkeypatch)
    # A fresh validator, so a cached one built before the block cannot stand in.
    from agentrust_trace import revocation as module
    module._bundle_validator.cache_clear()
    try:
        doc = _load(VECTORS / "20-malformed-statement-on-another-log.json")
        try:
            result = _run(doc)
        except Exception as exc:  # noqa: BLE001 - the chain is the diagnostic
            # referencing wraps retrieval errors, so the block's message sits at
            # the root of the chain; print the whole chain so the red is legible.
            chain, err = [], exc
            while err is not None:
                chain.append(f"{type(err).__name__}: {err}")
                err = err.__cause__ or err.__context__
            pytest.fail("bundle validation tried to leave the process:\n  " + "\n  ".join(chain))
        assert result.revocation.evidence["path"] == "statements/0/log_id"
    finally:
        module._bundle_validator.cache_clear()


def test_the_socket_block_is_live(monkeypatch) -> None:
    """The control. Under the same block, a connection attempt to the discard port
    must fail with the block's own message, and with nothing else: change the
    message and the match fails; remove the block and this test fails. A real
    connection attempt is not shown here, because the only thing that loads
    `socket` into this process is the block itself, and this file does not
    import it; the match on the block's message is the witness."""
    _refuse_sockets(monkeypatch)
    with pytest.raises(AssertionError, match="opened a socket"):
        sys.modules["socket"].create_connection(("127.0.0.1", 9), timeout=0.2)


def test_the_generator_reproduces_the_committed_vectors_byte_for_byte(
    tmp_path: pathlib.Path,
) -> None:
    """LF bytes on every platform. `test_generators_reproduce_fixtures` also covers
    this; it is repeated here so a failure in this set is reported beside the set."""
    import shutil
    target = tmp_path / "examples" / "revocation-bundle"
    shutil.copytree(ROOT / "examples" / "revocation-bundle", target)
    subprocess.run(
        [sys.executable, "examples/revocation-bundle/gen_revocation_vectors.py"],
        cwd=tmp_path, check=True, capture_output=True,
    )
    for path in FILES:
        assert (target / path.name).read_bytes() == path.read_bytes(), path.name
