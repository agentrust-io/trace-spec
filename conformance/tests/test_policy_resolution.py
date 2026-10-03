"""The policy-resolution set proves itself: digests, referents, and TR-POL-003.

Every vector states one expected value — the status of the TR-POL-003 finding
— and every test here obtains that status by running the module, never by
constructing a ``Finding`` by hand. A test that builds its own finding and
hands it to the reporting layer tests whichever code it happened to name; it
stays green while the thing under test is wrong.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from trace_tests.runner import run

VECTOR_DIR = Path(__file__).parent / "vectors" / "policy-resolution"
SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "trace-claim.json"
MANIFEST = VECTOR_DIR / "resolutions.json"

VECTOR_PATHS = sorted(VECTOR_DIR.glob("[0-9][0-9]-*.json"))
IDS = [p.name[:2] for p in VECTOR_PATHS]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def manifest() -> dict:
    return _load(MANIFEST)


@pytest.fixture(scope="module")
def resolver(manifest):
    """The set's own resolver: the manifest, then the bytes on disk.

    A URI the manifest does not hold raises, and so does a mapped file that is
    not there. Both are how a fetch fails, and TR-POL-003 must reach the same
    status by either road while saying which one happened.
    """
    def _resolve(uri: str) -> bytes:
        return (VECTOR_DIR / manifest[uri]).read_bytes()
    return _resolve


def _pol003(record: dict, resolver, level: int = 0):
    results = run(record, "trace", level, max_age_seconds=10**9, policy_resolver=resolver)
    return next(f for f in results["TR-POL"] if f.code == "TR-POL-003")


@pytest.mark.level0
def test_the_set_has_the_vectors_its_readme_documents() -> None:
    readme = (VECTOR_DIR / "README.md").read_text(encoding="utf-8")
    assert len(VECTOR_PATHS) == 11, "the set is eleven vectors, 01 through 11"
    for path in VECTOR_PATHS:
        assert path.name in readme, f"{path.name} is not documented in the set's README"


@pytest.mark.level0
@pytest.mark.parametrize("path", VECTOR_PATHS, ids=IDS)
def test_the_record_is_valid_under_the_packaged_schema(path: Path, schema) -> None:
    """Including the malformed-URI vectors.

    ``format: "uri"`` is inert here: no format checker is passed at any
    validate call site in this repository, and ``uri`` is unregistered without
    an optional dependency that is not installed. So 08 and 10 are
    schema-valid and are caught by TR-POL-003 instead, which is the whole
    reason the check has something to do.
    """
    jsonschema.validate(_load(path)["record"], schema)


@pytest.mark.level0
@pytest.mark.parametrize("path", VECTOR_PATHS, ids=IDS)
def test_the_record_carries_no_invented_field(path: Path) -> None:
    """The set argues from the fields that exist, not from ones it wishes existed."""
    policy = _load(path)["record"]["policy"]
    assert set(policy) <= {"bundle_hash", "enforcement_mode", "version", "policy_uri"}, (
        f"{path.name} carries a policy field the packaged schema does not define"
    )


@pytest.mark.level0
@pytest.mark.parametrize("path", VECTOR_PATHS, ids=IDS)
def test_the_declared_resolution_matches_the_manifest(path: Path, manifest) -> None:
    """The vector's story about what it cites must match the one mapping on disk.

    There is a single manifest, so a vector cannot hold a private idea of what
    its URI resolves to. The three unreachable-by-design cases are named here
    rather than skipped, so that "not in the manifest" stays a deliberate state
    instead of an oversight.
    """
    vector = _load(path)
    cited = vector["context"]["cited_uri"]
    outcome = vector["context"]["resolution"]["outcome"]

    if outcome == "not_attempted":
        assert cited is None or cited not in manifest, (
            f"{path.name} says resolution was not attempted, but the manifest "
            "offers a route; the vector and the manifest disagree"
        )
        return
    if outcome == "unreachable_no_route":
        assert cited not in manifest, (
            f"{path.name} claims no route, but the manifest maps {cited}"
        )
        return
    if outcome == "unreachable_route_fails":
        assert cited in manifest, f"{path.name} claims a route the manifest does not hold"
        assert not (VECTOR_DIR / manifest[cited]).exists(), (
            f"{path.name} claims the route fails, but {manifest[cited]} is present"
        )
        return

    assert outcome == "resolved", f"{path.name}: unknown resolution outcome {outcome!r}"
    assert cited in manifest, f"{path.name} says it resolved, but no route is mapped"
    assert (VECTOR_DIR / manifest[cited]).exists()


@pytest.mark.level0
@pytest.mark.parametrize("path", VECTOR_PATHS, ids=IDS)
def test_the_module_produces_the_status_the_vector_expects(path: Path, resolver) -> None:
    """The load-bearing test: the module is run, and its finding is read."""
    vector = _load(path)
    finding = _pol003(vector["record"], resolver)
    assert finding.status.value == vector["expected"]["tr_pol_003"], (
        f"{path.name}: expected {vector['expected']['tr_pol_003']}, "
        f"got {finding.status.value} — {finding.message}"
    )


@pytest.mark.level0
@pytest.mark.parametrize("path", VECTOR_PATHS, ids=IDS)
def test_no_finding_message_leaks_the_bundle_bytes(path: Path, resolver) -> None:
    """A message is forwarded in reports; it names the digest, never the content."""
    finding = _pol003(_load(path)["record"], resolver)
    for bundle in (VECTOR_DIR / "policies").glob("*.json"):
        body = bundle.read_text(encoding="utf-8").strip()
        assert body not in finding.message


@pytest.mark.level0
def test_the_two_unresolvable_vectors_fail_by_different_roads() -> None:
    """05 and 11 must be separable, or one of them is a duplicate.

    A resolver that handled only a missing key would leave 11 reporting a
    comparison it never made, and one that handled only a missing file would
    do the same to 05. The pair is what makes that visible.
    """
    manifest = _load(MANIFEST)
    no_route = _load(VECTOR_DIR / "05-referent-unreachable-no-route.json")
    route_fails = _load(VECTOR_DIR / "11-referent-unreachable-route-fails.json")

    def only_keyerror(uri: str) -> bytes:
        return (VECTOR_DIR / manifest[uri]).read_bytes()

    # A resolver that answers for anything the manifest holds, even absent
    # files, deviates 11 alone: 05 still has no route.
    def tolerating_missing_files(uri: str) -> bytes:
        path = VECTOR_DIR / manifest[uri]
        return path.read_bytes() if path.exists() else b""

    a = _pol003(no_route["record"], tolerating_missing_files)
    b = _pol003(route_fails["record"], tolerating_missing_files)
    assert a.status.value == "unverified", "05 must be untouched by tolerating missing files"
    assert b.status.value != "unverified", (
        "11 must deviate when missing files are tolerated, or it is not "
        "independent of 05"
    )
    assert _pol003(route_fails["record"], only_keyerror).status.value == "unverified"


@pytest.mark.level0
def test_the_two_malformed_vectors_fail_by_different_roads() -> None:
    """08 and 10 must be separable for the same reason."""
    eight = _load(VECTOR_DIR / "08-policy-uri-is-a-relative-reference.json")
    ten = _load(VECTOR_DIR / "10-policy-uri-carries-a-space.json")
    assert " " not in eight["record"]["policy"]["policy_uri"], (
        "08 must be caught by the scheme rule alone, so it carries no whitespace"
    )
    assert "://" in ten["record"]["policy"]["policy_uri"], (
        "10 must be caught by the character rule alone, so its scheme is valid"
    )


@pytest.mark.level0
def test_the_two_sha384_vectors_separate_accept_from_compare() -> None:
    """06 and 09 must be separable, or sha384 support sits on one outcome."""
    six = _load(VECTOR_DIR / "06-resolved-and-matches-sha384.json")
    nine = _load(VECTOR_DIR / "09-sha384-bound-to-other-referent.json")
    assert six["record"]["policy"]["bundle_hash"].startswith("sha384:")
    assert nine["record"]["policy"]["bundle_hash"].startswith("sha384:")
    assert six["expected"]["tr_pol_003"] == "pass"
    assert nine["expected"]["tr_pol_003"] == "fail", (
        "without a sha384 vector that must fail, a verifier accepting sha384 "
        "without comparing would pass the set"
    )


@pytest.mark.level0
def test_03_and_04_differ_in_kind_not_just_in_bytes() -> None:
    """The pair that keeps the contradicted boundary off a single vector."""
    manifest = _load(MANIFEST)
    minimal = _load(VECTOR_DIR / "03-digest-mismatch-minimal-mutation.json")
    wholesale = _load(VECTOR_DIR / "04-digest-mismatch-different-object.json")
    base = (VECTOR_DIR / "policies" / "policy-bundle-base.json").read_bytes()
    a = (VECTOR_DIR / manifest[minimal["context"]["cited_uri"]]).read_bytes()
    b = (VECTOR_DIR / manifest[wholesale["context"]["cited_uri"]]).read_bytes()

    assert len(a) == len(base) and sum(x != y for x, y in zip(a, base)) == 1, (
        "03 must be the minimal mutation: one byte from the baseline"
    )
    assert len(b) != len(base), "04 must be a different object, not an edit of the baseline"


@pytest.mark.level0
def test_the_declared_digests_are_the_digests_of_the_bytes_on_disk() -> None:
    """Nothing in the set is a digest someone typed."""
    manifest = _load(MANIFEST)
    algos = {"sha256:": hashlib.sha256, "sha384:": hashlib.sha384}
    checked = 0
    for path in VECTOR_PATHS:
        vector = _load(path)
        if vector["context"]["resolution"]["outcome"] != "resolved":
            continue
        declared = vector["record"]["policy"]["bundle_hash"]
        prefix = declared.split(":")[0] + ":"
        body = (VECTOR_DIR / manifest[vector["context"]["cited_uri"]]).read_bytes()
        actual = prefix + algos[prefix](body).hexdigest()
        expected_match = vector["expected"]["tr_pol_003"] == "pass"
        assert (declared == actual) is expected_match, (
            f"{path.name}: the declared digest and the bytes on disk disagree with "
            f"the expected outcome"
        )
        checked += 1
    assert checked >= 5, "this check must not degrade into a pass over no work"
