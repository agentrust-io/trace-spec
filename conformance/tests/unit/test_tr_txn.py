"""Unit tests for TR-TXN module.

This module had no unit tests, which is why all four of its failure paths measured
margin 0 in `measurement/`: every one of them could have been deleted without a
single test failing. TR-TXN-001 is the only place the Level 2 tool-transcript
requirement is enforced anywhere in the suite.

Each test below targets one `Finding(..., Status.FAIL, ...)` site, so deleting that
site takes exactly this test with it.
"""

from trace_tests.modules.tr_txn import check

VALID_HASH_256 = "sha256:" + "a" * 64
VALID_HASH_384 = "sha384:" + "b" * 96


def _txn(**over):
    txn = {"hash": VALID_HASH_256}
    txn.update(over)
    return {"tool_transcript": txn}


def test_valid_transcript_passes():
    findings = check(_txn())
    assert all(f.passed() or f.code == "TR-TXN-002" for f in findings), findings


def test_sha384_hash_is_accepted():
    failed = [f for f in check(_txn(hash=VALID_HASH_384)) if f.failed()]
    assert not failed, failed


# --- TR-TXN-001, the Level 2 obligation ------------------------------------


def test_missing_transcript_fails():
    """The Level 2 requirement itself. Nothing else in the suite enforces it."""
    failed = [f for f in check({}) if f.failed()]
    assert any(f.code == "TR-TXN-001" for f in failed)
    assert any("required at Level 2" in f.message for f in failed)


def test_non_object_transcript_fails():
    failed = [f for f in check({"tool_transcript": "sha256:deadbeef"}) if f.failed()]
    assert any(f.code == "TR-TXN-001" for f in failed)
    assert any("must be an object" in f.message for f in failed)


def test_malformed_hash_fails():
    failed = [f for f in check(_txn(hash="deadbeef")) if f.failed()]
    assert any(f.code == "TR-TXN-001" for f in failed)


def test_missing_hash_fails():
    failed = [f for f in check({"tool_transcript": {}}) if f.failed()]
    assert any(f.code == "TR-TXN-001" for f in failed)


def test_truncated_digest_fails():
    """63 hex characters, not 64. A prefix comparison would let this through."""
    failed = [f for f in check(_txn(hash="sha256:" + "a" * 63)) if f.failed()]
    assert any(f.code == "TR-TXN-001" for f in failed)


def test_uppercase_digest_fails():
    """The pattern is lowercase hex; a case-insensitive match would accept this."""
    failed = [f for f in check(_txn(hash="sha256:" + "A" * 64)) if f.failed()]
    assert any(f.code == "TR-TXN-001" for f in failed)


# --- TR-TXN-002, optional but constrained when present ---------------------


def test_absent_call_count_is_skipped_not_failed():
    """Optional means optional: absence must not be reported as a failure."""
    codes = {f.code: f for f in check(_txn())}
    assert "TR-TXN-002" in codes
    assert not codes["TR-TXN-002"].failed()


def test_negative_call_count_fails():
    failed = [f for f in check(_txn(call_count=-1)) if f.failed()]
    assert any(f.code == "TR-TXN-002" for f in failed)


def test_non_integer_call_count_fails():
    failed = [f for f in check(_txn(call_count="3")) if f.failed()]
    assert any(f.code == "TR-TXN-002" for f in failed)


def test_boolean_call_count_fails():
    """bool is an int subclass, so True passes a bare isinstance check and reads
    as a call count of one. Found by writing these guards, fixed with them."""
    failed = [f for f in check(_txn(call_count=True)) if f.failed()]
    assert any(f.code == "TR-TXN-002" for f in failed)


def test_zero_call_count_is_valid():
    """A transcript with no calls is a real outcome, not an error."""
    failed = [f for f in check(_txn(call_count=0)) if f.failed()]
    assert not failed, failed
