"""Release-facing security policy invariants."""

from pathlib import Path


POLICY = (Path(__file__).parent.parent / "SECURITY.md").read_text(encoding="utf-8")


def test_current_trace_profile_is_supported() -> None:
    assert "TRACE v0.2 / `agentrust-trace` 0.x | Yes" in POLICY


def test_superseded_profile_is_not_supported() -> None:
    assert "TRACE v0.1 and earlier drafts | No" in POLICY
    assert "v0.1 (current)" not in POLICY


def test_private_reporting_channel_is_published() -> None:
    assert "trace-spec/security/advisories/new" in POLICY
    assert "Do not open a public GitHub issue" in POLICY


def test_reference_library_is_explicitly_in_scope() -> None:
    assert "Python reference library" in POLICY
    assert "signing or verification APIs" in POLICY
