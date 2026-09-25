"""Freshness decisions can be replayed at a caller-supplied instant (#407)."""

import pytest

from agentrust_trace import provenance as p
from agentrust_trace.sign import generate_key, key_to_jwk


@pytest.fixture(params=[p.FORMAT, p.FORMAT_V2])
def signed(request):
    key = generate_key()
    record = p.build_record(
        kind="publisher-asserted", publisher="did:web:example.com", tools=[],
        artifact={"package": "pkg:npm/example@1", "digest": "sha256:" + "a" * 64},
        issued_at=1000, format=request.param,
    )
    return p.sign_record(record, key), key_to_jwk(key)


@pytest.mark.parametrize("now,error", [(1300, None), (1301, "stale"),
                                     (700, None), (699, "future")])
def test_exact_freshness_boundaries_ignore_host_clock(signed, monkeypatch, now, error):
    def forbidden_clock():
        raise AssertionError("explicit now must not sample the host clock")
    monkeypatch.setattr(p.time, "time", forbidden_clock)
    if error:
        with pytest.raises(p.ProvenanceError, match=error):
            p.verify_record(*signed, now=now, max_age_seconds=300)
    else:
        p.verify_record(*signed, now=now, max_age_seconds=300)


@pytest.mark.parametrize("bad", [True, False, -1, 1.0, "1000", [], {}, float("nan")])
def test_bad_clock_is_named_as_configuration_error(signed, bad):
    with pytest.raises(p.ProvenanceError, match="now"):
        p.verify_record(*signed, now=bad)


def test_zero_is_an_explicit_instant(signed, monkeypatch):
    monkeypatch.setattr(p.time, "time", lambda: 1000)
    with pytest.raises(p.ProvenanceError, match="future"):
        p.verify_record(*signed, now=0)


@pytest.mark.parametrize("kwargs", [{}, {"now": None}])
def test_default_preserves_fractional_wall_clock_boundary(signed, monkeypatch, kwargs):
    monkeypatch.setattr(p.time, "time", lambda: 1300)
    p.verify_record(*signed, max_age_seconds=300, **kwargs)
    monkeypatch.setattr(p.time, "time", lambda: 1300.5)
    with pytest.raises(p.ProvenanceError, match="stale"):
        p.verify_record(*signed, max_age_seconds=300, **kwargs)


def test_explicit_clock_does_not_skip_signature_or_revocation(signed):
    record, key = signed
    with pytest.raises(p.ProvenanceError, match="signature"):
        p.verify_record({**record, "publisher": "did:web:changed.example"}, key, now=1000)
    with pytest.raises(p.ProvenanceError, match="revoked"):
        p.verify_record(record, key, now=1000, revocation=lambda _: True)
