import base64
import json
import pathlib
import subprocess
import sys
import textwrap
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VECTORS_DIR = pathlib.Path(__file__).parent / "vectors"
SCHEMAS_DIR = pathlib.Path(__file__).parent.parent / "schemas"


def load_vector(filename):
    return json.loads((VECTORS_DIR / filename).read_text())


@pytest.fixture(name="load_vector")
def load_vector_fixture():
    return load_vector


def load_schema():
    return json.loads((SCHEMAS_DIR / "trace-claim.json").read_text())


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _canonical_json(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _build_signed_cmcp_record(
    *, platform: str = "tpm2", nonce: str | None = None
) -> tuple[dict, Ed25519PrivateKey]:
    """Return (record, private_key) for a fully-signed cmcp-runtime claim.

    The signature covers the canonical JSON of the envelope with the 'signature'
    field absent, matching the verification path in tr_sig.check_cmcp_runtime.
    """
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes_raw()
    x = _b64url(pub_raw)
    kid = f"test-{pub_raw[:4].hex()}"

    iat = int(time.time()) - 30  # fresh but not future-dated

    trace: dict = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": iat,
        "subject": "spiffe://cmcp.gateway/session/conformance-test",
        "runtime": {
            "platform": platform,
            "measurement": "sha256:" + "a" * 64,
        },
        "policy": {
            "bundle_hash": "sha256:" + "b" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "internal",
        "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}},
        "appraisal": {"status": "affirming", "verifier": "https://verifier.example.org"},
    }

    if nonce is not None:
        trace["runtime"]["nonce"] = nonce

    record: dict = {
        "cmcp_version": "1.0",
        "trace": trace,
        "gateway": {"session_id": "conformance-test"},
        "signature": "",
    }

    body = _canonical_json({k: v for k, v in record.items() if k != "signature"})
    record["signature"] = _b64url(priv.sign(body))
    return record, priv


@pytest.fixture
def schema():
    return load_schema()


@pytest.fixture
def valid_level0():
    return load_vector("valid_level0.json")


@pytest.fixture
def valid_level0_with_transcript():
    return load_vector("valid_level0_with_transcript.json")


@pytest.fixture
def invalid_missing_runtime():
    return load_vector("invalid_missing_runtime.json")


@pytest.fixture
def signed_root():
    """A signed Trust Record with no delegation block, from trace-spec's
    `examples/delegation-link/01-valid-single-hop.json`."""
    return load_vector("signed_root.json")


@pytest.fixture
def signed_delegated_hop():
    """The delegated hop from the same chain: signed, and carrying a
    `delegation` block."""
    return load_vector("signed_delegated_hop.json")


@pytest.fixture
def invalid_wrong_profile():
    return load_vector("invalid_wrong_profile.json")


# ---------------------------------------------------------------------------
# Level 1 fixtures
# ---------------------------------------------------------------------------

_CHALLENGE_NONCE = _b64url(b"level1-conformance-nonce-01")


@pytest.fixture
def challenge_nonce() -> str:
    """A stable base64url nonce that the signed EAT fixture embeds in runtime.nonce."""
    return _CHALLENGE_NONCE


@pytest.fixture
def signed_eat_fixture() -> dict:
    """A valid, fully-signed cmcp-runtime envelope for Level 1 conformance tests."""
    record, _ = _build_signed_cmcp_record(platform="tpm2", nonce=_CHALLENGE_NONCE)
    return record


# ---------------------------------------------------------------------------
# Level 2 fixtures
# ---------------------------------------------------------------------------

# Measurement value used consistently across Level 2 fixtures.
_SW_MEASUREMENT = "sha256:" + "c" * 64


def _build_software_only_record() -> dict:
    """Build a signed cmcp-runtime record with platform='software-only' and a fixed measurement."""
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    x = _b64url(pub_raw)
    kid = f"test-{pub_raw[:4].hex()}"
    iat = int(time.time()) - 30

    record: dict = {
        "cmcp_version": "1.0",
        "trace": {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": iat,
            "subject": "spiffe://cmcp.gateway/session/level2-test",
            "runtime": {
                "platform": "software-only",
                "measurement": _SW_MEASUREMENT,
            },
            "policy": {
                "bundle_hash": "sha256:" + "b" * 64,
                "enforcement_mode": "enforce",
            },
            "data_class": "internal",
            "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}},
            "appraisal": {"status": "affirming", "verifier": "https://verifier.example.org"},
        },
        "gateway": {"session_id": "level2-test"},
        "signature": "",
    }
    body = _canonical_json({k: v for k, v in record.items() if k != "signature"})
    record["signature"] = _b64url(priv.sign(body))
    return record


@pytest.fixture
def trust_record() -> dict:
    """A software-only cmcp-runtime record for Level 2 fixture coverage.

    'software-only' is the development platform that carries no hardware TEE
    evidence. It is deliberately distinct from real attestation platforms so a
    consumer can never mistake it for hardware-backed evidence.
    """
    return _build_software_only_record()


@pytest.fixture
def attestation_report(trust_record: dict) -> dict:
    """A synthetic attestation report whose measurement matches trust_record.

    For software-only records there is no real TEE report; this fixture captures
    the structure that a hardware verifier would produce so Level 2 tests can
    exercise field-matching logic without real attestation hardware.
    """
    return {
        "platform": trust_record["trace"]["runtime"]["platform"],
        "measurement": trust_record["trace"]["runtime"]["measurement"],
        "freshness_nonce": _b64url(b"level2-freshness-nonce"),
        "timestamp": trust_record["trace"]["iat"],
        "cnf_key_x": trust_record["trace"]["cnf"]["jwk"]["x"],
    }


# --- environment guard ---
#: Packages this suite is meant to exercise from source.
_PACKAGES_UNDER_TEST = ("trace_tests",)

#: Repository root, resolved from this file.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

_PROBE = textwrap.dedent(
    """
    import importlib, sys
    try:
        m = importlib.import_module(sys.argv[1])
    except Exception:
        print("")
    else:
        print(getattr(m, "__file__", "") or "")
    """
)


def _subprocess_origin(package: str) -> pathlib.Path | None:
    """Where a fresh interpreter finds ``package``, or None if it cannot."""
    try:
        done = subprocess.run(
            [sys.executable, "-c", _PROBE, package],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,  # a non-zero exit just means "cannot import", handled below
        )
    except (OSError, subprocess.SubprocessError):
        return None
    origin = done.stdout.strip()
    return pathlib.Path(origin).resolve() if origin else None


def pytest_configure(config: pytest.Config) -> None:
    for name in _PACKAGES_UNDER_TEST:
        origin = _subprocess_origin(name)
        if origin is None:
            continue  # not importable from a subprocess; nothing can shadow
        if _REPO_ROOT not in origin.parents:
            raise pytest.UsageError(
                f"{name} resolves to {origin} in a subprocess, outside "
                f"{_REPO_ROOT}. Any test that shells out would exercise that "
                "installed distribution instead of this working tree. Install "
                f"editable (pip install -e .) or uninstall the shadowing {name}."
            )
