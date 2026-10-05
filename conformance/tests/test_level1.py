"""Level 1 conformance tests: signed EAT envelope with Ed25519 verification.

A Level 1 record must be a cmcp-runtime envelope carrying a valid Ed25519
signature by the key in trace.cnf.jwk over the canonical JSON body. The runner
module (TR-SIG) is the authoritative implementation; these tests drive it through
representative conformant and non-conformant fixtures to verify it behaves correctly.
"""

import base64
import json

import pytest

from trace_tests.modules.tr_sig import check as tr_sig_check
from trace_tests.result import Status


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _canonical_json(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@pytest.mark.level1
class TestLevel1Conformance:
    def test_eat_is_cose_sign1(self, signed_eat_fixture):
        """The envelope must have cmcp_version and a non-empty signature field.

        In the TRACE cMCP profile the cmcp-runtime envelope is the signed EAT
        carrier. A present, non-empty 'signature' field is the indicator that
        the record was signed rather than merely assembled.
        """
        assert "cmcp_version" in signed_eat_fixture, (
            "Level 1 record must be a cmcp-runtime envelope (cmcp_version key required)"
        )
        sig = signed_eat_fixture.get("signature", "")
        assert isinstance(sig, str) and len(sig) > 0, (
            "Level 1 record must carry a non-empty signature field"
        )
        assert "trace" in signed_eat_fixture and isinstance(signed_eat_fixture["trace"], dict), (
            "Level 1 record must embed a trace object"
        )

    def test_eat_protected_header_content_type(self, signed_eat_fixture):
        """The trace envelope must declare the expected EAT profile sentinel.

        In the cMCP profile the eat_profile field inside trace serves the role
        of the COSE protected header content-type: it binds the record to the
        TRACE v0.2 specification and prevents cross-profile replay.
        """
        trace = signed_eat_fixture["trace"]
        assert trace.get("eat_profile") == "tag:agentrust-io.com,2026:trace-v0.2", (
            "trace.eat_profile must be 'tag:agentrust-io.com,2026:trace-v0.2'"
        )

    def test_signature_verifies_against_cnf_key(self, signed_eat_fixture):
        """TR-SIG must pass for a validly-signed cmcp-runtime record."""
        trace = signed_eat_fixture["trace"]
        findings = tr_sig_check(trace, signed_eat_fixture, "cmcp-runtime")
        failures = [f for f in findings if f.failed()]
        assert not failures, (
            f"Valid signed record must pass TR-SIG at Level 1; failures: {failures}"
        )
        passed = [f for f in findings if f.passed()]
        assert passed, "TR-SIG must emit at least one PASS finding for a valid signature"

    def test_signature_byte_flipped_fails(self, signed_eat_fixture):
        """A record with a tampered signature must fail TR-SIG.

        Flipping a byte in the base64url signature produces an invalid
        Ed25519 signature that cannot verify against the embedded cnf.jwk
        public key.
        """
        import base64

        original = signed_eat_fixture["signature"]
        # Decode, flip the first byte, re-encode without padding.
        raw = base64.urlsafe_b64decode(original + "=" * (4 - len(original) % 4))
        tampered = bytes([raw[0] ^ 0xFF]) + raw[1:]
        signed_eat_fixture["signature"] = base64.urlsafe_b64encode(tampered).rstrip(b"=").decode()

        trace = signed_eat_fixture["trace"]
        findings = tr_sig_check(trace, signed_eat_fixture, "cmcp-runtime")
        assert any(f.failed() and "TR-SIG-001" in f.code for f in findings), (
            "Byte-flipped signature must produce TR-SIG-001 FAIL"
        )

    def test_cnf_jwk_swapped_key_fails(self, signed_eat_fixture):
        """A record whose cnf.jwk has been replaced with a different key must fail TR-SIG.

        The signature was produced by the original private key; verifying it
        against a freshly-generated unrelated public key must fail.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        different_priv = Ed25519PrivateKey.generate()
        different_pub_raw = different_priv.public_key().public_bytes_raw()
        different_x = _b64url(different_pub_raw)

        # Swap x in cnf.jwk while leaving the signature unchanged.
        signed_eat_fixture["trace"]["cnf"]["jwk"]["x"] = different_x

        trace = signed_eat_fixture["trace"]
        findings = tr_sig_check(trace, signed_eat_fixture, "cmcp-runtime")
        assert any(f.failed() for f in findings), (
            "Swapped cnf.jwk public key must cause TR-SIG to fail"
        )

    def test_eat_nonce_matches_challenge(self, signed_eat_fixture, challenge_nonce):
        """The runtime.nonce embedded in the EAT must match the challenge nonce.

        Nonce binding prevents replay: a verifier issues a freshness challenge
        before the agent signs; the resulting EAT must echo that exact nonce.
        """
        trace = signed_eat_fixture["trace"]
        assert trace["runtime"].get("nonce") == challenge_nonce, (
            "trace.runtime.nonce must match the challenge nonce issued by the verifier"
        )
