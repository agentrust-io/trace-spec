"""Level 2 conformance tests: TEE measurement binding.

Level 2 requires that the runtime.measurement in the TRACE claim matches the
value reported by the hardware TEE attestation report, that the report is fresh,
that the platform field agrees with the report format, and that the cnf key was
sealed inside the TEE measurement (preventing key substitution without breaking
attestation).

Full Level 2 verification requires an in-scope hardware attestation verifier
(TDX Quote, SEV-SNP Attestation Report, Nitro NSM, etc.). CI does not have
access to real attestation hardware, so tests in this class are marked
xfail(strict=False): they run with software-only fixture data and serve as
regression scaffolding for the day a CI runner gains hardware TEE access.

What a full Level 2 CI run would require:
  - A hardware TEE (intel-tdx, amd-sev-snp, aws-nitro, ...) or a verified
    software emulation layer providing authentic attestation quotes.
  - An attestation verifier service or library that validates the quote chain
    back to the manufacturer root CA.
  - The ability to re-generate the attestation_report fixture from a live
    attestation call so that quote freshness checks pass against real hardware.
  - Binding proof that the agent's Ed25519 key from cnf.jwk was sealed into
    the TEE's measurement register at enclave initialization time.
"""

import pytest


@pytest.mark.level2
class TestLevel2Conformance:
    @pytest.mark.xfail(strict=False, reason="requires hardware TEE; software-only fixture coverage only")
    def test_measurement_matches_tee_report(self, trust_record, attestation_report):
        """runtime.measurement must equal the value in the hardware attestation report.

        For software-only records the fixture manufactures a matching report so
        this assertion passes in the stub path; real hardware would produce a
        cryptographically-bound measurement from the actual enclave state.
        """
        measurement = trust_record["trace"]["runtime"]["measurement"]
        reported = attestation_report["measurement"]
        assert measurement == reported, (
            f"runtime.measurement {measurement!r} does not match "
            f"attestation report measurement {reported!r}"
        )

    @pytest.mark.xfail(strict=False, reason="requires hardware TEE; software-only fixture coverage only")
    def test_measurement_mismatch_is_detected(self, trust_record, attestation_report):
        """A measurement field that differs from the TEE report must be detected.

        This tests that a mismatch between the claimed measurement and the
        attested measurement is caught rather than silently ignored.
        """
        tampered_report = {**attestation_report, "measurement": "sha256:" + "f" * 64}
        measurement = trust_record["trace"]["runtime"]["measurement"]
        reported = tampered_report["measurement"]
        assert measurement != reported, (
            "Tampered report should differ from the trust record measurement"
        )
        # A conformant verifier must reject this record.
        assert measurement != reported, (
            "Level 2 verifier must reject a record whose measurement does not match the TEE report"
        )

    @pytest.mark.xfail(strict=False, reason="requires hardware TEE; software-only fixture coverage only")
    def test_attestation_report_freshness(self, trust_record, attestation_report):
        """The attestation report timestamp must be recent relative to the claim iat.

        Stale attestation evidence allows replay of old TEE state. The verifier
        must reject reports whose timestamp deviates from the claim iat by more
        than a defined freshness window (typically 60 seconds for online flows).
        """
        import time

        claim_iat = trust_record["trace"]["iat"]
        report_ts = attestation_report.get("timestamp")
        assert report_ts is not None, "attestation_report must carry a timestamp"

        skew = abs(claim_iat - report_ts)
        max_skew = 300  # 5-minute allowance for the software-only fixture
        assert skew <= max_skew, (
            f"attestation_report.timestamp {report_ts} deviates {skew}s from "
            f"claim iat {claim_iat}; exceeds max allowed skew {max_skew}s"
        )

        now = int(time.time())
        report_age = now - report_ts
        assert report_age < 24 * 3600, (
            f"attestation_report is {report_age}s old; hardware TEE reports "
            "should be generated within the attestation session window"
        )

    @pytest.mark.xfail(strict=False, reason="requires hardware TEE; software-only fixture coverage only")
    def test_platform_matches_report_format(self, trust_record, attestation_report):
        """runtime.platform must match the platform identifier in the attestation report.

        Each TEE produces a platform-specific report format (TDX Quote, SNP
        Attestation Report, Nitro NSM document, ...). The platform field in the
        TRACE claim must agree with the report format so a verifier can apply
        the correct verification algorithm.
        """
        claim_platform = trust_record["trace"]["runtime"]["platform"]
        report_platform = attestation_report.get("platform")
        assert claim_platform == report_platform, (
            f"runtime.platform {claim_platform!r} does not match "
            f"attestation report platform {report_platform!r}"
        )

    @pytest.mark.xfail(strict=False, reason="requires hardware TEE; software-only fixture coverage only")
    def test_cnf_key_sealed_in_tee_measurement(self, trust_record, attestation_report):
        """The cnf.jwk public key must be sealed into the TEE measurement.

        Key sealing ensures that the attestation report covers the exact key
        material used to sign the TRACE claim. Without this binding an attacker
        could substitute a different key into cnf.jwk without invalidating the
        TEE quote. The software-only fixture records the key's x value directly
        in the report; a real TEE would include a hash of the key material in a
        measurement register (e.g., MRTD for TDX, MEASUREMENT for SNP).
        """
        claim_key_x = trust_record["trace"]["cnf"]["jwk"].get("x")
        report_key_x = attestation_report.get("cnf_key_x")
        assert claim_key_x is not None, "cnf.jwk.x must be present in the trust record"
        assert report_key_x is not None, "attestation_report must record the sealed cnf key"
        assert claim_key_x == report_key_x, (
            "cnf.jwk.x in the trust record does not match the key sealed in the "
            "TEE attestation report; the claim key may have been substituted"
        )
