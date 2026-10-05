import re
import pytest
import jsonschema

SUBJECT_RE = re.compile(r"^(spiffe://|did:)")
DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")
# These three restate schema enums. `tests/test_enum_parity.py` fails if any drifts.
VALID_PLATFORMS = {
    "intel-tdx", "amd-sev-snp", "azure-cvm-sev-snp", "nvidia-h100", "nvidia-blackwell",
    "aws-nitro", "arm-cca", "google-confidential-space", "tpm2", "software-only",
}
VALID_ENFORCEMENT = {"enforce", "advisory", "silent", "declared"}
VALID_APPRAISAL = {"affirming", "warning", "contraindicated", "none"}


@pytest.mark.level0
class TestLevel0Conformance:
    def test_schema_valid(self, schema, valid_level0):
        jsonschema.validate(valid_level0, schema)

    def test_eat_profile_sentinel(self, valid_level0):
        assert valid_level0["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2"

    def test_iat_is_positive_integer(self, valid_level0):
        assert isinstance(valid_level0["iat"], int)
        assert valid_level0["iat"] >= 1700000000

    def test_subject_is_valid_workload_identity_uri(self, valid_level0):
        assert SUBJECT_RE.match(valid_level0["subject"])

    def test_runtime_platform_is_registered(self, valid_level0):
        assert valid_level0["runtime"]["platform"] in VALID_PLATFORMS

    def test_runtime_measurement_digest_format(self, valid_level0):
        assert DIGEST_RE.match(valid_level0["runtime"]["measurement"])

    def test_policy_bundle_hash_digest_format(self, valid_level0):
        assert DIGEST_RE.match(valid_level0["policy"]["bundle_hash"])

    def test_policy_enforcement_mode_known(self, valid_level0):
        assert valid_level0["policy"]["enforcement_mode"] in VALID_ENFORCEMENT

    def test_build_provenance_slsa_level_range(self, valid_level0):
        assert valid_level0["build_provenance"]["slsa_level"] in (0,1, 2, 3)

    def test_build_provenance_digest_format(self, valid_level0):
        assert DIGEST_RE.match(valid_level0["build_provenance"]["digest"])

    def test_appraisal_status_known(self, valid_level0):
        assert valid_level0["appraisal"]["status"] in VALID_APPRAISAL

    def test_transparency_is_https_uri(self, valid_level0):
        assert valid_level0["transparency"].startswith("https://")

    def test_cnf_jwk_has_kty(self, valid_level0):
        assert "kty" in valid_level0["cnf"]["jwk"]

    def test_transcript_digest_when_present(self, valid_level0_with_transcript):
        t = valid_level0_with_transcript.get("tool_transcript")
        if t:
            assert DIGEST_RE.match(t["hash"])
