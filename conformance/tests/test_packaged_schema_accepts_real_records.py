"""The packaged schema against records that carry the fields real records carry.

The packaged copy sat at `$id` `trace-v0.1.json` while the normative schema moved
to v0.2, and the two diverged on two top-level properties: `signature` and
`delegation`. With `additionalProperties: false` (which
`test_unknown_fields_rejected` shows is deliberate), the packaged copy therefore
rejected **every signed record**, which is every real one, and every delegated
record twice over.

Nothing here failed, because not one of the six vectors this suite carried had a
`signature` at all. The schema forbade a field the corpus never used.

That is the same shape as the canonicalization defect in `tr_sig`: the corpus
avoided the case the defect lived in, so the suite stayed green while the thing it
scores was wrong. Two of these in one repository is a pattern rather than an
accident, and the answer to both is a vector that uses the field.

The two vectors are copied from trace-spec's `examples/delegation-link/`, which is
generated from a published seed and reproducible by anyone. Nothing here compares
them to the originals: a guard that needs another repository checked out is a
guard that gets skipped. They are held instead to the property that makes them
worth having: they carry the fields whose absence hid the defect. A vector edited
into something unsigned stops being a regression test loudly rather than quietly.
"""

from __future__ import annotations

import copy
import pathlib

import jsonschema
import pytest

CONFORMANCE_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGED_SCHEMA_PATH = CONFORMANCE_ROOT / "schemas" / "trace-claim.json"
NORMATIVE_SCHEMA_PATH = CONFORMANCE_ROOT.parent / "schema" / "trace-claim.json"


@pytest.mark.level0
class TestPackagedSchemaAcceptsRealRecords:
    def test_the_vectors_still_carry_the_fields_that_matter(
        self, signed_root, signed_delegated_hop
    ):
        """Half of what makes these regression material. Without it, both records
        could be edited down to the shape the old schema accepted and the two
        tests below would keep passing against a schema that had drifted back."""
        assert "signature" in signed_root, "signed_root lost its signature"
        assert "delegation" not in signed_root, "signed_root is no longer the root case"
        assert "signature" in signed_delegated_hop, "the hop lost its signature"
        assert "delegation" in signed_delegated_hop, "the hop lost its delegation block"

    def test_a_signed_record_validates(self, schema, signed_root):
        """Rejected by the packaged schema before the resync: `'signature' was
        unexpected`."""
        jsonschema.validate(signed_root, schema)

    def test_a_signed_delegated_record_validates(self, schema, signed_delegated_hop):
        """Rejected twice before the resync: `'delegation', 'signature' were
        unexpected`."""
        jsonschema.validate(signed_delegated_hop, schema)

    def test_the_packaged_schema_declares_the_version_it_is(self, schema):
        """The drift was visible in one line the whole time. `$id` named v0.1
        while every record the suite scores declares the v0.2 profile."""
        assert schema["$id"].endswith("trace-v0.2.json"), (
            f"packaged schema declares {schema['$id']}, which is not the version "
            "the records it validates say they are"
        )

    def test_packaged_schema_is_byte_identical_to_normative_schema(self):
        """In the consolidated repository, `conformance/schemas/trace-claim.json`
        must be byte-identical to `schema/trace-claim.json` (#515)."""
        if not NORMATIVE_SCHEMA_PATH.is_file():
            pytest.skip("standalone checkout without ../schema/trace-claim.json")
        assert PACKAGED_SCHEMA_PATH.read_bytes() == NORMATIVE_SCHEMA_PATH.read_bytes(), (
            "conformance/schemas/trace-claim.json has drifted from schema/trace-claim.json"
        )

    def test_v02_record_with_references_reproducibility_and_appraisal_extensions_validates(
        self, schema, signed_root
    ):
        """Records carrying sections 3.1.2, 3.1.4, and 3.1.5 fields must validate (#515)."""
        record = copy.deepcopy(signed_root)
        record["references"] = [
            {
                "rel": "behavior-trace",
                "id": "run-1",
                "resolver": "https://agt.example.org",
                "digest": "sha256:" + "f" * 64,
                "retention": "P30D",
            }
        ]
        record["reproducibility"] = {
            "function": "coordination/v1",
            "code_identity": "sha256:" + "1" * 64,
            "code_resolver": "https://artifacts.example.org",
            "input_closure": [
                {
                    "id": "config/initial",
                    "digest": "sha256:" + "2" * 64,
                    "resolver": "https://artifacts.example.org",
                }
            ],
            "transcript_digest": "sha256:" + "3" * 64,
        }
        record["appraisal"] = {
            "status": "contraindicated",
            "verifier": "https://verifier.example/v1",
            "method": "re-execution",
            "re_execution": {
                "outcome": "diverged",
                "observed_digest": "sha256:" + "4" * 64,
                "verifier_code_identity": "sha256:" + "5" * 64,
            },
            "platform_measurement": {
                "measurement": record["runtime"]["measurement"],
                "layers": {
                    "pcr:0": {"outcome": "established"},
                    "pcr:2": {
                        "outcome": "not-established",
                        "reason": "layer-not-measured",
                    },
                },
            },
        }
        jsonschema.validate(record, schema)

    def test_cnf_jwk_accepts_canonicalizable_extensions_and_rejects_non_canonicalizable_numbers(
        self, schema, signed_root
    ):
        """cnf.jwk uses $defs/canonicalizableValue (#448 item 2): RFC 7517 extension
        members with canonicalizable values validate, while floats and unsafe integers
        are rejected."""
        valid_ext = copy.deepcopy(signed_root)
        valid_ext["cnf"]["jwk"]["use"] = "sig"
        valid_ext["cnf"]["jwk"]["key_ops"] = ["verify"]
        jsonschema.validate(valid_ext, schema)

        for bad_number in (1e21, 1.5, 9007199254740992):
            invalid_ext = copy.deepcopy(signed_root)
            invalid_ext["cnf"]["jwk"]["ext"] = bad_number
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(invalid_ext, schema)

    @pytest.mark.parametrize(
        ("mutator", "reason"),
        [
            (
                lambda r: r.__setitem__("subject", "spiffe://bernstein.run"),
                "SPIFFE prefix without workload path",
            ),
            (
                lambda r: r.__setitem__("iat", 9007199254740992),
                "iat above IEEE 754 MAX_SAFE_INTEGER",
            ),
            (
                lambda r: r.__setitem__("signature", "A" * 85 + "B"),
                "non-canonical 86-char base64url signature",
            ),
            (
                lambda r: r["cnf"].__setitem__("jwk", {"kty": "RSA"}),
                "RSA cnf.jwk missing required n and e members",
            ),
        ],
    )
    def test_packaged_schema_rejects_records_forbidden_by_normative_schema(
        self, schema, signed_root, mutator, reason
    ):
        record = copy.deepcopy(signed_root)
        mutator(record)
        with pytest.raises(jsonschema.ValidationError, match="."):
            jsonschema.validate(record, schema)

