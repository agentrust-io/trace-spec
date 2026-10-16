import pytest, jsonschema


@pytest.mark.level0
class TestSchemaValidation:
    def test_valid_minimal_record_passes(self, schema, valid_level0):
        jsonschema.validate(valid_level0, schema)

    def test_valid_record_with_transcript_passes(self, schema, valid_level0_with_transcript):
        jsonschema.validate(valid_level0_with_transcript, schema)

    @pytest.mark.negative
    def test_missing_runtime_rejected(self, schema, invalid_missing_runtime):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid_missing_runtime, schema)

    @pytest.mark.negative
    def test_wrong_eat_profile_rejected(self, schema, invalid_wrong_profile):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid_wrong_profile, schema)

    @pytest.mark.negative
    def test_empty_object_rejected(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({}, schema)

    @pytest.mark.negative
    def test_unknown_fields_rejected(self, schema, valid_level0):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({**valid_level0, "unexpected_field": "x"}, schema)
