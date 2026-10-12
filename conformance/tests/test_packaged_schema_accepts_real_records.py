"""The packaged schema against records that carry the fields real records carry.

The packaged copy sat at `$id` `trace-v0.1.json` while the normative schema moved
to v0.2, and the two diverged on two top-level properties: `signature` and
`delegation`. With `additionalProperties: false` — which
`test_unknown_fields_rejected` shows is deliberate — the packaged copy therefore
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
them to the originals — a guard that needs another repository checked out is a
guard that gets skipped. They are held instead to the property that makes them
worth having: they carry the fields whose absence hid the defect. A vector edited
into something unsigned stops being a regression test loudly rather than quietly.
"""

from __future__ import annotations

import jsonschema
import pytest


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
