"""Regenerate only the experimental verifier-token schemas."""

import json
from pathlib import Path

from prototype import verifier_token as v

ROOT = Path(__file__).resolve().parents[1]
for name, model in [
    ("token", v.Token),
    ("requirements", v.Requirements),
    ("holder-proof", v.Proof),
    ("decision-receipt", v.Receipt),
]:
    target = ROOT / "schema" / ("trace-" + name + "-experimental-v1.json")
    target.write_bytes((json.dumps(model.model_json_schema(), indent=2) + "\n").encode())
