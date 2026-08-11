"""Fail closed if a built TRACE distribution is incomplete or not self-consistent."""

from __future__ import annotations

import argparse
import inspect
import json
import time
from importlib import metadata
from pathlib import Path

import agentrust_trace
from agentrust_trace import (
    generate_key,
    key_to_jwk,
    sign_record,
    validate_json,
    verify_record,
)
from jsonschema import ValidationError


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()

    imported_from = Path(inspect.getfile(agentrust_trace)).resolve()
    workspace = args.workspace.resolve()
    if imported_from.is_relative_to(workspace):
        raise SystemExit(
            f"artifact check imported checkout source at {imported_from}, "
            "not the installed artifact"
        )

    installed_version = metadata.version("agentrust-trace")
    if installed_version != args.expected_version:
        raise SystemExit(
            f"installed artifact version {installed_version!r} != tag {args.expected_version!r}"
        )
    if agentrust_trace.__version__ != installed_version:
        raise SystemExit(
            f"runtime version {agentrust_trace.__version__!r} != metadata {installed_version!r}"
        )

    example_path = workspace / "examples" / "intel-tdx.json"
    record = json.loads(example_path.read_text(encoding="utf-8"))
    record["iat"] = int(time.time())
    record.pop("signature", None)

    # Exercises packaged schema resources plus the public signing and verification API.
    validate_json(record)
    key = generate_key()
    signed = sign_record(record, key)
    validate_json(signed)
    verify_record(signed, key_to_jwk(key))

    malformed = {**signed, "unexpected_security_semantics": "trusted"}
    try:
        validate_json(malformed)
    except ValidationError:
        pass
    else:
        raise SystemExit("packaged schema accepted an unknown top-level security field")

    print(
        f"verified agentrust-trace {installed_version} from {imported_from} "
        "with packaged schema and signing round trip"
    )


if __name__ == "__main__":
    main()
