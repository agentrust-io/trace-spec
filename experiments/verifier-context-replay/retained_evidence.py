"""Retain and revalidate exact replay evidence bytes; fail closed if incomplete."""
import hashlib
import json
from pathlib import Path

REQUIRED = ("record", "trusted_root", "policy", "revocation", "resolver")

def _sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def freeze(directory, *, record, root, policy, revocation, resolver, context):
    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    artifacts = dict(record=record, trusted_root=root, policy=policy,
                     revocation=revocation, resolver=resolver)
    if not isinstance(context, dict) or type(context.get("verification_time")) is not int:
        raise ValueError("explicit verification time required")
    manifest = {"format": "trace-replay-bundle-v1", "context": context, "artifacts": {}}
    for name, data in artifacts.items():
        if not isinstance(data, bytes):
            raise ValueError("evidence must be retained as bytes: " + name)
        path = destination / (name + ".bin")
        if path.exists():
            raise FileExistsError(str(path))
        path.write_bytes(data)
        manifest["artifacts"][name] = {"file": path.name, "length": len(data), "digest": _sha(data)}
    manifest_path = destination / "MANIFEST.json"
    if manifest_path.exists():
        raise FileExistsError(str(manifest_path))
    manifest_path.write_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    return manifest

def inspect(directory, *, expected_context=None):
    destination = Path(directory)
    try:
        manifest = json.loads((destination / "MANIFEST.json").read_bytes())
        if manifest.get("format") != "trace-replay-bundle-v1":
            return False, "format"
        context = manifest["context"]
        if type(context.get("verification_time")) is not int:
            return False, "implicit-time"
        if expected_context is not None and context != expected_context:
            return False, "context-drift"
        if set(manifest["artifacts"]) != set(REQUIRED):
            return False, "missing-evidence"
        for name in REQUIRED:
            entry = manifest["artifacts"][name]
            if entry.get("file") != name + ".bin":
                return False, "path"
            data = (destination / entry["file"]).read_bytes()
            if len(data) != entry["length"] or _sha(data) != entry["digest"]:
                return False, "evidence-tampering:" + name
        return True, "integrity-established-only"
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError):
        return False, "incomplete-or-malformed-bundle"
