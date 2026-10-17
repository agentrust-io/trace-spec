"""Retain and revalidate exact replay evidence bytes; fail closed if incomplete."""
import hashlib
import json
import os
import tempfile
from pathlib import Path

REQUIRED = ("record", "trusted_root", "policy", "revocation", "resolver")
MEASUREMENT = ("measurement_reference", "measurement_quote")
SIMULATION = ("simulation_tpm", "simulation_tee")

def _sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _write_exclusive(path, data):
    """Publish complete bytes using an exclusive, atomic rename from a temp file."""
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() or path.is_symlink():
            raise FileExistsError(str(path))
        # Hard-link publication refuses replacement of an existing destination.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)


def freeze(directory, *, record, root, policy, revocation, resolver, context,
           measurement_reference=None, measurement_quote=None,
           simulation_tpm=None, simulation_tee=None):
    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    artifacts = dict(record=record, trusted_root=root, policy=policy,
                     revocation=revocation, resolver=resolver)
    supplied = (measurement_reference is not None, measurement_quote is not None)
    if supplied[0] != supplied[1]:
        raise ValueError("measurement reference and quote must be retained together")
    if supplied[0]:
        artifacts.update(measurement_reference=measurement_reference,
                         measurement_quote=measurement_quote)
    if context.get("simulation_contract") is not None:
        if type(simulation_tpm) is not bytes or type(simulation_tee) is not bytes:
            raise ValueError("simulated TPM and TEE evidence must both be retained")
        artifacts.update(simulation_tpm=simulation_tpm, simulation_tee=simulation_tee)
    elif simulation_tpm is not None or simulation_tee is not None:
        raise ValueError("unbound simulation evidence is not allowed")
    if context.get("measurement_contract") is not None and not supplied[0]:
        raise ValueError("measurement appraisal contract requires retained evidence")
    if not isinstance(context, dict) or type(context.get("verification_time")) is not int:
        raise ValueError("explicit verification time required")
    manifest = {"format": "trace-replay-bundle-v1", "context": context, "artifacts": {}}
    for name, data in artifacts.items():
        if not isinstance(data, bytes):
            raise ValueError("evidence must be retained as bytes: " + name)
        path = destination / (name + ".bin")
        if path.exists():
            raise FileExistsError(str(path))
        _write_exclusive(path, data)
        manifest["artifacts"][name] = {"file": path.name, "length": len(data), "digest": _sha(data)}
    manifest_path = destination / "MANIFEST.json"
    if manifest_path.exists():
        raise FileExistsError(str(manifest_path))
    _write_exclusive(manifest_path, json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
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
        expected = set(REQUIRED) | (set(MEASUREMENT) if context.get("measurement_contract") is not None else set())
        if context.get("simulation_contract") is not None:
            expected |= set(SIMULATION)
        if set(manifest["artifacts"]) != expected:
            return False, "missing-evidence"
        for name in expected:
            entry = manifest["artifacts"][name]
            if entry.get("file") != name + ".bin":
                return False, "path"
            data = (destination / entry["file"]).read_bytes()
            if len(data) != entry["length"] or _sha(data) != entry["digest"]:
                return False, "evidence-tampering:" + name
        return True, "integrity-established-only"
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError):
        return False, "incomplete-or-malformed-bundle"
