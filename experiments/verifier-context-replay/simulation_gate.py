"""Reproducible, privilege-free software TPM + isolated process acceptance gate.

Commands:
  python simulation_gate.py create --repo REPO --tools-dir USERLAND_TPM2_BIN
        --swtpm USERLAND_SWTPM --output BUNDLE --host HOST
  python simulation_gate.py verify --bundle BUNDLE --pin SHA256
        --checkquote USERLAND_TPM2_CHECKQUOTE

Only synthetic evidence is used. Attestation roots and keys are development
roots; output MUST NOT be represented as genuine TPM/TEE hardware attestation.
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentrust_trace.sign import sign_record, key_to_jwk

from simulated_tpm import capture as tpm_capture, expected_pcr, sha as raw_sha
from simulated_tee import capture_software_tee
from retained_evidence import freeze
from replay_bundle import run as replay
from enrolled_gate import verify_enrolled
from software_tee_workload import output_bytes as expected_workload_output


def _json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run(command):
    r = subprocess.run(command, capture_output=True, text=True, timeout=20, check=True)
    return r.stdout.strip()


def create(*, repo, tool_dir, swtpm, output, host_label):
    repo = Path(repo).resolve(strict=True)
    tool_dir = Path(tool_dir).resolve(strict=True)
    swtpm = Path(swtpm).resolve(strict=True)
    output = Path(output)
    if output.exists():
        raise FileExistsError("output bundle must not already exist")
    if not isinstance(host_label, str) or not host_label:
        raise ValueError("nonblank host label required")
    commit = _run(["git", "-C", str(repo), "rev-parse", "HEAD"])
    if _run(
        ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=normal"]
    ):
        raise ValueError("refusing dirty source checkout")
    output.mkdir(mode=0o700, parents=True)
    nonce_hex = os.urandom(24).hex()
    challenge = uuid.uuid4().hex
    python_runtime = Path("/usr/bin/python3").resolve(strict=True)
    workload = Path(__file__).resolve().with_name("software_tee_workload.py")
    tpm_source = Path(__file__).resolve().with_name("simulated_tpm.py")
    # Model the measured execution closure, not an unrelated no-op program.
    events = [
        raw_sha(commit.encode()),
        raw_sha(python_runtime.read_bytes()),
        raw_sha(workload.read_bytes()),
        raw_sha(tpm_source.read_bytes()),
    ]
    now = int(time.time())
    with tempfile.TemporaryDirectory(prefix="trace-tpm-state-") as scratch:
        state = Path(scratch)
        (state / "tpm-state").mkdir(mode=0o700)
        (state / "work").mkdir(mode=0o700)
        port = _available_port()
        # TSS swtpm TCTI assumes the control socket is data port + 1.
        if port >= 65534:
            raise RuntimeError("invalid emulator port")
        ctrl = port + 1
        env = {**os.environ}
        swtpm.parents[2] / "lib" / "x86_64-linux-gnu"
        # Rootless package installation stores binaries in .../usr/bin and
        # libraries in .../usr/lib; a system installation needs no override.
        if "trace-tpm-lab" in str(swtpm):
            base = swtpm.parent.parent
            paths = [
                base / "lib" / "x86_64-linux-gnu" / "swtpm",
                base / "lib" / "x86_64-linux-gnu",
            ]
            env["LD_LIBRARY_PATH"] = ":".join(map(str, paths))
        process = subprocess.run(
            [
                str(swtpm),
                "socket",
                "--tpm2",
                "--tpmstate",
                "dir=" + str(state / "tpm-state"),
                "--server",
                f"type=tcp,port={port},bindaddr=127.0.0.1",
                "--ctrl",
                f"type=tcp,port={ctrl},bindaddr=127.0.0.1",
                "--pid",
                "file=" + str(state / "swtpm.pid"),
                "--flags",
                "not-need-init,startup-clear",
                "--daemon",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        if process.returncode != 0:
            raise RuntimeError(
                "failed to start rootless swtpm: " + process.stderr[-400:]
            )
        try:
            tpm = tpm_capture(
                tool_dir=tool_dir,
                tcti=f"swtpm:host=127.0.0.1,port={port}",
                event_digests=events,
                nonce_hex=nonce_hex,
                directory=state / "work",
            )
        finally:
            pidfile = state / "swtpm.pid"
            if pidfile.exists():
                try:
                    pid = int(pidfile.read_text().strip())
                    if pid > 1:
                        os.kill(pid, signal.SIGTERM)
                except (ValueError, ProcessLookupError, PermissionError):
                    pass
    tee_key = Ed25519PrivateKey.generate()
    command = [str(python_runtime), "-I", str(workload), commit, challenge]
    tee = capture_software_tee(
        argv=command,
        repository=repo,
        expected_commit=commit,
        signing_key=tee_key,
        host_label=host_label,
        challenge=challenge,
    )
    tee_public = tee_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trace_key = Ed25519PrivateKey.generate()
    policy_bytes = _json(
        {
            "policy_version": 1,
            "enforcement_mode": "enforce",
            "profile": "simulation-only",
        }
    )
    resolver_bytes = _json({"source": "local-software-simulation", "authority": "none"})
    commit_digest = raw_sha(commit.encode())
    record = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": now,
        "subject": "spiffe://frequency.example/lab/simulated-workload",
        "model": {"provider": "simulation-only", "model_id": "no-model-executed"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + commit_digest,
        },
        "policy": {
            "bundle_hash": "sha256:" + raw_sha(policy_bytes),
            "enforcement_mode": "enforce",
        },
        "data_class": "internal",
        "build_provenance": {"slsa_level": 0, "digest": "sha256:" + commit_digest},
        "appraisal": {
            "status": "none",
            "verifier": "https://frequency.example/simulation",
        },
    }
    signed = sign_record(record, trace_key)
    tpm_policy = {
        "expected_manifest_digest": raw_sha(_json(tpm)),
        "expected_ak_digest": raw_sha(tpm["ak_pem"].encode()),
        "expected_nonce": nonce_hex,
        "expected_pcr0": expected_pcr(events),
    }
    tee_policy = {
        "trusted_observer_public_hex": tee_public.hex(),
        "trusted_observer_digest": raw_sha(tee_public),
        "expected_commit": commit,
        "expected_executable_digest": raw_sha(python_runtime.read_bytes()),
        "expected_host": host_label,
        "expected_command": command,
        "expected_workload_digest": raw_sha(workload.read_bytes()),
        "expected_tpm_source_digest": raw_sha(tpm_source.read_bytes()),
        "expected_stdout_digest": raw_sha(expected_workload_output(commit, challenge)),
        "expected_stderr_digest": raw_sha(b""),
        "expected_challenge": challenge,
        "verification_time": int(time.time()),
        "max_age_seconds": 120,
    }
    context = {
        "verification_time": now,
        "max_age_seconds": 120,
        "max_future_skew_seconds": 10,
        "expected_nonce": None,
        "verifier_version": "simulated-mixed-attestation-v1",
        "semantic_contract": {
            "version": 1,
            "enforcement_mode": "enforce",
            "policy": json.loads(policy_bytes),
            "resolver": json.loads(resolver_bytes),
        },
        "simulation_contract": {"tpm": tpm_policy, "tee": tee_policy},
    }
    freeze(
        output,
        record=_json(signed),
        root=_json(key_to_jwk(trace_key)),
        policy=policy_bytes,
        revocation=b"[]",
        resolver=resolver_bytes,
        context=context,
        simulation_tpm=_json(tpm),
        simulation_tee=_json(tee),
    )
    pin = "sha256:" + raw_sha((output / "MANIFEST.json").read_bytes())
    verdict = replay(output, pin, tpm2_checkquote=tool_dir / "tpm2_checkquote")
    return {
        "commit": commit,
        "bundle": str(output),
        "manifest_digest": pin,
        "status": verdict["status"],
        "reason": verdict.get("reason"),
        "simulation": verdict.get("simulation"),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest="action", required=True)
    a = subs.add_parser("create")
    for flag in ("repo", "tools-dir", "swtpm", "output", "host"):
        a.add_argument("--" + flag, required=True)
    b = subs.add_parser("verify")
    for flag in ("bundle", "pin", "checkquote"):
        b.add_argument("--" + flag, required=True)
    c=subs.add_parser("verify-enrolled")
    for flag in ("bundle","pin","checkquote","registry","registry-pin"):
        c.add_argument("--"+flag,required=True)
    c.add_argument("--verification-time",type=int,required=True)
    args = p.parse_args()
    if args.action == "create":
        result = create(
            repo=args.repo,
            tool_dir=args.tools_dir,
            swtpm=args.swtpm,
            output=args.output,
            host_label=args.host,
        )
    elif args.action=="verify-enrolled":
        result=verify_enrolled(args.bundle,args.pin,registry_path=args.registry,
                               registry_pin=args.registry_pin,
                               checkquote=args.checkquote,
                               verification_time=args.verification_time)
    else:
        result = replay(args.bundle, args.pin, tpm2_checkquote=args.checkquote)
    print(json.dumps(result, sort_keys=True))
    status = result.get("status")
    if status not in ("simulated-evidence-validated","simulation-enrolled-verified"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
