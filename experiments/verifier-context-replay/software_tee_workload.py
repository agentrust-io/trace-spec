"""Deterministic code/nonce measurement inside a network-isolated software sandbox.

No model, runtime network, secret key, or hardware enclave is involved.
The output is data to be captured by an independently controlled observer.
"""
import hashlib
import json
import sys
from pathlib import Path


def measured_output(commit, challenge):
    if len(commit) != 40 or any(ch not in "0123456789abcdef" for ch in commit):
        raise ValueError("commit must be a full lowercase hexadecimal SHA-1")
    if len(challenge) < 16:
        raise ValueError("nonce too short")
    pinned_source = Path(__file__).resolve().with_name("simulated_tpm.py")
    source_hash = hashlib.sha256(pinned_source.read_bytes()).hexdigest()
    proof = hashlib.sha256((commit + ":" + challenge + ":" + source_hash).encode()).hexdigest()
    return {
        "challenge": challenge,
        "commit": commit,
        "measurement": "sha256:" + source_hash,
        "proof": "sha256:" + proof,
    }


def output_bytes(commit, challenge):
    return (json.dumps(measured_output(commit, challenge), sort_keys=True,
                       separators=(",", ":")) + "\n").encode()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("requires explicit commit and challenge")
    sys.stdout.buffer.write(output_bytes(sys.argv[1], sys.argv[2]))
