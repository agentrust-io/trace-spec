"""Software TPM2 quote capture and independent offline replay.

Requires actual swtpm and tpm2-tools executables for the capture step.
Attestation status is always SIMULATED_TPM, NEVER hardware backed.
Use a separately supplied trust-root SHA256 and manifest SHA256.
No ambient socket/network access is needed for verify().
"""

import base64
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _bin(value):
    return base64.b64decode(value, validate=True)


def _run(args, *, env=None):
    r = subprocess.run(args, capture_output=True, text=True, timeout=30, env=env)
    if r.returncode != 0:
        raise ValueError(
            "tpm-tool-rejected:" + Path(args[0]).name + ":" + r.stderr[-320:]
        )
    return r.stdout


def expected_pcr(event_digests):
    pcr = bytes(32)
    for event in event_digests:
        if not isinstance(event, str) or re.fullmatch(r"[0-9a-f]{64}", event) is None:
            raise ValueError("invalid-event-digest")
        pcr = hashlib.sha256(pcr + bytes.fromhex(event)).digest()
    return pcr.hex()


def capture(*, tool_dir, tcti, event_digests, nonce_hex, directory):
    """Talk to an existing *software* TPM; never provision system services."""
    if re.fullmatch(r"[0-9a-f]{16,128}", nonce_hex or "") is None:
        raise ValueError("nonce must be explicit 8..64 byte hex")
    if not event_digests:
        raise ValueError("at least one measured event is required")
    import os

    env = {**os.environ, "TPM2TOOLS_TCTI": tcti}
    tool_dir = Path(tool_dir)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    def cmd(name, *args):
        return _run([str(tool_dir / name), *map(str, args)], env=env)

    cmd("tpm2_flushcontext", "-t")
    cmd("tpm2_createek", "-c", directory / "ek.ctx", "-G", "rsa", "-Q")
    cmd("tpm2_flushcontext", "-t")
    cmd(
        "tpm2_createak",
        "-C",
        directory / "ek.ctx",
        "-c",
        directory / "ak.ctx",
        "-u",
        directory / "ak.pub",
        "-n",
        directory / "ak.name",
        "-G",
        "rsa",
        "-g",
        "sha256",
        "-s",
        "rsassa",
        "-Q",
    )
    cmd("tpm2_flushcontext", "-t")
    for event in event_digests:
        if re.fullmatch(r"[0-9a-f]{64}", event) is None:
            raise ValueError("invalid-event-digest")
        cmd("tpm2_pcrextend", "0:sha256=" + event)
    cmd(
        "tpm2_quote",
        "-c",
        directory / "ak.ctx",
        "-l",
        "sha256:0,1,7",
        "-q",
        nonce_hex,
        "-m",
        directory / "quote.msg",
        "-s",
        directory / "quote.sig",
        "-o",
        directory / "quote.pcr",
        "-g",
        "sha256",
        "-Q",
    )
    cmd("tpm2_flushcontext", "-t")
    cmd(
        "tpm2_readpublic",
        "-c",
        directory / "ak.ctx",
        "-f",
        "pem",
        "-o",
        directory / "ak.pem",
        "-Q",
    )
    payload = {
        "profile": "frequency-swtpm-quote-v1",
        "classification": "SIMULATED_TPM",
        "nonce_hex": nonce_hex,
        "selection": "sha256:0,1,7",
        "event_digests": event_digests,
        "ak_pem": (directory / "ak.pem").read_text(),
        "quote_msg_b64": base64.b64encode(
            (directory / "quote.msg").read_bytes()
        ).decode(),
        "quote_sig_b64": base64.b64encode(
            (directory / "quote.sig").read_bytes()
        ).decode(),
        "quote_pcr_b64": base64.b64encode(
            (directory / "quote.pcr").read_bytes()
        ).decode(),
    }
    return payload


def verify(
    payload,
    *,
    expected_manifest_digest,
    expected_ak_digest,
    expected_nonce,
    expected_pcr0,
    tpm2_checkquote,
):
    """Verify a captured software TPM quote, freshness challenge and replay."""
    try:
        if (
            not isinstance(payload, dict)
            or payload.get("profile") != "frequency-swtpm-quote-v1"
            or payload.get("classification") != "SIMULATED_TPM"
        ):
            return {"status": "rejected", "reason": "not-simulated-tpm"}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        if (
            not isinstance(expected_manifest_digest, str)
            or sha(encoded) != expected_manifest_digest
        ):
            return {
                "status": "not-established",
                "reason": "external-manifest-pin-mismatch",
            }
        pem = payload["ak_pem"].encode()
        if sha(pem) != expected_ak_digest:
            return {"status": "rejected", "reason": "ak-root-substitution"}
        if payload["nonce_hex"] != expected_nonce:
            return {"status": "rejected", "reason": "challenge-context-mismatch"}
        observed = expected_pcr(payload["event_digests"])
        if observed != expected_pcr0:
            return {"status": "rejected", "reason": "event-log-or-reference-drift"}
        with tempfile.TemporaryDirectory(prefix="trace-swtpm-verify-") as tmp:
            root = Path(tmp)
            for filename, value in (
                ("ak.pem", pem),
                ("quote.msg", _bin(payload["quote_msg_b64"])),
                ("quote.sig", _bin(payload["quote_sig_b64"])),
                ("quote.pcr", _bin(payload["quote_pcr_b64"])),
            ):
                (root / filename).write_bytes(value)
            output = _run(
                [
                    str(tpm2_checkquote),
                    "-u",
                    str(root / "ak.pem"),
                    "-m",
                    str(root / "quote.msg"),
                    "-s",
                    str(root / "quote.sig"),
                    "-f",
                    str(root / "quote.pcr"),
                    "-g",
                    "sha256",
                    "-q",
                    expected_nonce,
                ]
            )
            found = {
                int(n): v.lower()
                for n, v in re.findall(
                    r"^\s*([017])\s*:\s*0x([0-9a-fA-F]{64})\s*$", output, re.M
                )
            }
            if found.get(0) != observed:
                return {"status": "rejected", "reason": "quote-pcr0-mismatch"}
            if found.get(1) != "0" * 64 or found.get(7) != "0" * 64:
                return {
                    "status": "not-established",
                    "reason": "unretained-pcr-event-log",
                }
        return {
            "status": "verified-simulation-only",
            "reason": "tpm2-signed-quote-and-pcr-replay",
            "ak_digest": expected_ak_digest,
            "pcr0": observed,
        }
    except Exception as exc:
        return {
            "status": "rejected",
            "reason": "tpm-evidence-invalid:" + type(exc).__name__,
        }
