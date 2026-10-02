"""TR-RTE: Runtime / TEE platform checks (spec §3.1)."""

from __future__ import annotations

import hmac
import re
from typing import Any

from trace_tests.result import Finding, Status

# Byte-equal to the schema pattern (test_digest_parity) and always applied with
# fullmatch: Python's $ also matches before a trailing newline, ECMA-262's does not.
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")
_VALID_PLATFORMS = frozenset(
    {
        "intel-tdx",
        "amd-sev-snp",
        # Azure confidential VM: SEV-SNP behind a Hyper-V paravisor (vTPM-rooted).
        "azure-cvm-sev-snp",
        "nvidia-h100",
        "nvidia-blackwell",
        "aws-nitro",
        "arm-cca",
        "google-confidential-space",
        "tpm2",
        "software-only",
    }
)
# Platforms that provide no hardware attestation evidence. Valid only at Level 0.
_DEV_PLATFORMS = frozenset({"software-only"})


def check(
    trace: dict[str, Any], level: int = 0, expected_nonce: str | None = None
) -> list[Finding]:
    """Return TR-RTE findings for the runtime / TEE platform claim.

    *level* is the conformance level being checked. Development-mode platforms
    (e.g. ``software-only``) are accepted at Level 0 but rejected at Level 1+
    because they carry no hardware attestation evidence.
    """
    findings: list[Finding] = []
    runtime = trace.get("runtime")

    if not isinstance(runtime, dict):
        return [
            Finding(
                "TR-RTE-001", Status.FAIL, "TR-RTE-001: runtime field is missing or not an object"
            )
        ]

    platform = runtime.get("platform")
    if isinstance(platform, str) and platform in _DEV_PLATFORMS:
        if level == 0:
            findings.append(
                Finding("TR-RTE-001", Status.PASS, f"runtime.platform is registered ({platform!r})")
            )
        else:
            findings.append(
                Finding(
                    "TR-RTE-001",
                    Status.FAIL,
                    f"TR-RTE-001: runtime.platform {platform!r} is development-mode "
                    "and not acceptable for "
                    f"hardware-attested levels (Level {level} requires a hardware TEE platform)",
                )
            )
    elif isinstance(platform, str) and platform in _VALID_PLATFORMS:
        findings.append(
            Finding("TR-RTE-001", Status.PASS, f"runtime.platform is registered ({platform!r})")
        )
    else:
        valid_platforms = sorted(_VALID_PLATFORMS)
        findings.append(
            Finding(
                "TR-RTE-001",
                Status.FAIL,
                f"TR-RTE-001: runtime.platform {platform!r} is not in the "
                f"registered set; valid: {valid_platforms}",
            )
        )

    measurement = runtime.get("measurement", "")
    if _DIGEST_RE.fullmatch(str(measurement)):
        findings.append(
            Finding("TR-RTE-002", Status.PASS, "runtime.measurement has valid digest format")
        )
    else:
        findings.append(
            Finding(
                "TR-RTE-002",
                Status.FAIL,
                "TR-RTE-002: runtime.measurement must match sha256:<64hex> or "
                f"sha384:<96hex>, got {measurement!r}",
            )
        )

    rim_uri = runtime.get("rim_uri")
    if rim_uri is None:
        findings.append(
            Finding("TR-RTE-003", Status.SKIP, "runtime.rim_uri not present (optional)")
        )
    elif isinstance(rim_uri, str) and rim_uri.startswith("https://"):
        findings.append(
            Finding("TR-RTE-003", Status.PASS, f"runtime.rim_uri is an https URI ({rim_uri[:60]})")
        )
    else:
        findings.append(
            Finding(
                "TR-RTE-003",
                Status.FAIL,
                f"TR-RTE-003: runtime.rim_uri must be an https URI, got {rim_uri!r}",
            )
        )

    if level >= 1:
        actual_nonce = runtime.get("nonce")
        if not isinstance(expected_nonce, str) or not expected_nonce:
            findings.append(
                Finding(
                    "TR-RTE-004",
                    Status.FAIL,
                    "TR-RTE-004: Level 1+ verification requires the verifier's expected nonce",
                )
            )
        elif not isinstance(actual_nonce, str) or not actual_nonce:
            findings.append(
                Finding(
                    "TR-RTE-004",
                    Status.FAIL,
                    "TR-RTE-004: runtime.nonce is missing or empty",
                )
            )
        # Compared as bytes: compare_digest raises TypeError on a str that is not
        # ASCII, and the record's nonce is attacker-controlled. surrogatepass so a
        # lone surrogate, which json.loads accepts, still encodes.
        elif hmac.compare_digest(
            actual_nonce.encode("utf-8", "surrogatepass"),
            expected_nonce.encode("utf-8", "surrogatepass"),
        ):
            findings.append(
                Finding("TR-RTE-004", Status.PASS, "runtime.nonce matches the verifier challenge")
            )
        else:
            findings.append(
                Finding(
                    "TR-RTE-004",
                    Status.FAIL,
                    "TR-RTE-004: runtime.nonce does not match the verifier challenge",
                )
            )

    return findings
