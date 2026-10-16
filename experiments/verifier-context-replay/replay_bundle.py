"""Offline replay execution from externally pinned retained evidence.

The caller MUST supply the expected SHA-256 of MANIFEST.json out of band.
Never trust a self-supplied manifest checksum as an authority.
"""

import hashlib
import json
from pathlib import Path
from retained_evidence import inspect
from independent_verifier import verify as independent_verify
from measurement_appraisal import appraise as appraise_measurement
from simulated_tpm import verify as verify_simulated_tpm
from simulated_tee import verify_software_tee
from agentrust_trace.sign import verify_record
from cryptography.exceptions import InvalidSignature


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def run(directory, expected_manifest_digest, *, tpm2_checkquote=None):
    directory = Path(directory)
    if not isinstance(
        expected_manifest_digest, str
    ) or not expected_manifest_digest.startswith("sha256:"):
        return {"status": "not-established", "reason": "missing-external-manifest-pin"}
    try:
        manifest_bytes = (directory / "MANIFEST.json").read_bytes()
        if sha256(manifest_bytes) != expected_manifest_digest:
            return {"status": "rejected", "reason": "manifest-pin-mismatch"}
        sound, why = inspect(directory)
        if not sound:
            return {"status": "rejected", "reason": why}
        manifest = json.loads(manifest_bytes)
        context = manifest["context"]
        if any(
            field not in context
            for field in (
                "verification_time",
                "max_age_seconds",
                "max_future_skew_seconds",
                "expected_nonce",
            )
        ):
            return {"status": "not-established", "reason": "missing-replay-options"}
        artifacts = {
            name: (directory / (name + ".bin")).read_bytes()
            for name in ("record", "trusted_root", "policy", "revocation", "resolver")
        }
        record = json.loads(artifacts["record"])
        trusted_key = json.loads(artifacts["trusted_root"])
        revoked = json.loads(artifacts["revocation"])
        if not isinstance(revoked, list) or not all(
            isinstance(item, str) for item in revoked
        ):
            return {
                "status": "not-established",
                "reason": "revocation-snapshot-invalid",
            }
        if record.get("policy", {}).get("bundle_hash") != sha256(artifacts["policy"]):
            return {"status": "rejected", "reason": "signed-policy-digest-mismatch"}
        # A complete replay must bind the exact policy and resolver semantics.
        # Older bundles remain testable as crypto/context only; never upgrade
        # them to a semantic acceptance claim.
        contract = context.get("semantic_contract")
        semantic_status = "not-established"
        if contract is not None:
            if not isinstance(contract, dict) or contract.get("version") != 1:
                return {
                    "status": "not-established",
                    "reason": "unsupported-semantic-contract",
                }
            if set(contract) != {"version", "enforcement_mode", "policy", "resolver"}:
                return {
                    "status": "not-established",
                    "reason": "incomplete-semantic-contract",
                }
            policy_semantics = json.loads(artifacts["policy"])
            resolver_semantics = json.loads(artifacts["resolver"])
            if not isinstance(policy_semantics, dict) or not isinstance(
                resolver_semantics, dict
            ):
                return {
                    "status": "not-established",
                    "reason": "invalid-semantic-documents",
                }
            # Exact equality is intentional: a replay contract is a snapshot,
            # not a policy language interpreter with implicit defaults.
            if policy_semantics != contract["policy"]:
                return {"status": "rejected", "reason": "policy-semantic-drift"}
            if resolver_semantics != contract["resolver"]:
                return {"status": "rejected", "reason": "resolver-semantic-drift"}
            if (
                record.get("policy", {}).get("enforcement_mode")
                != contract["enforcement_mode"]
            ):
                return {"status": "rejected", "reason": "enforcement-mode-mismatch"}
            if contract["enforcement_mode"] != "enforce":
                return {"status": "not-established", "reason": "non-enforcing-policy"}
            semantic_status = "exact-snapshot-matched"
        options = {
            name: context[name]
            for name in (
                "verification_time",
                "max_age_seconds",
                "max_future_skew_seconds",
                "expected_nonce",
            )
        }
        independently = independent_verify(
            record, trusted_key, **options, revoked_identifiers=revoked
        )
        try:
            verify_record(
                record, trusted_key, revocation=set(revoked),
                now=options["verification_time"],
                max_age_seconds=options["max_age_seconds"],
                max_future_skew_seconds=options["max_future_skew_seconds"],
                expected_nonce=options["expected_nonce"],
            )
            reference = "verified"
        except (ValueError, InvalidSignature):
            reference = "rejected"
        independent = (
            "verified"
            if independently.status == "verified-crypto"
            else independently.status
        )
        if reference != independent:
            return {
                "status": "not-established",
                "reason": "verifier-disagreement",
                "reference": reference,
                "independent": independent,
            }
        measurement_result = {
            "status": "not-established",
            "reason": "no-retained-measurement-appraisal",
        }
        measurement_contract = context.get("measurement_contract")
        if measurement_contract is not None:
            if not isinstance(measurement_contract, dict) or set(
                measurement_contract
            ) != {
                "policy",
                "reference_public_key_hex",
                "quote_public_key_hex",
                "reference_digest",
            }:
                return {
                    "status": "not-established",
                    "reason": "incomplete-measurement-context",
                }
            try:
                reference_bytes = (directory / "measurement_reference.bin").read_bytes()
                quote_bytes = (directory / "measurement_quote.bin").read_bytes()
                measurement_result = appraise_measurement(
                    record,
                    reference=json.loads(reference_bytes),
                    quote=json.loads(quote_bytes),
                    policy=measurement_contract["policy"],
                    reference_public_key=bytes.fromhex(
                        measurement_contract["reference_public_key_hex"]
                    ),
                    quote_public_key=bytes.fromhex(
                        measurement_contract["quote_public_key_hex"]
                    ),
                    expected_reference_digest=measurement_contract["reference_digest"],
                )
            except (ValueError, TypeError, KeyError, OSError):
                return {
                    "status": "not-established",
                    "reason": "invalid-retained-measurement-context",
                }
            if measurement_result["status"] != "affirming":
                return {
                    "status": "not-established"
                    if measurement_result["status"] == "not-established"
                    else "rejected",
                    "reason": "measurement-appraisal-" + measurement_result["reason"],
                    "measurement_appraisal": measurement_result,
                }
            claimed = record.get("appraisal", {}).get("platform_measurement")
            if claimed is not None:
                if not isinstance(claimed, dict) or claimed.get(
                    "measurement"
                ) != record.get("runtime", {}).get("measurement"):
                    return {
                        "status": "rejected",
                        "reason": "producer-appraisal-measurement-mismatch",
                    }
                layers = claimed.get("layers")
                if not isinstance(layers, dict):
                    return {
                        "status": "not-established",
                        "reason": "missing-producer-layer-claims",
                    }
                for name in measurement_contract["policy"]["required_layers"]:
                    if (
                        layers.get(name, {}).get("outcome")
                        != measurement_result["layers"][name]["outcome"]
                    ):
                        return {
                            "status": "rejected",
                            "reason": "producer-layer-appraisal-disagreement",
                            "layer": name,
                        }
        simulation_result = None
        simulation_contract = context.get("simulation_contract")
        if simulation_contract is not None:
            if not isinstance(simulation_contract, dict) or set(
                simulation_contract
            ) != {"tpm", "tee"}:
                return {
                    "status": "not-established",
                    "reason": "incomplete-simulation-contract",
                }
            if not isinstance(simulation_contract["tpm"], dict) or not isinstance(
                simulation_contract["tee"], dict
            ):
                return {
                    "status": "not-established",
                    "reason": "malformed-simulation-policy",
                }
            if tpm2_checkquote is None:
                return {
                    "status": "not-established",
                    "reason": "tpm2-quote-verifier-not-provisioned",
                }
            tpm_args = dict(simulation_contract["tpm"])
            tee_args = dict(simulation_contract["tee"])
            try:
                tee_args["trusted_observer_public"] = bytes.fromhex(
                    tee_args.pop("trusted_observer_public_hex")
                )
                tpm_payload = json.loads(
                    (directory / "simulation_tpm.bin").read_bytes()
                )
                tee_payload = json.loads(
                    (directory / "simulation_tee.bin").read_bytes()
                )
                expected_workload_digest = tee_args.pop(
                    "expected_workload_digest", None
                )
                expected_tpm_source_digest = tee_args.pop(
                    "expected_tpm_source_digest", None
                )
                event_digests = tpm_payload.get("event_digests")
                expected_closure = [
                    sha256(tee_args["expected_commit"].encode()).removeprefix(
                        "sha256:"
                    ),
                    tee_args["expected_executable_digest"],
                    expected_workload_digest,
                    expected_tpm_source_digest,
                ]
                if not all(
                    isinstance(v, str) and len(v) == 64 for v in expected_closure
                ):
                    return {
                        "status": "not-established",
                        "reason": "missing-measured-source-closure",
                    }
                if event_digests != expected_closure:
                    return {
                        "status": "rejected",
                        "reason": "tpm-tee-measurement-closure-disagreement",
                    }
                sim_tpm = verify_simulated_tpm(
                    tpm_payload, tpm2_checkquote=tpm2_checkquote, **tpm_args
                )
                sim_tee = verify_software_tee(tee_payload, **tee_args)
            except (TypeError, ValueError, KeyError, OSError) as exc:
                return {
                    "status": "not-established",
                    "reason": "invalid-simulation-context:" + type(exc).__name__,
                }
            simulation_result = {"tpm": sim_tpm, "tee": sim_tee}
            if (
                sim_tpm["status"] != "verified-simulation-only"
                or sim_tee["status"] != "verified-simulation-only"
            ):
                return {
                    "status": "rejected"
                    if "rejected" in (sim_tpm["status"], sim_tee["status"])
                    else "not-established",
                    "reason": "simulation-replay-not-established",
                    "simulation": simulation_result,
                }
        return {
            "status": (
                "simulated-evidence-validated"
                if simulation_result is not None and reference == "verified"
                else "crypto-and-context-verified"
                if reference == "verified"
                else "rejected"
            ),
            "reason": "matched-bounded-verifiers",
            "reference": reference,
            "independent": independent,
            "manifest_digest": expected_manifest_digest,
            "scope": "exact-snapshot-equality-only-not-external-authority",
            "semantic_status": semantic_status,
            "measurement_appraisal": measurement_result,
            "simulation": simulation_result,
        }
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {
            "status": "not-established",
            "reason": "bundle-unreadable:" + type(exc).__name__,
        }
