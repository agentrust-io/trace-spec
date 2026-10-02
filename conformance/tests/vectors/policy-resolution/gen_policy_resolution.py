"""Regenerate the policy-resolution vector set, byte for byte.

Deterministic by construction: no keys, no clock, no randomness, no network.
Running this on any machine with the same CPython minor version reproduces
every file in this directory exactly, which is what
``tests/test_policy_resolution_reproduces.py`` asserts.

    python tests/vectors/policy-resolution/gen_policy_resolution.py

The digests in the vectors are computed over the exact bytes of the sibling
files under ``policies/``. Anyone holding only this directory can recompute
them; nothing here depends on another repository being checked out.

WHAT THIS SET IS FOR
    ``policy.bundle_hash`` states the digest of the policy bundle in force,
    and ``policy.policy_uri`` says where that bundle can be fetched. Nothing
    in the suite used to compare the two, so a record could name a bundle,
    declare a digest, and have the two disagree without any check noticing.
    TR-POL-003 makes that comparison, and this set is what holds it to
    account. See the set's README.md.

WHAT EACH VECTOR ASSERTS
    One thing: the status of the TR-POL-003 finding. That is the unit of
    measurement for this set, and it is deliberately narrower than a whole
    record's verdict. These records carry other findings — they are unsigned,
    so TR-SIG-005 has an opinion about them — and reading the set at record
    granularity would blur the check under test with everything around it.

ANCHORS
    Every expected outcome names the text it derives from, and says which
    surface that text lives on. Tier 1 is merged prose in the specification.
    Tier 2 is the packaged schema, which is what this suite tests conformance
    against but is not the specification. Where no text governs a case, the
    vector says so rather than implying an authority it does not have.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICIES = HERE / "policies"

# --- house serialization, fixed so bytes are stable across platforms -------
INDENT = 2


def write_json(path: Path, obj: object) -> bytes:
    """Write *obj* as UTF-8 JSON with LF endings; return the exact bytes."""
    text = json.dumps(obj, indent=INDENT, ensure_ascii=True) + "\n"
    data = text.encode("utf-8")
    path.write_bytes(data)
    return data


def sha256_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha384_of(data: bytes) -> str:
    """A digest the schema admits and a sha256-only verifier cannot compute.

    The pattern on ``policy.bundle_hash`` accepts sha384, so a verifier that
    hardcoded sha256 would be wrong rather than merely limited. Two vectors
    turn on this: one where the sha384 comparison must succeed, and one where
    it must fail. A verifier that skips what it cannot compute passes the
    first and is caught by the second.
    """
    return "sha384:" + hashlib.sha384(data).hexdigest()


# --- the cited objects -----------------------------------------------------
# Small, ASCII-only, and shaped like a policy bundle rather than a
# placeholder, so a reader can see why swapping one for another matters.

POLICY_BASE = {
    "policy_id": "appraisal/baseline",
    "version": "1.0.0",
    "rules": [
        {"claim": "runtime.platform",
         "must_be_one_of": ["intel-tdx", "amd-sev-snp", "tpm2"]},
        {"claim": "build_provenance.slsa_level", "minimum": 2},
    ],
}

# One character apart from the baseline: the SLSA floor moves 2 -> 3. A
# verifier comparing digests sees a mismatch; a human diffing the two files
# sees a single byte. That is the point: the smallest edit that changes what
# the policy permits still has to be caught.
POLICY_ONEBYTE = {
    "policy_id": "appraisal/baseline",
    "version": "1.0.0",
    "rules": [
        {"claim": "runtime.platform",
         "must_be_one_of": ["intel-tdx", "amd-sev-snp", "tpm2"]},
        {"claim": "build_provenance.slsa_level", "minimum": 3},
    ],
}

# A wholesale replacement rather than an edit: different rules, different
# shape, same job. Paired with the one-byte case so the check cannot be
# satisfied by a heuristic that only notices large changes.
POLICY_OTHER = {
    "policy_id": "appraisal/baseline",
    "version": "2.0.0",
    "rules": [
        {"claim": "runtime.platform",
         "must_be_one_of": ["intel-tdx", "amd-sev-snp"]},
        {"claim": "build_provenance.slsa_level", "minimum": 3},
        {"claim": "transparency", "must_be_present": True},
    ],
}

# A different policy entirely, not a version of the baseline.
POLICY_UNRELATED = {
    "policy_id": "retention/pii-90d",
    "version": "1.4.2",
    "rules": [
        {"claim": "data_class", "must_be_one_of": ["public", "internal"]},
    ],
}

POLICY_FILES = {
    "policy-bundle-base.json": POLICY_BASE,
    "policy-bundle-onebyte.json": POLICY_ONEBYTE,
    "policy-bundle-other.json": POLICY_OTHER,
    "policy-bundle-unrelated.json": POLICY_UNRELATED,
}

BASE_URI = "https://policy.example.org/bundles/"

# --- the record ------------------------------------------------------------
# Every vector's record is identical except for the policy block, so the
# defect under test is the only thing that varies. appraisal.policy_ref is
# fixed and never varied: this set is about policy.bundle_hash and
# policy.policy_uri, and a second moving field would blur which one the
# finding is answering. Modelled on tests/vectors/valid_level0.json:
# unsigned, ASCII-only, fixed iat.

RECORD_IAT = 1748000000
APPRAISAL_TIMESTAMP = 1748000042
#: Fixed so the CLI can be handed a matching --expected-nonce and TR-RTE-004
#: stops being noise at Level 1. base64url, no padding, per the schema.
RECORD_NONCE = "Zm9yLXRoZS1yZWNvcmQtbm9uY2U"
APPRAISAL_POLICY_REF = "https://verifier.example.org/appraisal-policy/v1"


def record_with(policy: dict[str, object]) -> dict[str, object]:
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": RECORD_IAT,
        "subject": "spiffe://example.org/agent/credit-risk/01926b4c-1234-7abc-9def-000000000001",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-5"},
        "runtime": {
            "platform": "intel-tdx",
            "measurement":
                "sha256:a3f8d2b4e1c9f7a5b2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8",
            "nonce": RECORD_NONCE,
        },
        "policy": policy,
        "data_class": "confidential",
        "build_provenance": {
            "slsa_level": 2,
            "digest": "sha256:c9f7a5b2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8",
        },
        "appraisal": {
            "status": "affirming",
            "verifier": "https://verifier.example.org",
            "policy_ref": APPRAISAL_POLICY_REF,
            "timestamp": APPRAISAL_TIMESTAMP,
        },
        "transparency": "https://scitt.example.org/receipts/abc123def456",
        "cnf": {
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "dGhpcyBpcyBhIHRlc3QgeA",
                "y": "dGhpcyBpcyBhIHRlc3QgeQ",
                "kid": "tee-key-001",
            }
        },
    }


def policy(bundle_hash: str, policy_uri: str | None = None) -> dict[str, object]:
    block: dict[str, object] = {
        "bundle_hash": bundle_hash,
        "enforcement_mode": "enforce",
    }
    if policy_uri is not None:
        block["policy_uri"] = policy_uri
    return block


# --- anchors ---------------------------------------------------------------
# The text each expected outcome derives from, and the surface it lives on.

ANCHOR_SUBSTITUTION = {
    "tier": 1,
    "source": "agentrust-io/trace-spec spec/trace-v0.2.md 4.3",
    "text": (
        "the policy bundle hash is sealed to the TEE measurement, the "
        "enforcement mode is recorded, and substituting the policy invalidates "
        "the runtime claim"
    ),
    "applies": (
        "A resolved bundle whose digest is not the declared one is a "
        "substituted policy, so the runtime claim does not stand."
    ),
}

ANCHOR_MATCHES = {
    "tier": 1,
    "source": "agentrust-io/trace-spec spec/trace-v0.2.md 4.3",
    "text": (
        "the policy bundle hash is sealed to the TEE measurement, the "
        "enforcement mode is recorded, and substituting the policy invalidates "
        "the runtime claim"
    ),
    "applies": (
        "Read the other way: the bundle that resolves is the bundle that was "
        "sealed, so nothing was substituted and the claim stands."
    ),
}

ANCHOR_URI_FORM = {
    "tier": 2,
    "source": "schemas/trace-claim.json properties.policy.properties.policy_uri",
    "text": "URI to the policy bundle for verification.",
    "applies": (
        "The schema asks for format: uri, which is the absolute form. A "
        "reference the record got wrong is a defect in the record, visible "
        "with no network. This is a conformance statement about the packaged "
        "schema, not a claim about the specification, which says nothing about "
        "policy_uri at all."
    ),
}

ANCHOR_OPTIONAL = {
    "tier": 2,
    "source": "schemas/trace-claim.json properties.policy.required",
    "text": "required: [bundle_hash, enforcement_mode]",
    "applies": (
        "policy_uri is absent from the required list, so a record that omits "
        "it is conformant and the check has nothing to compare."
    ),
}

ANCHOR_UNRESOLVED = {
    "tier": 0,
    "source": "no merged sentence governs this case",
    "text": "",
    "applies": (
        "No text in the specification says what a verifier records when a "
        "policy bundle cannot be fetched: policy_uri appears nowhere in the "
        "merged specification, and the reference block that does discuss "
        "resolvability governs the references field rather than this one. The "
        "vector therefore asserts only that the check was not performed, which "
        "is a fact about the run rather than a reading of any text. The level "
        "at which that stops being tolerable is suite policy, registered in "
        "src/trace_tests/modules/unverified.py and docs/levels.md, and is not "
        "claimed here as a specification requirement."
    ),
}


def main(out_dir: Path | None = None) -> int:
    """Write the set into *out_dir* (default: this directory).

    The parameter exists so the byte-reproduction guard can regenerate into a
    temporary directory and compare, rather than overwriting the committed
    files and comparing them to themselves — which would agree no matter what.
    """
    here = Path(out_dir) if out_dir is not None else HERE
    policies = here / "policies"
    here.mkdir(parents=True, exist_ok=True)
    policies.mkdir(exist_ok=True)

    # 1. Write the cited objects and digest their exact bytes.
    digests: dict[str, str] = {}
    raw: dict[str, bytes] = {}
    for name, obj in POLICY_FILES.items():
        raw[name] = write_json(policies / name, obj)
        digests[name] = sha256_of(raw[name])

    d_base = digests["policy-bundle-base.json"]
    d384_base = sha384_of(raw["policy-bundle-base.json"])
    d384_other = sha384_of(raw["policy-bundle-other.json"])

    uri_base = BASE_URI + "policy-bundle-base.json"
    uri_onebyte = BASE_URI + "policy-bundle-onebyte.json"
    uri_other = BASE_URI + "policy-bundle-other.json"
    uri_unrelated = BASE_URI + "policy-bundle-unrelated.json"
    # Cited by 05 and deliberately absent from the manifest: no route at all.
    uri_withdrawn = BASE_URI + "policy-bundle-withdrawn.json"
    # Cited by 11 and mapped by the manifest to a file that is not there:
    # a route that fails. Two input classes, two exception classes.
    uri_gone = BASE_URI + "policy-bundle-gone.json"
    # 08: the uri-reference form the schema's format: uri does not admit.
    uri_relative = "bundles/policy-bundle-base.json"
    # 10: absolute, well-schemed, and carrying a space in the path.
    uri_spaced = BASE_URI + "policy bundle base.json"

    def ctx(cited: str, outcome: str, anchor: dict[str, object]) -> dict[str, object]:
        return {
            "cited_uri": cited,
            "resolution": {"outcome": outcome},
            "anchor": anchor,
        }

    vectors: list[tuple[str, dict[str, object]]] = [
        ("01-no-policy-uri.json", {
            "name": "no-policy-uri",
            "description": (
                "The record declares a bundle digest and no location to fetch the "
                "bundle from. This is every conformant record today, so it must keep "
                "verifying: a set that failed it would be proposing a breaking change "
                "rather than describing a gap."
            ),
            "boundary": "accept",
            "defect": "none - backward-compatibility control",
            "record": record_with(policy(d_base)),
            "context": ctx(None, "not_attempted", ANCHOR_OPTIONAL),
            "expected": {
                "tr_pol_003": "skip",
                "reason": "No policy_uri is declared, so there is nothing to resolve.",
            },
        }),
        ("02-resolved-and-matches.json", {
            "name": "resolved-and-matches",
            "description": (
                "The bundle at policy_uri hashes to exactly what bundle_hash "
                "declares. The positive control: a set that could not pass this would "
                "reject every honest record."
            ),
            "boundary": "accept",
            "defect": "none - positive control, sha256",
            "record": record_with(policy(d_base, uri_base)),
            "context": ctx(uri_base, "resolved", ANCHOR_MATCHES),
            "expected": {
                "tr_pol_003": "pass",
                "reason": "The resolved bytes hash to the declared digest.",
            },
        }),
        ("03-digest-mismatch-minimal-mutation.json", {
            "name": "digest-mismatch-minimal-mutation",
            "description": (
                "The cited bundle was edited by one character after the digest was "
                "taken. The smallest change that alters what the policy permits, and "
                "the one a reader is least likely to notice."
            ),
            "boundary": "contradicted",
            "defect": "cited object mutated minimally after the digest was taken",
            "record": record_with(policy(d_base, uri_onebyte)),
            "context": ctx(uri_onebyte, "resolved", ANCHOR_SUBSTITUTION),
            "expected": {
                "tr_pol_003": "fail",
                "reason": "The resolved bytes contradict the declared digest.",
            },
        }),
        ("04-digest-mismatch-different-object.json", {
            "name": "digest-mismatch-different-object",
            "description": (
                "The cited bundle was replaced wholesale after the digest was taken. "
                "Paired with 03 so the check cannot be satisfied by a heuristic that "
                "only notices large differences, or only small ones."
            ),
            "boundary": "contradicted",
            "defect": "cited object wholly replaced after the digest was taken",
            "record": record_with(policy(d_base, uri_other)),
            "context": ctx(uri_other, "resolved", ANCHOR_SUBSTITUTION),
            "expected": {
                "tr_pol_003": "fail",
                "reason": "The resolved bytes contradict the declared digest.",
            },
        }),
        ("05-referent-unreachable-no-route.json", {
            "name": "referent-unreachable-no-route",
            "description": (
                "The cited URI is not one the verifier has any route to. Nothing was "
                "contradicted, because nothing was read. This vector asserts only "
                "that the comparison did not happen."
            ),
            "boundary": "unresolvable",
            "defect": "referent unreachable: no route to the cited URI",
            "record": record_with(policy(d_base, uri_withdrawn)),
            "context": ctx(uri_withdrawn, "unreachable_no_route", ANCHOR_UNRESOLVED),
            "expected": {
                "tr_pol_003": "unverified",
                "reason": (
                    "The bundle could not be fetched, so the digest was never "
                    "compared. Reporting that as a pass would claim a check that "
                    "did not run."
                ),
            },
        }),
        ("06-resolved-and-matches-sha384.json", {
            "name": "resolved-and-matches-sha384",
            "description": (
                "The same accept as 02, with the digest taken in sha384. The schema "
                "admits both algorithms, so a verifier that hardcodes sha256 is wrong "
                "rather than merely limited, and this is the vector that says so."
            ),
            "boundary": "accept",
            "defect": "none - positive control, sha384",
            "record": record_with(policy(d384_base, uri_base)),
            "context": ctx(uri_base, "resolved", ANCHOR_MATCHES),
            "expected": {
                "tr_pol_003": "pass",
                "reason": "The resolved bytes hash to the declared sha384 digest.",
            },
        }),
        ("07-digest-bound-to-other-referent.json", {
            "name": "digest-bound-to-other-referent",
            "description": (
                "The declared digest is a correct digest of some object, just not of "
                "the one policy_uri names. A verifier that checks the digest is "
                "well formed, or that it matches something it holds, passes this."
            ),
            "boundary": "contradicted",
            "defect": "digest well formed but taken over a different object",
            "record": record_with(policy(d_base, uri_unrelated)),
            "context": ctx(uri_unrelated, "resolved", ANCHOR_SUBSTITUTION),
            "expected": {
                "tr_pol_003": "fail",
                "reason": (
                    "The binding does not describe the object the record cites, "
                    "even though it describes some object."
                ),
            },
        }),
        ("08-policy-uri-is-a-relative-reference.json", {
            "name": "policy-uri-is-a-relative-reference",
            "description": (
                "policy_uri is a uri-reference rather than the absolute URI the "
                "schema asks for. No network is needed to see it: this is a defect "
                "in the record, and it is reported the same way with or without a "
                "resolver."
            ),
            "boundary": "malformed",
            "defect": "reference is relative, not the absolute URI the schema asks for",
            "record": record_with(policy(d_base, uri_relative)),
            "context": ctx(uri_relative, "not_attempted", ANCHOR_URI_FORM),
            "expected": {
                "tr_pol_003": "fail",
                "reason": (
                    "A relative reference names no authority, so no verifier can "
                    "dereference it on its own."
                ),
            },
        }),
        ("09-sha384-bound-to-other-referent.json", {
            "name": "sha384-bound-to-other-referent",
            "description": (
                "A sha384 digest of a different object. Paired with 06: deleting "
                "sha384 support turns both to skip, while a verifier that computes "
                "only sha256 fails 06 alone, and one that accepts sha384 without "
                "comparing fails 09 alone."
            ),
            "boundary": "contradicted",
            "defect": "sha384 digest taken over a different object",
            "record": record_with(policy(d384_other, uri_base)),
            "context": ctx(uri_base, "resolved", ANCHOR_SUBSTITUTION),
            "expected": {
                "tr_pol_003": "fail",
                "reason": (
                    "The resolved bytes contradict the declared sha384 digest. A "
                    "verifier that cannot compute sha384 must not report a pass."
                ),
            },
        }),
        ("10-policy-uri-carries-a-space.json", {
            "name": "policy-uri-carries-a-space",
            "description": (
                "An absolute URI with a legitimate scheme and a space in the path. "
                "A transcription accident rather than a wrong form, and one that "
                "survives a diff unnoticed unless something checks for it."
            ),
            "boundary": "malformed",
            "defect": "reference carries a space in its path",
            "record": record_with(policy(d_base, uri_spaced)),
            "context": ctx(uri_spaced, "not_attempted", ANCHOR_URI_FORM),
            "expected": {
                "tr_pol_003": "fail",
                "reason": (
                    "A URI carrying a raw space is not a URI. Paired with 08: the "
                    "scheme rule and the character rule catch different mistakes."
                ),
            },
        }),
        ("11-referent-unreachable-route-fails.json", {
            "name": "referent-unreachable-route-fails",
            "description": (
                "The verifier knows where the bundle should be and cannot read it. "
                "Paired with 05: one has no route, this one has a route that fails, "
                "and a resolver that handled only one of the two would leave the "
                "other reporting something it has not checked."
            ),
            "boundary": "unresolvable",
            "defect": "referent unreachable: route known, bundle missing",
            "record": record_with(policy(d_base, uri_gone)),
            "context": ctx(uri_gone, "unreachable_route_fails", ANCHOR_UNRESOLVED),
            "expected": {
                "tr_pol_003": "unverified",
                "reason": (
                    "The bundle could not be read, so the digest was never "
                    "compared. The finding carries the reason so this is "
                    "distinguishable from a URI nothing routes."
                ),
            },
        }),
    ]

    # 2. The manifest. One mapping from cited URI to the bytes behind it, used
    #    by the CLI's --policy-dir and by the tests, so there is no second
    #    place for a vector's idea of what it resolves to to drift from.
    #    uri_withdrawn is deliberately absent. uri_gone is deliberately mapped
    #    to a file that is not written.
    manifest = {
        uri_base: "policies/policy-bundle-base.json",
        uri_onebyte: "policies/policy-bundle-onebyte.json",
        uri_other: "policies/policy-bundle-other.json",
        uri_unrelated: "policies/policy-bundle-unrelated.json",
        uri_gone: "policies/policy-bundle-gone.json",
    }
    write_json(here / "resolutions.json", manifest)

    for name, vector in vectors:
        write_json(here / name, vector)

    print(f"wrote {len(POLICY_FILES)} policy objects, {len(vectors)} vectors, 1 manifest")
    for name in POLICY_FILES:
        print(f"  policies/{name}  {digests[name]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
