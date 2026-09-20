"""Generate the reproducibility-claim vectors (spec section 3.1.4).

Section 3.1.4 puts a claim on the record and its result in the appraisal, and states
four rules about their shape that a schema can hold: `appraisal.re_execution` is
present exactly when `appraisal.method` is `re-execution`; `observed_digest` is
required when the outcome is `diverged`; `reason` is required when it is
`not-attempted`; and every `input_closure` entry carries `id`, `digest` and
`resolver`. The schema holds the two closed sets as well, `method` and `outcome`, and
the members the claim itself requires.

These vectors pin each of those, two per rule (agentrust-io/trace-spec#124), and pin
the accepting direction with a claim carrying no result and one result per outcome.
A verifier that rejects everything fails the five accepting vectors; one that accepts
everything fails the sixteen rejecting ones; one that checks presence but not the
closed set of `method` passes `16` and fails `17`.

**What is real and what is a placeholder.** `transcript_digest` and every closure
`digest` are SHA-256 over the RFC 8785 bytes of the JSON values carried inline under
`context`, so a verifier can recompute them from the vector alone, and vector `03`'s
`observed_digest` is the same computation over `context.observed_transcript`.
`code_identity` and `verifier_code_identity` are derived from the fixture seed: no
implementation artifact exists behind them, since these vectors pin the shape of the
claim and its result, not the re-execution itself, which needs a function and a
closure from a producer that has both. That corpus belongs beside the annex that
describes the function.

Every record is signed, the rejected ones included, because the subject of each
rejection is the schema and not the signature: a verifier that reached the signature
check on `06` would find it valid. Keys derive from one published seed, so the set
regenerates byte-for-byte. Files are written as bytes with LF line endings.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path("examples/reproducibility-claim")
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
SPEC = "spec/trace-v0.2.md#314-reproducibility-deterministic-re-execution-as-evidence"

SEED = hashlib.sha256(b"trace-spec reproducibility-claim fixture key").digest()

#: Fixed issue time. Nothing in this set turns on the clock.
IAT = 1785000000

SUBJECT = "spiffe://orchestrator.example/run/2026-09-18T09:00:00Z/exec/plan"
VERIFIER = "https://verifier.example/re-execution"
RESOLVER = "https://artifacts.example.org"

#: The closure the function reads, carried inline so every digest is recomputable.
#: Two inputs: the initial configuration, and one recorded model interaction. The
#: model call is an input like any other; that is the whole point of the boundary.
CLOSURE: dict[str, Any] = {
    "config/initial": {"tasks": ["plan", "review"], "max_parallel": 1, "merge": "gated"},
    "model-call/0007": {
        "task": "plan",
        "request_digest": "sha256:" + "7a" * 32,
        "response": "split into two steps: draft, then verify",
    },
}

#: The transcript the function produces over CLOSURE: every decision, in order.
TRANSCRIPT: dict[str, Any] = {
    "function": "coordination/v1",
    "steps": [
        {"step": 0, "read": "config/initial", "decision": "schedule", "task": "plan"},
        {"step": 1, "read": "model-call/0007", "decision": "split", "task": "plan",
         "into": ["plan/draft", "plan/verify"]},
        {"step": 2, "read": "config/initial", "decision": "gate", "task": "plan/verify"},
    ],
}

#: What a verifier at a different implementation produced over the same closure:
#: one decision differs. Vector 03's observed digest is taken over this.
OBSERVED_TRANSCRIPT: dict[str, Any] = copy.deepcopy(TRANSCRIPT)
OBSERVED_TRANSCRIPT["steps"][2]["decision"] = "merge"


def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(SEED + b"|producer").digest())


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk() -> dict[str, str]:
    raw = key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


def digest(value: Any) -> str:
    """The section's preimage: RFC 8785 bytes of a JSON value."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def placeholder(label: str) -> str:
    """A digest with no artifact behind it, derived from the seed by label."""
    return "sha256:" + hashlib.sha256(SEED + b"|" + label.encode()).hexdigest()


def claim(*, code_resolver: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "function": "coordination/v1",
        "code_identity": placeholder("code"),
        "input_closure": [
            {"id": name, "digest": digest(blob), "resolver": RESOLVER}
            for name, blob in CLOSURE.items()
        ],
        "transcript_digest": digest(TRANSCRIPT),
    }
    if code_resolver:
        out["code_resolver"] = RESOLVER
    return out


def record(*, appraisal: dict[str, Any], claim_block: dict[str, Any] | None) -> dict[str, Any]:
    """A schema-valid software-only record carrying the claim and the appraisal given.

    Minimal otherwise: nothing optional is present except what the vector is about.
    """
    body: dict[str, Any] = {
        "eat_profile": V0_2,
        "iat": IAT,
        "subject": SUBJECT,
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "00" * 32},
        "policy": {"bundle_hash": "sha256:" + "aa" * 32, "enforcement_mode": "enforce"},
        "data_class": "internal",
    }
    if claim_block is not None:
        body["reproducibility"] = claim_block
    body["build_provenance"] = {"slsa_level": 0, "digest": placeholder("code")}
    body["appraisal"] = appraisal
    body["cnf"] = {"jwk": jwk()}
    body["signature"] = b64u(key().sign(rfc8785.dumps(body)))
    return body


def result(outcome: str, **members: Any) -> dict[str, Any]:
    return {"outcome": outcome, **members}


def appraisal(status: str, *, method: str | None = None,
              re_execution: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"status": status, "verifier": VERIFIER}
    if method is not None:
        out["method"] = method
    if re_execution is not None:
        out["re_execution"] = re_execution
    return out


def vector(n: int, name: str, description: str, *, rec: dict[str, Any],
           codes: list[str], context: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
    doc: dict[str, Any] = {
        "name": name,
        "description": description,
        "spec": SPEC,
        "record": rec,
        "expected": {"outcome": "reject" if codes else "accept", "codes": codes},
    }
    if context is not None:
        doc["context"] = context
    return f"{n:02d}-{name}.json", doc


#: Recompute material for the accepting vectors, and for any rejected one whose
#: claim is intact. The closure blobs and the transcript are the preimages.
CONTEXT: dict[str, Any] = {"closure": CLOSURE, "transcript": TRANSCRIPT}
CONTEXT_DIVERGED: dict[str, Any] = {**CONTEXT, "observed_transcript": OBSERVED_TRANSCRIPT}

REPRODUCED = result("reproduced", verifier_code_identity=placeholder("verifier"))
DIVERGED = result("diverged", observed_digest=digest(OBSERVED_TRANSCRIPT),
                  verifier_code_identity=placeholder("verifier"))
NOT_RESOLVED = result("not-attempted",
                      reason=f"closure entry model-call/0007 did not resolve at {RESOLVER}",
                      verifier_code_identity=placeholder("verifier"))
READ_BEYOND = result("not-attempted",
                     reason="function read config/feature-flags, which the closure does not pin",
                     verifier_code_identity=placeholder("verifier"))


def main() -> None:
    out: list[tuple[str, dict[str, Any]]] = []

    # Accepting. The claim alone, then one result per outcome.
    out.append(vector(1, "claim-without-a-result",
        "A record carries the claim and no verifier has re-run it. The claim is "
        "producer-side and needs no result to be well-formed; status none says no "
        "appraisal was performed, which is true here.",
        rec=record(appraisal=appraisal("none"), claim_block=claim()),
        codes=[], context=CONTEXT))
    out.append(vector(2, "reproduced",
        "The verifier re-ran the function over the closure alone and its transcript "
        "digest equals transcript_digest. The claim names a code_resolver, so the "
        "optional member is exercised on the accepting side.",
        rec=record(appraisal=appraisal("affirming", method="re-execution", re_execution=REPRODUCED),
                   claim_block=claim(code_resolver=True)),
        codes=[], context=CONTEXT))
    out.append(vector(3, "diverged-carries-the-observed-digest",
        "The re-run completed on the closure alone and produced a different transcript: "
        "one decision differs, recorded under context.observed_transcript. The result "
        "carries the verifier's digest, so a third party can compare the two.",
        rec=record(appraisal=appraisal("contraindicated", method="re-execution", re_execution=DIVERGED),
                   claim_block=claim()),
        codes=[], context=CONTEXT_DIVERGED))
    out.append(vector(4, "not-attempted-closure-entry-unresolved",
        "A closure blob could not be resolved, so no outcome is reported and the reason "
        "names the entry. Not status none: an appraisal was performed and what it could "
        "not do is on the record.",
        rec=record(appraisal=appraisal("warning", method="re-execution", re_execution=NOT_RESOLVED),
                   claim_block=claim()),
        codes=[], context=CONTEXT))
    out.append(vector(5, "not-attempted-read-beyond-the-closure",
        "The function read something the closure does not pin. Whatever the re-run "
        "would otherwise have produced, the outcome is not-attempted with the read "
        "named: a re-run on something the claim did not pin is not the re-run the "
        "claim describes.",
        rec=record(appraisal=appraisal("warning", method="re-execution", re_execution=READ_BEYOND),
                   claim_block=claim()),
        codes=[], context=CONTEXT))

    # A result under no method. A verifier cannot key on it.
    out.append(vector(6, "result-without-method",
        "appraisal.re_execution is present and appraisal.method is absent. The result is "
        "scoped under the method; without it nothing says what the block is a result of.",
        rec=record(appraisal=appraisal("affirming", re_execution=REPRODUCED), claim_block=claim()),
        codes=["re_execution_without_method"], context=CONTEXT))
    out.append(vector(7, "result-without-method-not-attempted",
        "Same rule, on a not-attempted result that is otherwise complete. The reason "
        "does not stand in for the method.",
        rec=record(appraisal=appraisal("warning", re_execution=NOT_RESOLVED), claim_block=claim()),
        codes=["re_execution_without_method"], context=CONTEXT))

    # A method with no result. It reports nothing.
    out.append(vector(8, "method-without-result",
        "appraisal.method is re-execution and appraisal.re_execution is absent. The "
        "method names what was done; the result is where it is reported, and a method "
        "with no result reports nothing.",
        rec=record(appraisal=appraisal("affirming", method="re-execution"), claim_block=claim()),
        codes=["method_without_re_execution"], context=CONTEXT))
    out.append(vector(9, "method-without-result-status-none",
        "Same rule with status none. The status does not stand in for the result, and "
        "none is the wrong value for an appraisal that was performed in any case.",
        rec=record(appraisal=appraisal("none", method="re-execution"), claim_block=claim()),
        codes=["method_without_re_execution"], context=CONTEXT))

    # Divergence must be comparable.
    out.append(vector(10, "diverged-without-observed-digest",
        "outcome diverged with no observed_digest. Divergence localises nothing by "
        "itself; without the verifier's digest nobody can compare the two transcripts.",
        rec=record(appraisal=appraisal("contraindicated", method="re-execution",
                                       re_execution=result("diverged",
                                                           verifier_code_identity=placeholder("verifier"))),
                   claim_block=claim()),
        codes=["diverged_without_observed_digest"], context=CONTEXT))
    out.append(vector(11, "diverged-with-a-reason-instead",
        "outcome diverged carrying a reason and no observed_digest. A reason belongs to "
        "not-attempted; it does not substitute for the digest a diverged result owes.",
        rec=record(appraisal=appraisal("contraindicated", method="re-execution",
                                       re_execution=result("diverged",
                                                           reason="transcripts differ at step 2")),
                   claim_block=claim()),
        codes=["diverged_without_observed_digest"], context=CONTEXT))

    # An absence is reported with its cause.
    out.append(vector(12, "not-attempted-without-reason",
        "outcome not-attempted with no reason. A named absence and a generic one are "
        "different findings, and this result has discarded the finding.",
        rec=record(appraisal=appraisal("warning", method="re-execution",
                                       re_execution=result("not-attempted",
                                                           verifier_code_identity=placeholder("verifier"))),
                   claim_block=claim()),
        codes=["not_attempted_without_reason"], context=CONTEXT))
    out.append(vector(13, "not-attempted-with-an-observed-digest-instead",
        "outcome not-attempted carrying an observed_digest and no reason. A digest a "
        "re-run matched or missed on something the claim did not pin says nothing "
        "about the claim, and it does not substitute for the reason.",
        rec=record(appraisal=appraisal("warning", method="re-execution",
                                       re_execution=result("not-attempted",
                                                           observed_digest=digest(OBSERVED_TRANSCRIPT))),
                   claim_block=claim()),
        codes=["not_attempted_without_reason"], context=CONTEXT))

    # A closure entry pins nothing without all three members.
    incomplete = claim()
    del incomplete["input_closure"][1]["digest"]
    out.append(vector(14, "closure-entry-without-digest",
        "The model-call entry has no digest. A references entry may omit its digest; a "
        "closure entry may not, because an entry a verifier cannot check against the "
        "digest the producer signed pins nothing.",
        rec=record(appraisal=appraisal("none"), claim_block=incomplete),
        codes=["closure_entry_incomplete"]))
    incomplete = claim()
    del incomplete["input_closure"][0]["resolver"]
    out.append(vector(15, "closure-entry-without-resolver",
        "The configuration entry has no resolver. A digest with nobody obliged to "
        "resolve it is an input the verifier has no way to obtain.",
        rec=record(appraisal=appraisal("none"), claim_block=incomplete),
        codes=["closure_entry_incomplete"]))

    # method is a closed set.
    out.append(vector(16, "method-outside-the-closed-set",
        "appraisal.method is static-analysis. The set is closed because a verifier keys "
        "on it; this version defines re-execution and nothing else.",
        rec=record(appraisal=appraisal("affirming", method="static-analysis"), claim_block=claim()),
        codes=["unknown_method"], context=CONTEXT))
    out.append(vector(17, "method-misspelled-with-a-complete-result",
        "appraisal.method is re_execution, the member's spelling rather than the "
        "value's, and a complete result is present. A verifier that checks the pair is "
        "present but not the value passes this and is wrong.",
        rec=record(appraisal=appraisal("affirming", method="re_execution", re_execution=REPRODUCED),
                   claim_block=claim()),
        codes=["unknown_method"], context=CONTEXT))

    # outcome is a closed set.
    out.append(vector(18, "outcome-outside-the-closed-set",
        "outcome partial. The three outcomes are the whole set; a fourth is a reader "
        "rounding something the section says not to round.",
        rec=record(appraisal=appraisal("warning", method="re-execution",
                                       re_execution=result("partial", reason="two of three steps")),
                   claim_block=claim()),
        codes=["unknown_outcome"], context=CONTEXT))
    out.append(vector(19, "outcome-capitalised",
        "outcome Reproduced. Values are case-sensitive; a verifier that lowercases "
        "before comparing accepts a record no other implementation will.",
        rec=record(appraisal=appraisal("affirming", method="re-execution",
                                       re_execution=result("Reproduced")),
                   claim_block=claim()),
        codes=["unknown_outcome"], context=CONTEXT))

    # The claim's own required members.
    partial = claim()
    del partial["transcript_digest"]
    out.append(vector(20, "claim-without-transcript-digest",
        "The claim names the function and the closure and no transcript digest. There "
        "is then nothing for a re-run to be compared against, and the block claims "
        "nothing.",
        rec=record(appraisal=appraisal("none"), claim_block=partial),
        codes=["claim_incomplete"]))
    partial = claim()
    del partial["function"]
    out.append(vector(21, "claim-without-function",
        "The claim carries a code identity and no function name. The artifact may expose "
        "several; the claim is about one of them, and has to say which.",
        rec=record(appraisal=appraisal("none"), claim_block=partial),
        codes=["claim_incomplete"]))

    OUT.mkdir(parents=True, exist_ok=True)
    for name, doc in sorted(out):
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        (OUT / name).write_bytes(text.encode("utf-8"))
        print("wrote", name)


if __name__ == "__main__":
    main()
