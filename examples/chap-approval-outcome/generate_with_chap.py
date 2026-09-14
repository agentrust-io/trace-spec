"""Generate the CHAP approval-outcome fixtures from CHAP's own reference coordinator.

The approvals and rejections here are produced by `chap-coordinator` 0.2.13, the
Python reference implementation of the Collaborative Human-Agent Protocol, not
written by hand. That package is not a dependency of this repository, so this
script is not run by CI, the same arrangement as `../action-receipts/acta/gen.mjs`.
`tests/test_chap_approval_outcome_fixtures.py` re-verifies every committed file with
this repository's own dependencies and without importing CHAP.

    pip install chap-coordinator==0.2.13 agentrust-trace
    python examples/chap-approval-outcome/generate_with_chap.py

A new run issues a new signing key and new CHAP identifiers, so regenerating
replaces every file here rather than reproducing it byte for byte.
"""
from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys
import time

import rfc8785
from agentrust_trace import generate_key, key_to_jwk, sign_record, verify_record
from chap_coordinator import Coordinator, CoordinatorOptions
from chap_coordinator.canonical import content_hash

HERE = pathlib.Path(__file__).resolve().parent
CHAP_VERSION = "0.2.13"
WORKSPACE = "wsp_refund_review"
RESOLVER = "https://chap.example.org/workspaces/wsp_refund_review"
REVIEWER = "human:alice@example.org"
AGENT = "agent:refund-bot"


def run_chap() -> tuple[dict, dict]:
    """One workspace, two reviewed drafts: one approved, one rejected."""
    coord = Coordinator(CoordinatorOptions(
        default_profiles=["core/1.0", "review/1.0", "audit-scitt/1.0"]))
    counter = iter(range(1, 10_000))

    def send(method: str, actor: str | None = None, **params) -> dict:
        body = {"workspace": WORKSPACE, **params}
        if actor is not None:
            body["from"] = actor
        response = coord.dispatch({"jsonrpc": "2.0", "id": str(next(counter)),
                                   "method": method, "params": body})
        if "error" in response:
            sys.exit(f"{method}: {response['error']}")
        return response["result"]

    send("workspace.create")
    send("participant.join", actor=REVIEWER, type="human", role="reviewer")
    send("participant.join", actor=AGENT, type="agent", role="drafter")

    def review(draft: dict) -> str:
        task_id = send("task.create", actor=AGENT, kind="refund_decision",
                       input={"order": draft["order"]}, assignee=AGENT)["task_id"]
        send("review.request", actor=AGENT, task_id=task_id, artefact=draft, to=REVIEWER)
        return task_id

    approved = review({"order": "1042", "action": "refund", "amount_minor": 1250})
    rejected = review({"order": "1043", "action": "refund", "amount_minor": 98000})
    workspace = coord.get_workspace(WORKSPACE)
    send("decide.approve", actor=REVIEWER, task_id=approved, comment="Within policy.",
         tags=[], approved_artefact_digest=content_hash(workspace.tasks[approved].pending_artefact))
    send("decide.reject", actor=REVIEWER, task_id=rejected, comment="Above the refund limit.",
         reason="Above the refund limit.", tags=[],
         approved_artefact_digest=content_hash(workspace.tasks[rejected].pending_artefact))

    verdict = send("audit.verify_chain")
    if verdict.get("status") != "verified":
        sys.exit(f"CHAP did not verify its own chain: {verdict}")
    log = {
        "format": "chap-audit-export/fixture-1",
        "generated_by": f"chap-coordinator {CHAP_VERSION}",
        "workspace": WORKSPACE,
        "chain_head": verdict["chain_head"],
        "chap_verify_chain": verdict,
        "entries": send("audit.read")["entries"],
    }
    return log, {"approved": approved, "rejected": rejected}


def entry_for(log: dict, method: str) -> dict:
    (entry,) = [e for e in log["entries"] if e["envelope"].get("method") == method]
    return entry


def jcs_digest(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def trust_record(reference: dict, key, iat: int) -> dict:
    record = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": iat,
        "subject": "spiffe://trust.example.org/agent/refund-bot",
        "model": {"provider": "example", "model_id": "example-model"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "confidential",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "cnf": {"jwk": key_to_jwk(key)},
        "references": [reference],
    }
    return sign_record(record, key)


def main() -> None:
    log, _ = run_chap()
    approve = entry_for(log, "decide.approve")
    reject = entry_for(log, "decide.reject")

    # CHAP canonicalises with its own implementation and TRACE with rfc8785. The
    # digest a record carries is only portable if the two agree on these envelopes.
    for entry in (approve, reject):
        if content_hash(entry["envelope"]) != jcs_digest(entry["envelope"]):
            sys.exit(f"canonicalisation disagrees on seq {entry['seq']}")

    altered = copy.deepcopy(log)
    entry_for(altered, "decide.approve")["envelope"]["params"]["comment"] = (
        "Approved after escalation.")
    altered["altered_after_export"] = (
        "decide.approve params.comment changed; chain_head left as exported")

    def ref(seq: int, digest: str) -> dict:
        return {"rel": "approval-outcome", "id": f"audit/{seq}", "resolver": RESOLVER,
                "retention": "P1Y", "digest": digest}

    key = generate_key()
    iat = int(time.time())
    missing_seq = max(e["seq"] for e in log["entries"]) + 50
    approve_ref = ref(approve["seq"], content_hash(approve["envelope"]))
    cases = [
        ("01-approval-confirmed.json", approve_ref,
         "chap-audit-log.json",
         {"reference_resolves": True, "digest_matches": True, "decision": "decide.approve",
          "chain_replays": True, "verdict": "approval-confirmed"}),
        ("02-approval-altered-after-issue.json", approve_ref,
         "chap-audit-log-altered.json",
         {"reference_resolves": True, "digest_matches": False, "decision": "decide.approve",
          "chain_replays": False, "verdict": "approval-contradicted"}),
        ("03-decision-is-a-rejection.json", ref(reject["seq"], content_hash(reject["envelope"])),
         "chap-audit-log.json",
         {"reference_resolves": True, "digest_matches": True, "decision": "decide.reject",
          "chain_replays": True, "verdict": "not-an-approval"}),
        ("04-reference-unresolvable.json", ref(missing_seq, content_hash(approve["envelope"])),
         "chap-audit-log.json",
         {"reference_resolves": False, "digest_matches": None, "decision": None,
          "chain_replays": True, "verdict": "approval-unconfirmed"}),
    ]

    def write(name: str, obj: object) -> None:
        (HERE / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8", newline="\n")

    for stale in HERE.glob("*.json"):
        stale.unlink()
    write("chap-audit-log.json", log)
    write("chap-audit-log-altered.json", altered)
    expected = {"trace_signer_jwk": key_to_jwk(key), "chap_version": CHAP_VERSION,
                "resolver": RESOLVER, "cases": {}}
    for name, reference, log_name, outcome in cases:
        record = trust_record(reference, key, iat)
        # verify_record raises on every rejection, so reaching write() means it verified.
        verify_record(record, key_to_jwk(key), max_age_seconds=None)
        write(name, record)
        expected["cases"][name] = {"log": log_name, "trace_record_verifies": True, **outcome}
    write("expected.json", expected)
    print(f"wrote {len(cases)} records, 2 logs and expected.json "
          f"from chap-coordinator {CHAP_VERSION}")


if __name__ == "__main__":
    main()
