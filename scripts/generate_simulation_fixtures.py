"""Deterministic synthetic Phase 2B inputs; independent, literal outcome oracle.

Phase 2A is used only for canonical case/result/action bindings. This generator
does not import or run any simulation implementation or infer expected outcomes.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ir_lab.contracts import document
from ir_lab.evidence import canonical_json, case_from_file, validate_artifacts
from ir_lab.events import verify_event_references
from ir_lab.triage import evaluate

CASE_PATH = REPO / "fixtures" / "ir_cases" / "response_case.json"
PLAN_DIR = REPO / "fixtures" / "ir_simulations"


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def log(rows: list[dict]) -> bytes:
    return b"".join((json.dumps(row, sort_keys=True, separators=(",", ":"),
                               allow_nan=False) + "\n").encode("utf-8") for row in rows)


def bind(plan: dict, action: dict) -> str:
    """Independent implementation of the documented consistency digest."""
    binding = copy.deepcopy(action)
    binding["target_ids"] = sorted(binding["target_ids"])
    binding["supporting_observation_ids"] = sorted(binding["supporting_observation_ids"])
    subject = {"case_id": plan["case_id"], "case_sha256": plan["case_sha256"],
               "result_sha256": plan["result_sha256"], "action": binding}
    return hashlib.sha256(encoded(subject)).hexdigest()


# These are hand-authored assertions, not computed by a response evaluator.
EXPECTED = {
    "success": {"states": {
        "investigate_signins": "verified_effective_synthetic",
        "quarantine_message": "verified_effective_synthetic",
        "review_authentication_methods": "verified_effective_synthetic",
        "revoke_sessions": "verified_effective_synthetic",
        "scope_recipients": "verified_effective_synthetic"},
        "simulation_closure_accepted": True},
    "denied": {"states": {
        "investigate_signins": "denied", "quarantine_message": "denied",
        "review_authentication_methods": "denied", "revoke_sessions": "denied",
        "scope_recipients": "denied"}, "simulation_closure_accepted": False},
    "expired": {"controlled_rejection": True, "cli_exit_code": 2},
    "partial": {"states": {
        "investigate_signins": "verified_effective_synthetic",
        "quarantine_message": "verified_effective_synthetic",
        "review_authentication_methods": "verified_effective_synthetic",
        "revoke_sessions": "failed", "scope_recipients": "verified_effective_synthetic"},
        "simulation_closure_accepted": False},
    "misleading_success": {"states": {
        "investigate_signins": "verified_effective_synthetic",
        "quarantine_message": "verified_effective_synthetic",
        "review_authentication_methods": "verified_effective_synthetic",
        "revoke_sessions": "failed", "scope_recipients": "verified_effective_synthetic"},
        "simulation_closure_accepted": False},
    "missing_approval": {"states": {
        "investigate_signins": "recommended", "quarantine_message": "recommended",
        "review_authentication_methods": "recommended", "revoke_sessions": "recommended",
        "scope_recipients": "recommended"}, "simulation_closure_accepted": False},
}

OBSERVATIONS = {
    "success": {"investigate_signins": "review_complete", "quarantine_message": "quarantined",
                "review_authentication_methods": "trusted_methods_only", "revoke_sessions": "no_active_sessions",
                "scope_recipients": "scope_complete"},
    "partial": {"investigate_signins": "review_complete", "quarantine_message": "quarantined",
                "review_authentication_methods": "trusted_methods_only", "revoke_sessions": "active_session",
                "scope_recipients": "scope_complete"},
    "misleading_success": {"investigate_signins": "review_complete", "quarantine_message": "quarantined",
                           "review_authentication_methods": "trusted_methods_only", "revoke_sessions": "active_session",
                           "scope_recipients": "scope_complete"},
}


def create() -> dict[Path, bytes]:
    case = copy.deepcopy(case_from_file(REPO / "fixtures" / "ir_cases" / "positive.json"))
    case["case_id"] = "LAB-IR-RESPONSE"
    case["actions"].append({"id": "action_quarantine", "kind": "quarantine_message",
                            "target_ids": ["user_alex"], "state": "recommended",
                            "reason": "Synthetic delivered invoice lure justifies proposing scoped message quarantine; no action executed."})
    document(case)
    result = evaluate(case, validate_artifacts(case, CASE_PATH))
    result["correlated_event_references"] = verify_event_references(case, CASE_PATH)
    actions = [{"action_id": a["id"], "kind": a["kind"], "target_ids": sorted(a["target_ids"]),
                "supporting_observation_ids": sorted(a["supporting_observation_ids"])}
               for a in result["proposed_actions"]]
    files = {CASE_PATH: encoded(case),
             REPO / "tests" / "expected" / "simulation_expectations.json": encoded(EXPECTED)}
    for name in ("success", "denied", "partial", "expired", "misleading_success", "missing_approval"):
        completed = name in OBSERVATIONS
        attempts = completed or name == "expired"
        plan = {"schema_version": "ir-simulation/1.0", "simulation_id": "SIM-" + name.upper().replace("_", "-"),
                "synthetic": True, "case_id": case["case_id"],
                "case_sha256": hashlib.sha256(canonical_json(case)).hexdigest(),
                "result_sha256": hashlib.sha256(canonical_json(result)).hexdigest(),
                "as_of": "2026-10-05T10:30:00Z", "actors": [
                    {"id": "sim_approver", "display_name": "Fictional approver", "role": "approver", "synthetic": True},
                    {"id": "sim_operator", "display_name": "Fictional operator", "role": "operator", "synthetic": True},
                    {"id": "sim_verifier", "display_name": "Fictional verifier", "role": "verifier", "synthetic": True},
                    {"id": "sim_reviewer", "display_name": "Fictional reviewer", "role": "reviewer", "synthetic": True}],
                "actions": copy.deepcopy(actions), "evidence": [], "events": [],
                "recovery": {"observation_start": "2026-10-05T09:20:00Z",
                             "observation_end": "2026-10-05T10:20:00Z", "monitoring_refs": [],
                             "residual_risks": ["All exercise observations and actors are fictional; production recovery remains unverified."],
                             "acceptance": {"reviewer_id": "sim_reviewer", "at": "2026-10-05T10:25:00Z",
                                            "rationale": "Fictional reviewer requests closure only when independent synthetic evidence satisfies all gates.",
                                            "residual_risk_acknowledged": True, "closure_requested": True} if completed else None}}
        acknowledgements: list[dict] = []
        verifications: list[dict] = []
        monitoring: list[dict] = []
        if name != "missing_approval":
            for index, action in enumerate(actions, 1):
                plan["events"].append({"id": f"approval_{index}", "at": "2026-10-05T09:00:00Z",
                    "action_id": action["action_id"], "target_ids": action["target_ids"],
                    "previous_state": "recommended", "new_state": "denied" if name == "denied" else "approved_simulated",
                    "kind": "approval", "reason": "Fictional exercise decision; this conveys no operational authority.",
                    "evidence_refs": [], "approver_id": "sim_approver",
                    "expires_at": "2026-10-05T09:04:00Z" if name == "expired" else "2026-10-05T10:00:00Z",
                    "binding_sha256": bind(plan, action)})
        if attempts:
            for index, action in enumerate(actions, 1):
                acknowledgements.append({"record_id": f"ack_{index}", "record_type": "acknowledgement",
                    "action_id": action["action_id"], "kind": action["kind"], "target_ids": action["target_ids"],
                    "at": "2026-10-05T09:05:00Z", "operator_id": "sim_operator",
                    "acknowledged": not (name == "partial" and action["kind"] == "revoke_sessions")})
                plan["events"].append({"id": f"attempt_{index}", "at": "2026-10-05T09:05:00Z",
                    "action_id": action["action_id"], "target_ids": action["target_ids"],
                    "previous_state": "approved_simulated", "new_state": "attempted_simulated", "kind": "attempt",
                    "reason": "Synthetic operator records a local exercise attempt; no external service invoked.",
                    "operator_id": "sim_operator", "evidence_refs": [{"evidence_id": "sim_acknowledgements", "record_id": f"ack_{index}"}]})
        if completed:
            for index, action in enumerate(actions, 1):
                verifications.append({"record_id": f"verify_{index}", "record_type": "verification",
                    "action_id": action["action_id"], "kind": action["kind"], "target_id": "user_alex",
                    "at": "2026-10-05T09:15:00Z", "verifier_id": "sim_verifier",
                    "observed_state": OBSERVATIONS[name][action["kind"]],
                    "window_start": "2026-10-05T09:05:00Z", "window_end": "2026-10-05T09:15:00Z"})
                plan["events"].append({"id": f"verification_{index}", "at": "2026-10-05T09:15:00Z",
                    "action_id": action["action_id"], "target_ids": action["target_ids"],
                    "previous_state": "attempted_simulated", "new_state": EXPECTED[name]["states"][action["kind"]],
                    "kind": "verification", "reason": "Hand-authored independent synthetic observation determines the claimed transition.",
                    "evidence_refs": [{"evidence_id": "sim_verifications", "record_id": f"verify_{index}"}]})
                monitoring.append({"record_id": f"monitor_{index}", "record_type": "monitoring",
                    "action_id": action["action_id"], "kind": action["kind"], "target_id": "user_alex",
                    "at": "2026-10-05T10:20:00Z", "verifier_id": "sim_verifier", "observed_state": "clear",
                    "window_start": "2026-10-05T09:20:00Z", "window_end": "2026-10-05T10:20:00Z"})
                plan["recovery"]["monitoring_refs"].append({"evidence_id": "sim_monitoring", "record_id": f"monitor_{index}"})
        for label, rows, collected in (("acknowledgements", acknowledgements, "2026-10-05T09:06:00Z"),
                                       ("verifications", verifications, "2026-10-05T09:16:00Z"),
                                       ("monitoring", monitoring, "2026-10-05T10:21:00Z")):
            relative = f"artifacts/{name}_{label}.jsonl"
            raw = log(rows)
            files[PLAN_DIR / relative] = raw
            plan["evidence"].append({"id": "sim_" + label, "path": relative, "kind": "original",
                "sha256": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw),
                "source": "Hand-authored fictional exercise " + label, "collected_at": collected})
        files[PLAN_DIR / (name + ".json")] = encoded(plan)
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true", help="Read-only byte-for-byte comparison, including under python -O")
    modes.add_argument("--write", action="store_true", help="Create new files only; refuse if any destination exists")
    args = parser.parse_args()
    files = create()
    if args.write:
        # Preflight the complete set before creating any file. Exclusive creation
        # additionally prevents clobbering a destination introduced concurrently.
        for path in files:
            if path.exists() or path.is_symlink():
                raise SystemExit(f"Refusing to overwrite existing fixture: {path.relative_to(REPO)}")
        for path, raw in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
    else:
        for path, expected in files.items():
            try:
                observed = path.read_bytes()
            except OSError as exc:
                raise SystemExit(f"Fixture unavailable: {path.relative_to(REPO)}") from exc
            if observed != expected:
                raise SystemExit(f"Fixture drift: {path.relative_to(REPO)}")
    print(f"{'CREATED' if args.write else 'PASS'} {len(files)} deterministic synthetic simulation fixtures")


if __name__ == "__main__":
    main()
