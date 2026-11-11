"""Independent Phase 2B behavioral acceptance and hostile-input regressions.

Expected outcomes are authored in tests/expected, never obtained from replay.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ir_lab.contracts import CaseError, document
from ir_lab.evidence import canonical_json, case_from_file, validate_artifacts
from ir_lab.events import verify_event_references
from ir_lab.triage import evaluate
from ir_lab import simulation_engine
from ir_lab.simulation_contracts import load_plan, validate_plan
from ir_lab.simulation_verification import load_evidence
from ir_lab.simulation_report import markdown

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "fixtures" / "ir_cases"
PLANS = ROOT / "fixtures" / "ir_simulations"
GOLD_PATH = ROOT / "tests" / "expected" / "simulation_expectations.json"


def independently_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def independently_bind(plan: dict, action: dict) -> str:
    binding = copy.deepcopy(action)
    for key in ("target_ids", "supporting_observation_ids"):
        binding[key] = sorted(binding[key])
    return independently_digest({key: plan[key] for key in
                                 ("case_id", "case_sha256", "result_sha256")} |
                                {"action": binding})


def phase2a(path: Path) -> tuple[dict, dict]:
    case = case_from_file(path)
    result = evaluate(case, validate_artifacts(case, path))
    result["correlated_event_references"] = verify_event_references(case, path)
    return case, result


def execute(name: str = "success", *, case_path: Path | None = None,
            plan_path: Path | None = None) -> dict:
    case, result = phase2a(case_path or CASES / "response_case.json")
    path = plan_path or PLANS / (name + ".json")
    plan = load_plan(path, case, result)
    artifacts, records = load_evidence(plan, path)
    return simulation_engine.replay(plan, result, records, artifacts)


def projection(result: dict) -> dict:
    return {"states": {a["kind"]: a["state"] for a in result["actions"]},
            "simulation_closure_accepted": result["recovery"]["simulation_closure_accepted"]}


@contextlib.contextmanager
def copied_inputs(name: str = "success"):
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        shutil.copytree(CASES, folder / "ir_cases")
        shutil.copytree(PLANS, folder / "ir_simulations")
        case_path = folder / "ir_cases" / "response_case.json"
        plan_path = folder / "ir_simulations" / (name + ".json")
        yield case_path, plan_path, json.loads(plan_path.read_text(encoding="utf-8"))


def save_plan(path: Path, plan: dict) -> None:
    path.write_bytes(canonical_json(plan))


def rewrite_records(path: Path, plan: dict, suffix: str, transform) -> None:
    descriptor = next(e for e in plan["evidence"] if e["path"].endswith(suffix + ".jsonl"))
    location = path.parent / descriptor["path"]
    records = [json.loads(row) for row in location.read_text(encoding="utf-8").splitlines()]
    transform(records)
    raw = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
                   for row in records)
    location.write_bytes(raw)
    descriptor["sha256"] = hashlib.sha256(raw).hexdigest()
    descriptor["byte_length"] = len(raw)
    save_plan(path, plan)


class IndependentSimulationExpectations(unittest.TestCase):
    def assert_oracle(self, name: str) -> dict:
        expected = json.loads(GOLD_PATH.read_text(encoding="utf-8"))[name]
        result = execute(name)
        self.assertEqual(projection(result), expected)
        return result

    def test_independent_scenario_outcomes(self):
        for name in ("success", "denied", "partial", "misleading_success", "missing_approval"):
            with self.subTest(name=name):
                self.assert_oracle(name)

    def test_expired_approval_rejects_without_result(self):
        expected = json.loads(GOLD_PATH.read_text(encoding="utf-8"))["expired"]
        self.assertTrue(expected["controlled_rejection"])
        with self.assertRaises(CaseError):
            execute("expired")

    def test_all_five_actual_proposals_have_exact_bindings(self):
        case, result = phase2a(CASES / "response_case.json")
        plan = load_plan(PLANS / "success.json", case, result)
        actual = [{"action_id": a["id"], "kind": a["kind"],
                   "target_ids": sorted(a["target_ids"]),
                   "supporting_observation_ids": sorted(a["supporting_observation_ids"])}
                  for a in result["proposed_actions"]]
        self.assertEqual(plan["actions"], actual)
        self.assertEqual(len(actual), 5)
        self.assertEqual(plan["case_sha256"], independently_digest(case))
        self.assertEqual(plan["result_sha256"], independently_digest(result))
        by_id = {a["action_id"]: a for a in actual}
        for event in plan["events"]:
            if event["kind"] == "approval":
                self.assertEqual(event["binding_sha256"], independently_bind(plan, by_id[event["action_id"]]))

    def test_success_never_changes_phase2a_triage_or_source_bytes(self):
        inputs = [*CASES.rglob("*"), *PLANS.rglob("*")]
        before = {p: p.read_bytes() for p in inputs if p.is_file()}
        _, original = phase2a(CASES / "response_case.json")
        result = self.assert_oracle("success")
        self.assertEqual(result["phase2a_triage"], original["triage"])
        self.assertFalse(result["phase2a_triage"]["incident_closure_verified"])
        self.assertEqual(result["phase2a_triage"]["recovery_state"], "unverified")
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_denied_has_no_attempt_events(self):
        result = self.assert_oracle("denied")
        self.assertFalse(any(e["kind"] == "attempt" for e in result["events"]))

    def test_acknowledgement_true_cannot_override_active_session(self):
        self.assert_oracle("misleading_success")
        path = PLANS / "artifacts" / "misleading_success_acknowledgements.jsonl"
        self.assertTrue(all(json.loads(row)["acknowledged"] for row in path.read_text().splitlines()))

    def test_repeated_json_and_markdown_are_byte_identical(self):
        first = execute()
        for _ in range(3):
            again = execute()
            self.assertEqual(canonical_json(first), canonical_json(again))
            self.assertEqual(markdown(first), markdown(again))

    def test_phase2a_case_bytes_and_complete_results_keep_known_hashes(self):
        expected = {
            "positive": ("9ef1185ca5699d87341d0c22c3dbb7d1188abca9cee4ca3442dfedbbb734bd70",
                         "9ff7a9dea356cc2082e06a158cd8fa67bc96ce8727bf692ad5d41be6a7380f08"),
            "benign": ("f1aa4558d5fb696102bd1bc60cdb9e71dc88da0a9efc919d34c46d961d6b5b9c",
                       "02ccffe8c1be0d01ada1dc04691f8cc21569f7a1c9ef0b80311000f59f4ca8f0"),
            "incomplete": ("ba1a31a66b3c04dfeb77f42ed0e9c4a63fd1c117d249216418225d7dc615a45b",
                           "deea1c6292fe1aa3b588da35a0f81adbae553848969305cf54b4397639244b92")}
        for name, (case_hash, result_hash) in expected.items():
            with self.subTest(name=name):
                path = CASES / (name + ".json")
                _, result = phase2a(path)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), case_hash)
                self.assertEqual(independently_digest(result), result_hash)

    def test_actual_faulty_replay_is_detected_by_normal_independent_oracle(self):
        genuine = simulation_engine.replay

        def promote_failed_to_closed(*args, **kwargs):
            output = genuine(*args, **kwargs)
            output["recovery"]["simulation_closure_accepted"] = True
            return output

        with mock.patch.object(simulation_engine, "replay", side_effect=promote_failed_to_closed):
            with self.assertRaises(AssertionError):
                self.assert_oracle("misleading_success")
        self.assert_oracle("misleading_success")

    def test_no_network_or_process_in_full_simulation_pipeline(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")), \
             mock.patch.object(os, "system", side_effect=AssertionError("shell forbidden")):
            self.assert_oracle("success")


class SimulationContractFailures(unittest.TestCase):
    def reject_change(self, change, name="success"):
        with copied_inputs(name) as (case_path, path, plan):
            change(plan)
            save_plan(path, plan)
            with self.assertRaises(CaseError):
                execute(case_path=case_path, plan_path=path)

    def test_case_id_case_digest_and_result_digest_drift(self):
        for key, value in (("case_id", "LAB-WRONG"), ("case_sha256", "0" * 64),
                           ("result_sha256", "1" * 64)):
            with self.subTest(key=key):
                self.reject_change(lambda p: p.update({key: value}))

    def test_changed_valid_case_rejects_stale_plan(self):
        with copied_inputs() as (case_path, path, plan):
            case = case_from_file(case_path)
            case["observations"][0]["description"] += " Case input changed."
            case_path.write_bytes(canonical_json(document(case)))
            with self.assertRaises(CaseError):
                execute(case_path=case_path, plan_path=path)

    def test_incomplete_or_duplicate_actual_proposals(self):
        self.reject_change(lambda p: p["actions"].pop())
        self.reject_change(lambda p: p["actions"].append(copy.deepcopy(p["actions"][0])))

    def test_action_id_kind_targets_and_support_cannot_drift(self):
        for key, value in (("action_id", "invented_action"), ("kind", "revoke_sessions"),
                           ("target_ids", ["user_unknown"]),
                           ("supporting_observation_ids", ["obs_delivery"])):
            with self.subTest(key=key):
                self.reject_change(lambda p: p["actions"][0].update({key: value}))

    def test_approval_digest_and_actor_roles_enforced(self):
        self.reject_change(lambda p: p["events"][0].update(binding_sha256="0" * 64))
        self.reject_change(lambda p: p["events"][0].update(approver_id="sim_operator"))
        self.reject_change(lambda p: p["actors"][0].update(synthetic=False))

    def test_unsupported_version_unknown_fields_and_non_synthetic_reject(self):
        for extra in ({"schema_version": "ir-simulation/999"}, {"execute_live": True}, {"synthetic": False}):
            self.reject_change(lambda p: p.update(extra))

    def test_direct_verified_transition_without_attempt_rejects(self):
        self.reject_change(lambda p: p["events"][0].update(new_state="verified_effective_synthetic"))

    def test_attempt_without_approval_or_after_denial_rejects(self):
        self.reject_change(lambda p: p["events"].pop(0))
        def deny(plan):
            plan["events"][0]["new_state"] = "denied"
        self.reject_change(deny)

    def test_duplicate_event_and_conflicting_approval_reject(self):
        self.reject_change(lambda p: p["events"].insert(1, copy.deepcopy(p["events"][0])))
        def conflicting(plan):
            event = copy.deepcopy(plan["events"][0])
            event.update(id="conflicting_approval", new_state="denied")
            plan["events"].insert(1, event)
        self.reject_change(conflicting)

    def test_input_order_cannot_be_sorted_to_hide_replay_violation(self):
        def disorder(plan):
            plan["events"][0], plan["events"][5] = plan["events"][5], plan["events"][0]
        self.reject_change(disorder)
        def reversed_time(plan):
            plan["events"][1]["at"] = "2026-10-05T08:59:00Z"
        self.reject_change(reversed_time)

    def test_expiry_is_exclusive_at_attempt(self):
        self.reject_change(lambda p: p["events"][0].update(expires_at="2026-10-05T09:05:00Z"))

    def test_attempt_scope_and_operator_cannot_drift(self):
        self.reject_change(lambda p: p["events"][5].update(target_ids=["user_unknown"]))
        self.reject_change(lambda p: p["events"][5].update(operator_id="sim_approver"))

    def test_self_declared_verified_state_cannot_override_observations(self):
        def promote(plan):
            for event in plan["events"]:
                if event["kind"] == "verification" and event["action_id"] == "action_revoke":
                    event["new_state"] = "verified_effective_synthetic"
        self.reject_change(promote, "misleading_success")

    def test_acknowledgement_cannot_be_reused_as_verification(self):
        def substitute(plan):
            plan["events"][10]["evidence_refs"] = copy.deepcopy(plan["events"][5]["evidence_refs"])
        self.reject_change(substitute)

    def test_evidence_bytes_length_and_missing_files_reject(self):
        for defect in ("bytes", "length", "missing"):
            with self.subTest(defect=defect), copied_inputs() as (case_path, path, plan):
                artifact = path.parent / plan["evidence"][0]["path"]
                if defect == "bytes":
                    raw = artifact.read_bytes()
                    artifact.write_bytes(raw.replace(b"sim_operator", b"bad_operator"))
                elif defect == "length":
                    plan["evidence"][0]["byte_length"] += 1
                    save_plan(path, plan)
                else:
                    artifact.unlink()
                with self.assertRaises(CaseError):
                    execute(case_path=case_path, plan_path=path)

    def test_missing_and_duplicate_record_references_reject(self):
        self.reject_change(lambda p: p["events"][5]["evidence_refs"][0].update(record_id="missing_row"))
        self.reject_change(lambda p: p["events"][10]["evidence_refs"].append(
            copy.deepcopy(p["events"][10]["evidence_refs"][0])))

    def test_duplicate_record_id_and_conflicting_target_rows_reject(self):
        for duplicate_id in (True, False):
            with self.subTest(duplicate_id=duplicate_id), copied_inputs() as (case_path, path, plan):
                def add(records):
                    row = copy.deepcopy(records[0])
                    if not duplicate_id:
                        row["record_id"] = "conflicting_row"
                        row["observed_state"] = "unauthorized_access_present"
                    records.append(row)
                rewrite_records(path, plan, "verifications", add)
                if not duplicate_id:
                    plan["events"][10]["evidence_refs"].append({
                        "evidence_id": "sim_verifications", "record_id": "conflicting_row"})
                    save_plan(path, plan)
                with self.assertRaises(CaseError):
                    execute(case_path=case_path, plan_path=path)

    def test_wrong_verifier_target_kind_and_time_reject_even_with_fresh_hash(self):
        for key, value in (("verifier_id", "sim_operator"), ("target_id", "user_unknown"),
                           ("kind", "revoke_sessions"),
                           ("window_start", "2026-10-05T09:00:00Z"),
                           ("window_end", "2026-10-05T09:16:00Z")):
            with self.subTest(key=key), copied_inputs() as (case_path, path, plan):
                rewrite_records(path, plan, "verifications", lambda rows: rows[0].update({key: value}))
                with self.assertRaises(CaseError):
                    execute(case_path=case_path, plan_path=path)

    def test_duplicate_json_key_unknown_record_shape_and_unsafe_path_reject(self):
        for mutation in ("duplicate_key", "unknown_key", "wrong_type"):
            with self.subTest(mutation=mutation), copied_inputs() as (case_path, path, plan):
                descriptor = next(e for e in plan["evidence"] if e["id"] == "sim_verifications")
                artifact = path.parent / descriptor["path"]
                raw = artifact.read_bytes()
                if mutation == "duplicate_key":
                    raw = raw.replace(b'{"action_id":', b'{"record_type":"verification","action_id":', 1)
                elif mutation == "unknown_key":
                    raw = raw.replace(b'{"action_id":', b'{"trusted":true,"action_id":', 1)
                else:
                    raw = raw.replace(b'"observed_state":"review_complete"', b'"observed_state":["review_complete"]', 1)
                artifact.write_bytes(raw)
                descriptor.update(sha256=hashlib.sha256(raw).hexdigest(), byte_length=len(raw))
                save_plan(path, plan)
                with self.assertRaises(CaseError):
                    execute(case_path=case_path, plan_path=path)
        for unsafe in ("../escape.jsonl", "C:\\private.jsonl", "/absolute.jsonl"):
            self.reject_change(lambda p: p["evidence"][0].update(path=unsafe))

    def test_verification_before_attempt_and_future_evidence_reject(self):
        self.reject_change(lambda p: p["events"][10].update(at="2026-10-05T09:04:00Z"))
        self.reject_change(lambda p: p.update(as_of="2026-10-05T09:14:00Z"))

    def test_terminal_state_cannot_be_retried_or_overwritten(self):
        def retry(plan):
            event = copy.deepcopy(plan["events"][5])
            event.update(id="retry_event", at="2026-10-05T09:16:00Z",
                         previous_state="verified_effective_synthetic")
            plan["events"].append(event)
        self.reject_change(retry)


class RecoveryGates(unittest.TestCase):
    def altered_result(self, change) -> dict:
        with copied_inputs() as (case_path, path, plan):
            change(plan)
            save_plan(path, plan)
            return execute(case_path=case_path, plan_path=path)

    def test_no_acceptance_no_risk_ack_and_no_closure_request_block(self):
        changes = [lambda p: p["recovery"].update(acceptance=None),
                   lambda p: p["recovery"]["acceptance"].update(residual_risk_acknowledged=False),
                   lambda p: p["recovery"]["acceptance"].update(closure_requested=False)]
        for change in changes:
            result = self.altered_result(change)
            self.assertFalse(result["recovery"]["simulation_closure_accepted"])
            self.assertTrue(result["recovery"]["blocking_reasons"])

    def test_premature_acceptance_cannot_close(self):
        with copied_inputs() as (case_path, path, plan):
            plan["recovery"]["acceptance"]["at"] = "2026-10-05T09:10:00Z"
            save_plan(path, plan)
            try:
                result = execute(case_path=case_path, plan_path=path)
            except CaseError:
                return
            self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_acceptance_before_artifact_collection_cannot_close(self):
        with copied_inputs() as (case_path, path, plan):
            plan["recovery"]["acceptance"]["at"] = "2026-10-05T10:20:30Z"
            save_plan(path, plan)
            try:
                result = execute(case_path=case_path, plan_path=path)
            except CaseError:
                return
            self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_monitoring_window_before_last_verification_cannot_close(self):
        with copied_inputs() as (case_path, path, plan):
            plan["recovery"]["observation_start"] = "2026-10-05T09:10:00Z"
            rewrite_records(path, plan, "monitoring", lambda rows: [row.update(
                window_start="2026-10-05T09:10:00Z") for row in rows])
            try:
                result = execute(case_path=case_path, plan_path=path)
            except CaseError:
                return
            self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_incomplete_monitoring_window_blocks_closure(self):
        with copied_inputs() as (case_path, path, plan):
            rewrite_records(path, plan, "monitoring", lambda rows: rows[0].update(
                window_start="2026-10-05T09:21:00Z"))
            self.assertFalse(execute(case_path=case_path, plan_path=path)["recovery"]["simulation_closure_accepted"])

    def test_missing_adverse_unknown_monitoring_blocks_closure(self):
        for defect in ("missing", "adverse", "unknown"):
            with self.subTest(defect=defect), copied_inputs() as (case_path, path, plan):
                if defect == "missing":
                    plan["recovery"]["monitoring_refs"].pop()
                    save_plan(path, plan)
                else:
                    rewrite_records(path, plan, "monitoring", lambda rows: rows[0].update(observed_state=defect))
                result = execute(case_path=case_path, plan_path=path)
                self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_window_not_elapsed_cannot_close(self):
        result = self.altered_result(lambda p: p["recovery"].update(observation_end="2026-10-05T10:31:00Z"))
        self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_unknown_verification_is_unverified_and_prevents_closure(self):
        with copied_inputs() as (case_path, path, plan):
            plan["events"][10]["new_state"] = "unverified"
            affected_action = plan["events"][10]["action_id"]
            rewrite_records(path, plan, "verifications", lambda rows: rows[0].update(observed_state="unknown"))
            result = execute(case_path=case_path, plan_path=path)
            self.assertEqual(next(a["state"] for a in result["actions"]
                                  if a["action_id"] == affected_action), "unverified")
            self.assertTrue(all(a["state"] == "verified_effective_synthetic"
                                for a in result["actions"] if a["action_id"] != affected_action))
            self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_one_effective_target_cannot_clear_a_second_unobserved_target(self):
        with copied_inputs() as (case_path, path, plan):
            case = case_from_file(case_path)
            case["entities"].append({"id": "user_bailey", "kind": "user", "value": "bailey@example.test"})
            case["observations"].append({"id": "obs_second_report", "kind": "credential_submission_report",
                "source": "reported", "entity_ids": ["user_bailey"], "evidence_ids": [],
                "occurred_at": "2026-10-01T13:06:00Z", "description": "A second fictional user reports credential submission."})
            next(a for a in case["actions"] if a["id"] == "action_revoke")["target_ids"].append("user_bailey")
            case_path.write_bytes(canonical_json(document(case)))
            _, case_result = phase2a(case_path)
            plan["case_sha256"] = independently_digest(case)
            plan["result_sha256"] = independently_digest(case_result)
            plan["actions"] = [{"action_id": a["id"], "kind": a["kind"],
                                "target_ids": sorted(a["target_ids"]),
                                "supporting_observation_ids": sorted(a["supporting_observation_ids"])}
                               for a in case_result["proposed_actions"]]
            actions = {a["action_id"]: a for a in plan["actions"]}
            for event in plan["events"]:
                action = actions[event["action_id"]]
                event["target_ids"] = action["target_ids"]
                if event["kind"] == "approval":
                    event["binding_sha256"] = independently_bind(plan, action)
                if event["kind"] == "verification" and event["action_id"] == "action_revoke":
                    event["new_state"] = "partially_effective"
            rewrite_records(path, plan, "acknowledgements", lambda rows: [row.update(
                target_ids=actions[row["action_id"]]["target_ids"]) for row in rows])
            def expand_verification(rows):
                for row in list(rows):
                    if "user_bailey" not in actions[row["action_id"]]["target_ids"] or row["action_id"] == "action_revoke":
                        continue
                    added = copy.deepcopy(row)
                    added.update(record_id=row["record_id"] + "_bailey", target_id="user_bailey")
                    rows.append(added)
                    event = next(e for e in plan["events"] if e["kind"] == "verification" and e["action_id"] == row["action_id"])
                    event["evidence_refs"].append({"evidence_id": "sim_verifications", "record_id": added["record_id"]})
            rewrite_records(path, plan, "verifications", expand_verification)
            def expand_monitoring(rows):
                for row in list(rows):
                    if "user_bailey" not in actions[row["action_id"]]["target_ids"]:
                        continue
                    added = copy.deepcopy(row)
                    added.update(record_id=row["record_id"] + "_bailey", target_id="user_bailey")
                    rows.append(added)
                    plan["recovery"]["monitoring_refs"].append({"evidence_id": "sim_monitoring", "record_id": added["record_id"]})
            rewrite_records(path, plan, "monitoring", expand_monitoring)
            result = execute(case_path=case_path, plan_path=path)
            revoke = next(a for a in result["actions"] if a["kind"] == "revoke_sessions")
            self.assertEqual(revoke["state"], "partially_effective")
            self.assertFalse(result["recovery"]["simulation_closure_accepted"])


class SimulationCLI(unittest.TestCase):
    def cli(self, *args, optimize=False):
        command = [sys.executable, "-B"] + (["-O"] if optimize else [])
        return subprocess.run(command + ["-m", "ir_lab", *map(str, args)], cwd=ROOT,
                              capture_output=True, check=False)

    def test_validate_and_repeat_simulate_json(self):
        args = [CASES / "response_case.json", "--plan", PLANS / "success.json"]
        validated = self.cli("simulation-validate", *args)
        self.assertEqual(validated.returncode, 0, validated.stderr)
        first = self.cli("simulate", *args)
        second = self.cli("simulate", *args, optimize=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout), execute())

    def test_expired_cli_returns_controlled_error_and_empty_stdout(self):
        expected = json.loads(GOLD_PATH.read_text(encoding="utf-8"))["expired"]
        for command in ("simulation-validate", "simulate"):
            proc = self.cli(command, CASES / "response_case.json", "--plan", PLANS / "expired.json")
            self.assertEqual(proc.returncode, expected["cli_exit_code"], proc.stderr)
            self.assertEqual(proc.stdout, b"")

    def test_json_markdown_output_requires_new_explicit_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            common = [CASES / "response_case.json", "--plan", PLANS / "success.json"]
            for fmt, raw in (("json", canonical_json(execute())), ("markdown", markdown(execute()))):
                path = Path(temp) / ("simulation." + fmt)
                proc = self.cli("simulation-render", *common, "--format", fmt, "--output", path)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(path.read_bytes(), raw)
                again = self.cli("simulation-render", *common, "--format", fmt, "--output", path)
                self.assertEqual(again.returncode, 2)
                self.assertEqual(path.read_bytes(), raw)
            proc = self.cli("simulation-render", *common, "--format", "json")
            self.assertEqual(proc.returncode, 2)

    def test_output_cannot_alias_case_plan_or_any_artifact(self):
        for path in (CASES / "response_case.json", PLANS / "success.json",
                     PLANS / "artifacts" / "success_acknowledgements.jsonl"):
            before = path.read_bytes()
            proc = self.cli("simulation-render", CASES / "response_case.json", "--plan",
                            PLANS / "success.json", "--format", "json", "--output", path)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(path.read_bytes(), before)

    def test_generator_read_only_check_and_no_clobber_in_optimized_python(self):
        before = {p: p.read_bytes() for p in [*PLANS.rglob("*"), CASES / "response_case.json", GOLD_PATH] if p.is_file()}
        for optimized in (False, True):
            command = [sys.executable, "-B"] + (["-O"] if optimized else [])
            checked = subprocess.run(command + ["scripts/generate_simulation_fixtures.py", "--check"],
                                     cwd=ROOT, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            refused = subprocess.run(command + ["scripts/generate_simulation_fixtures.py", "--write"],
                                     cwd=ROOT, capture_output=True)
            self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_optimized_generator_check_actually_detects_corrupt_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            shutil.copytree(ROOT / "ir_lab", folder / "ir_lab")
            shutil.copytree(ROOT / "fixtures", folder / "fixtures")
            (folder / "scripts").mkdir()
            (folder / "tests" / "expected").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts" / "generate_simulation_fixtures.py", folder / "scripts")
            shutil.copy2(GOLD_PATH, folder / "tests" / "expected")
            artifact = folder / "fixtures" / "ir_simulations" / "artifacts" / "success_monitoring.jsonl"
            artifact.write_bytes(artifact.read_bytes() + b"\n")
            proc = subprocess.run([sys.executable, "-B", "-O", str(folder / "scripts" / "generate_simulation_fixtures.py"),
                                   "--check"], cwd=folder, capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(b"Fixture drift", proc.stderr)


if __name__ == "__main__":
    unittest.main()
