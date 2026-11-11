"""Boundary tests authored before the simulation CLI/contract implementation."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ir_lab.contracts import CaseError
from ir_lab.evidence import canonical_json, case_from_file, validate_artifacts
from ir_lab.events import verify_event_references
from ir_lab.triage import evaluate

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "fixtures/ir_cases/positive.json"


def context():
    case = case_from_file(CASE)
    result = evaluate(case, validate_artifacts(case, CASE))
    result["correlated_event_references"] = verify_event_references(case, CASE)
    plan = {
        "schema_version": "ir-simulation/1.0", "simulation_id": "SIM-CONTRACT",
        "synthetic": True, "case_id": case["case_id"],
        "case_sha256": hashlib.sha256(canonical_json(case)).hexdigest(),
        "result_sha256": hashlib.sha256(canonical_json(result)).hexdigest(),
        "as_of": "2026-10-06T12:00:00Z",
        "actors": [{"id": "sim_" + role, "role": role, "synthetic": True,
                    "display_name": "Synthetic " + role}
                   for role in ("approver", "operator", "verifier", "reviewer")],
        "actions": [{"action_id": a["id"], "kind": a["kind"],
                     "target_ids": a["target_ids"],
                     "supporting_observation_ids": a["supporting_observation_ids"]}
                    for a in result["proposed_actions"]],
        "evidence": [], "events": [],
        "recovery": {"observation_start": "2026-10-05T12:00:00Z",
                     "observation_end": "2026-10-06T10:00:00Z",
                     "monitoring_refs": [], "residual_risks": [], "acceptance": None},
    }
    return case, result, plan


class SimulationContractCLI(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows directory junction behavior")
    def test_simulation_output_rejects_windows_junction_parent(self):
        _, _, plan = context()
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            real = folder / "real"
            real.mkdir()
            junction = folder / "junction"
            made = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(real)],
                                  capture_output=True)
            if made.returncode:
                self.skipTest("temporary filesystem does not support junction creation")
            path = folder / "plan.json"
            path.write_bytes(canonical_json(plan))
            proc = subprocess.run([sys.executable, "-B", "-m", "ir_lab", "simulation-render",
                                   str(CASE), "--plan", str(path), "--format", "json",
                                   "--output", str(junction / "report.json")], cwd=ROOT, capture_output=True)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertFalse((real / "report.json").exists())
            self.assertNotIn(b"Traceback", proc.stderr)

    def test_markdown_shows_acknowledgement_separately_from_adverse_observation(self):
        from ir_lab.simulation_contracts import load_plan
        from ir_lab.simulation_engine import replay
        from ir_lab.simulation_report import markdown
        from ir_lab.simulation_verification import load_evidence
        from ir_lab.report import safe
        path = ROOT / "fixtures/ir_cases/response_case.json"
        case = case_from_file(path)
        result = evaluate(case, validate_artifacts(case, path))
        result["correlated_event_references"] = verify_event_references(case, path)
        plan_path = ROOT / "fixtures/ir_simulations/misleading_success.json"
        plan = load_plan(plan_path, case, result)
        artifacts, records = load_evidence(plan, plan_path)
        output = markdown(replay(plan, result, records, artifacts)).decode("utf-8")
        self.assertIn("Independent Synthetic Observations", output)
        self.assertIn(safe("active_session"), output)
        self.assertIn("Acknowledged: true", output)
        self.assertIn("Fictional verifier", output)
        self.assertIn("NOT verified", output)

    def test_validate_no_approval_does_not_require_execution_or_create_report(self):
        _, _, plan = context()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "plan.json"
            path.write_bytes(canonical_json(plan))
            proc = subprocess.run([sys.executable, "-B", "-m", "ir_lab",
                                   "simulation-validate", str(CASE), "--plan", str(path)],
                                  cwd=ROOT, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(b"VALID synthetic simulation", proc.stdout)
            self.assertEqual([p.name for p in Path(td).iterdir()], ["plan.json"])

    def test_bindings_reject_changed_case_result_target_and_omitted_action(self):
        from ir_lab.simulation_contracts import validate_plan
        case, result, original = context()
        for field in ("case_sha256", "result_sha256", "case_id"):
            plan = copy.deepcopy(original)
            plan[field] = "wrong" if field == "case_id" else "0" * 64
            with self.subTest(field=field), self.assertRaises(CaseError):
                validate_plan(plan, case, result)
        plan = copy.deepcopy(original)
        plan["actions"][0]["target_ids"] = ["unknown"]
        with self.assertRaises(CaseError):
            validate_plan(plan, case, result)
        plan = copy.deepcopy(original)
        plan["actions"].pop()
        with self.assertRaises(CaseError):
            validate_plan(plan, case, result)

    def test_unknown_properties_and_unverified_recovery_shape(self):
        from ir_lab.simulation_contracts import validate_plan
        case, result, original = context()
        for mutate in (lambda p: p.update(verified=True),
                       lambda p: p["actions"][0].update(required=False),
                       lambda p: p["recovery"].update(verified=True),
                       lambda p: p["actors"][0].update(synthetic=False)):
            plan = copy.deepcopy(original)
            mutate(plan)
            with self.assertRaises(CaseError):
                validate_plan(plan, case, result)

    def test_output_preservation_and_explicit_destination(self):
        _, _, plan = context()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "plan.json"
            path.write_bytes(canonical_json(plan))
            for destination in (path, Path(td), Path(td) / "missing" / "out.json"):
                proc = subprocess.run([sys.executable, "-B", "-m", "ir_lab",
                                       "simulation-render", str(CASE), "--plan", str(path),
                                       "--format", "json", "--output", str(destination)],
                                      cwd=ROOT, capture_output=True)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertNotIn(b"Traceback", proc.stderr)
            self.assertEqual(path.read_bytes(), canonical_json(plan))


if __name__ == "__main__":
    unittest.main()
