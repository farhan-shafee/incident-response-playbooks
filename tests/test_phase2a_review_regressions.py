"""Adversarial reproductions of the independent Phase 2A PR #6 audit findings.

These tests operate on disposable copied fixtures; no production resources.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from ir_lab.contracts import CaseError, document, timestamp
from ir_lab.evidence import case_from_file, validate_artifacts
from ir_lab.events import verify_event_references
from ir_lab.report import markdown
from ir_lab.triage import evaluate

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "ir_cases"


@contextmanager
def copied_case(name="positive"):
    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory) / "cases"
        shutil.copytree(FIXTURES, destination)
        yield destination / (name + ".json")


def load(case_path: Path) -> dict:
    return case_from_file(case_path)


def audited_result(case: dict, case_path: Path) -> tuple[dict, list[dict]]:
    document(case)
    verified = validate_artifacts(case, case_path)
    references = verify_event_references(case, case_path)
    return evaluate(case, verified), references


def replace_artifact(case: dict, path: Path, evidence_id: str, raw: bytes) -> None:
    item = next(e for e in case["evidence"] if e["id"] == evidence_id)
    location = path.parent / item["path"]
    location.write_bytes(raw)
    item["sha256"] = hashlib.sha256(raw).hexdigest()
    item["byte_length"] = len(raw)


def encode_records(rows: list[dict]) -> bytes:
    return b"".join((json.dumps(row, sort_keys=True, ensure_ascii=False,
                                separators=(",", ":")) + "\n").encode("utf-8")
                    for row in rows)


class EntityScopedTriage(unittest.TestCase):
    def test_unrelated_authorization_does_not_clear_another_users_delivery(self):
        with copied_case("benign") as path:
            case = load(path)
            case["entities"].append({"id": "user_victim", "kind": "user",
                                     "value": "victim@example.test"})
            benign_file = path.parent / "artifacts" / "benign_events.jsonl"
            rows = [json.loads(line) for line in benign_file.read_text(encoding="utf-8").split("\n") if line]
            rows.append({
                "event_id": "victim_mail_001", "kind": "message_delivery",
                "entity_ids": ["user_victim"], "occurred_at": "2026-10-03T10:03:00Z",
                "summary": "Unexplained message for another identity"
            })
            replace_artifact(case, path, "benign_log", encode_records(rows))
            case["observations"].append({
                "id": "obs_victim_delivery", "kind": "message_delivery", "source": "artifact",
                "entity_ids": ["user_victim"], "evidence_ids": ["benign_log"],
                "source_event_id": "victim_mail_001",
                "occurred_at": "2026-10-03T10:03:00Z",
                "description": "Synthetic message unrelated to user Ben's approved exercise."
            })
            result, matched = audited_result(case, path)
            self.assertEqual(len(matched), 4)
            self.assertEqual(result["triage"]["disposition"], "needs_investigation")
            self.assertEqual(result["triage"]["provisional_severity"], "SEV-2")
            self.assertIn("benign_evidence_does_not_explain_all_affected_events",
                          result["quality_warnings"])
            self.assertIn("user_victim", next(a for a in result["proposed_actions"]
                                             if a["kind"] == "scope_recipients")["target_ids"])

    def test_authorization_must_cover_exact_entity_it_claims_to_explain(self):
        case = copy.deepcopy(load(FIXTURES / "benign.json"))
        case["entities"].append({"id": "user_victim", "kind": "user",
                                 "value": "victim@example.test"})
        case["observations"][0]["entity_ids"] = ["user_victim"]
        with self.assertRaisesRegex(CaseError, "affected entities"):
            document(case)

    def test_unlinked_benign_labels_do_not_clear_activity(self):
        case = copy.deepcopy(load(FIXTURES / "benign.json"))
        for obs in case["observations"]:
            obs.pop("explains_observation_ids", None)
        result, _ = audited_result(case, FIXTURES / "benign.json")
        self.assertNotEqual(result["triage"]["disposition"], "benign_explained")
        self.assertIn("benign_evidence_does_not_explain_all_affected_events",
                      result["quality_warnings"])

    def test_explicit_identity_log_gap_overrides_coverage_available(self):
        case = copy.deepcopy(load(FIXTURES / "benign.json"))
        case["observations"].append({
            "id": "obs_gap", "kind": "identity_log_gap", "source": "reported",
            "entity_ids": ["user_ben"], "evidence_ids": [],
            "occurred_at": "2026-10-03T10:04:00Z",
            "description": "Synthetic notice: identity logging unavailable for the scoped event."
        })
        result, _ = audited_result(case, FIXTURES / "benign.json")
        self.assertNotEqual(result["triage"]["disposition"], "benign_explained")
        self.assertEqual(result["triage"]["confidence"], "low")
        self.assertIn("explicit_identity_log_gap", result["quality_warnings"])
        self.assertIn("identity_coverage_contradiction", result["quality_warnings"])
        self.assertTrue(any("Reconcile" in q for q in result["outstanding_questions"]))
        self.assertTrue(result["proposed_actions"] or result["outstanding_questions"])

    def test_irrelevant_extra_user_does_not_receive_identity_actions(self):
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["entities"].append({"id": "user_unrelated", "kind": "user",
                                 "value": "unrelated@example.test"})
        result, _ = audited_result(case, FIXTURES / "positive.json")
        for action in result["proposed_actions"]:
            self.assertEqual(action["target_ids"], ["user_alex"], action)
            self.assertTrue(action["supporting_observation_ids"], action)

    def test_host_only_case_never_receives_identity_action(self):
        with copied_case("positive") as path:
            case = load(path)
            case["entities"] = [{"id": "host_only", "kind": "host",
                                 "value": "workstation.synthetic.test"}]
            case["actions"] = []
            for obs in case["observations"]:
                obs["entity_ids"] = ["host_only"]
            for evidence_id in ("mail_evidence", "identity_evidence"):
                item = next(x for x in case["evidence"] if x["id"] == evidence_id)
                location = path.parent / item["path"]
                rows = [json.loads(line) for line in location.read_text(encoding="utf-8").split("\n") if line]
                for row in rows:
                    row["entity_ids"] = ["host_only"]
                replace_artifact(case, path, evidence_id, encode_records(rows))
            result, _ = audited_result(case, path)
            self.assertEqual(result["triage"]["provisional_severity"], "SEV-1")
            self.assertEqual(result["proposed_actions"], [])
            self.assertIn("identity_action_target_mapping_missing", result["quality_warnings"])
            self.assertTrue(any("Identify and corroborate" in q for q in result["outstanding_questions"]))

    def test_input_action_rejects_unrelated_user_and_incompatible_host(self):
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["entities"].append({"id": "user_b", "kind": "user", "value": "b@example.test"})
        case["actions"][0]["target_ids"] = ["user_b"]
        with self.assertRaisesRegex(CaseError, "unrelated"):
            document(case)
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["entities"][0]["kind"] = "host"
        with self.assertRaisesRegex(CaseError, "incompatible"):
            document(case)

    def test_generated_action_id_collisions_allocate_unique_stable_suffix(self):
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["actions"][0]["id"] = "policy_scope_recipients"
        case["observations"][0]["id"] = "policy_investigate_signins"
        result, _ = audited_result(case, FIXTURES / "positive.json")
        ids = [a["id"] for a in result["proposed_actions"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("policy_scope_recipients", ids)  # retained user's revocation ID
        self.assertIn("policy_scope_recipients_2", ids)
        self.assertIn("policy_investigate_signins_2", ids)
        self.assertTrue(all(a["supporting_observation_ids"] for a in result["proposed_actions"]))
        self.assertEqual([a["id"] for a in result["proposed_actions"]],
                         [a["id"] for a in audited_result(case, FIXTURES / "positive.json")[0]["proposed_actions"]])


class InputAndEvidenceHardening(unittest.TestCase):
    def test_invalid_offset_minutes_rejected_not_normalized(self):
        for value in ("2026-10-01T12:00:00+00:60",
                      "2026-10-01T12:00:00-04:99",
                      "2026-10-01T12:00:00+24:00"):
            with self.subTest(value=value), self.assertRaises(CaseError):
                timestamp(value, "event")
        self.assertEqual(timestamp("2026-10-01T09:00:00-04:00", "event"),
                         timestamp("2026-10-01T13:00:00Z", "event"))

    def test_hash_valid_event_with_invalid_offset_is_rejected(self):
        with copied_case() as path:
            case = load(path)
            item = next(e for e in case["evidence"] if e["id"] == "mail_evidence")
            file = path.parent / item["path"]
            raw = file.read_bytes().replace(b"-04:00", b"-04:99")
            replace_artifact(case, path, "mail_evidence", raw)
            validate_artifacts(document(case), path)
            with self.assertRaises(CaseError):
                verify_event_references(case, path)

    def test_huge_integer_case_json_returns_controlled_cli_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / "huge.json"
            file.write_bytes(b'{"big":' + b"9" * 5000 + b"}")
            result = self.run_cli("validate", file)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_huge_integer_jsonl_returns_controlled_cli_exit(self):
        with copied_case() as path:
            case = load(path)
            source = path.parent / "artifacts" / "mail_events.jsonl"
            raw = source.read_bytes().replace(b'{"entity_ids":',
                                              b'{"huge":' + b"9" * 5000 + b',"entity_ids":')
            replace_artifact(case, path, "mail_evidence", raw)
            path.write_text(json.dumps(case, sort_keys=True), encoding="utf-8")
            result = self.run_cli("validate", path)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_deeply_nested_jsonl_returns_controlled_cli_exit(self):
        with copied_case() as path:
            case = load(path)
            raw = b"[" * 50000 + b"0" + b"]" * 50000 + b"\n"
            replace_artifact(case, path, "mail_evidence", raw)
            path.write_text(json.dumps(case, sort_keys=True), encoding="utf-8")
            result = self.run_cli("validate", path)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_unicode_u2028_in_jsonl_summary_is_not_a_record_split(self):
        with copied_case("benign") as path:
            case = load(path)
            item = next(e for e in case["evidence"] if e["id"] == "benign_log")
            source = path.parent / item["path"]
            rows = [json.loads(line) for line in source.read_text(encoding="utf-8").split("\n") if line]
            rows[0]["summary"] = "ordinary text\u2028with Unicode separator"
            replace_artifact(case, path, "benign_log", encode_records(rows))
            result, refs = audited_result(case, path)
            self.assertEqual(len(refs), 3)
            self.assertEqual(result["triage"]["disposition"], "benign_explained")

    def test_hardlinked_artifact_alias_is_rejected(self):
        with copied_case() as path:
            case = load(path)
            original = path.parent / "artifacts" / "mail_events.jsonl"
            alias = path.parent / "artifacts" / "mail_alias.jsonl"
            try:
                os.link(original, alias)
            except OSError as exc:
                self.skipTest(f"hard links unsupported by temp filesystem: {exc}")
            other = copy.deepcopy(next(x for x in case["evidence"] if x["id"] == "mail_evidence"))
            other["id"] = "evidence_alias"
            other["path"] = "artifacts/mail_alias.jsonl"
            case["evidence"].append(other)
            with self.assertRaisesRegex(CaseError, "duplicate physical artifact"):
                validate_artifacts(document(case), path)

    @unittest.skipUnless(os.name == "nt", "Windows file-name alias case")
    def test_windows_trailing_dot_artifact_alias_is_rejected(self):
        with copied_case() as path:
            case = load(path)
            original = path.parent / "artifacts" / "mail_events.jsonl"
            alias = path.parent / "artifacts." / "mail_events.jsonl"
            if not alias.is_file() or not alias.samefile(original):
                self.skipTest("Windows filesystem did not expose trailing-dot alias")
            other = copy.deepcopy(next(x for x in case["evidence"] if x["id"] == "mail_evidence"))
            other["id"] = "trailingdot_alias"
            other["path"] = "artifacts./mail_events.jsonl"
            case["evidence"].append(other)
            with self.assertRaisesRegex(CaseError, "duplicate physical artifact"):
                validate_artifacts(document(case), path)

    def test_optimized_fixture_checker_does_read_and_reject_missing_files(self):
        with tempfile.TemporaryDirectory() as temp:
            scripts = Path(temp) / "scripts"
            scripts.mkdir()
            script = scripts / "generate_ir_fixtures.py"
            shutil.copy2(ROOT / "scripts" / "generate_ir_fixtures.py", script)
            result = subprocess.run([sys.executable, "-O", "-B", str(script), "--check"],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"PASS 10", result.stdout)
            self.assertIn(b"Fixture unavailable", result.stderr)
        check = subprocess.run([sys.executable, "-O", "-B",
                                str(ROOT / "scripts" / "generate_ir_fixtures.py"), "--check"],
                               cwd=ROOT, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn(b"PASS 10", check.stdout)

    def test_extra_undocumented_jsonl_record_does_not_change_nominated_decisions(self):
        with copied_case("benign") as path:
            case = load(path)
            item = next(e for e in case["evidence"] if e["id"] == "benign_log")
            source = path.parent / item["path"]
            rows = [json.loads(line) for line in source.read_text(encoding="utf-8").split("\n") if line]
            rows.append({
                "event_id": "ignored_001", "kind": "suspicious_sign_in",
                "entity_ids": ["user_ben"], "occurred_at": "2026-10-03T10:05:00Z",
                "summary": "Unnominated event; scanner is NOT a hunting engine"
            })
            replace_artifact(case, path, "benign_log", encode_records(rows))
            result, refs = audited_result(case, path)
            self.assertEqual(len(refs), 3)
            self.assertEqual(result["triage"]["disposition"], "benign_explained")
            self.assertTrue(any("Only nominated" in limitation for limitation in result["limitations"]))

    @staticmethod
    def run_cli(command: str, path: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-B", "-m", "ir_lab", command, str(path)],
            cwd=ROOT, capture_output=True, check=False
        )


class ReportEvidenceReceipts(unittest.TestCase):
    def test_report_exposes_event_ids_entity_scope_lineage_and_decision_evidence(self):
        path = FIXTURES / "positive.json"
        case = load(path)
        result, references = audited_result(case, path)
        result["correlated_event_references"] = references
        output = markdown(result).decode("utf-8")
        self.assertIn("Scoped Entities", output)
        self.assertIn("Correlated Synthetic Source Events", output)
        self.assertIn("Supporting observation IDs", output)
        self.assertIn("raw SHA-256", output)
        self.assertIn("Explicit normalized digest", output)
        self.assertIn("Derived from", output)
        self.assertIn("original", output)
        self.assertIn("NOT verified", output)
        self.assertEqual(len(references), 2)
        self.assertEqual(result["triage"]["supporting_observation_ids"], ["obs_submission"])
        self.assertTrue(all(a["supporting_observation_ids"]
                            for a in result["proposed_actions"]))
        self.assertEqual(len({a["id"] for a in result["proposed_actions"]}),
                         len(result["proposed_actions"]))


class SeverityBranches(unittest.TestCase):
    def test_link_click_sev_two(self):
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["actions"] = []
        case["observations"] = [case["observations"][0], {
            "id": "obs_click", "kind": "link_click", "source": "reported",
            "entity_ids": ["user_alex"], "evidence_ids": [],
            "occurred_at": "2026-10-01T13:10:00Z", "description": "User clicked link."
        }]
        result, _ = audited_result(case, FIXTURES / "positive.json")
        self.assertEqual(result["triage"]["provisional_severity"], "SEV-2")

    def test_single_delivery_sev_three(self):
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["observations"] = [case["observations"][0]]
        case["actions"] = []
        result, _ = audited_result(case, FIXTURES / "positive.json")
        self.assertEqual(result["triage"]["provisional_severity"], "SEV-3")

    def test_suspicious_signin_only_pending(self):
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["observations"] = [case["observations"][2]]
        result, _ = audited_result(case, FIXTURES / "positive.json")
        self.assertEqual(result["triage"]["provisional_severity"], "pending")

    def test_delivery_with_inconclusive_signin_retains_sev_three_and_support(self):
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["observations"] = [
            obs for obs in case["observations"]
            if obs["kind"] != "credential_submission_report"
        ]
        case["actions"] = []
        result, refs = audited_result(case, FIXTURES / "positive.json")
        self.assertEqual({item["event_id"] for item in refs}, {"mail_001", "login_001"})
        triage = result["triage"]
        self.assertEqual(triage["provisional_severity"], "SEV-3")
        self.assertEqual(triage["urgency"], "elevated")
        self.assertEqual(triage["disposition"], "needs_investigation")
        self.assertEqual(triage["supporting_observation_ids"], ["obs_delivery"])
        self.assertFalse(triage["account_takeover_confirmed"])
        self.assertIn("successful_account_takeover_not_established",
                      result["quality_warnings"])
        self.assertTrue(any("unauthorized account use" in item
                            for item in result["outstanding_questions"]))
        actions = {item["kind"]: item for item in result["proposed_actions"]}
        self.assertEqual(set(actions), {"scope_recipients", "investigate_signins"})
        self.assertEqual(actions["investigate_signins"]["target_ids"], ["user_alex"])
        self.assertEqual(actions["investigate_signins"]["supporting_observation_ids"],
                         ["obs_signin"])
        self.assertEqual(actions["scope_recipients"]["target_ids"], ["user_alex"])
        self.assertEqual(actions["scope_recipients"]["supporting_observation_ids"],
                         ["obs_delivery", "obs_signin"])

    def test_delivery_plus_signin_and_missing_identity_coverage(self):
        case = copy.deepcopy(load(FIXTURES / "positive.json"))
        case["observations"] = [
            obs for obs in case["observations"]
            if obs["kind"] != "credential_submission_report"
        ]
        case["actions"] = []
        case["coverage"]["identity_logs"] = "missing"
        result, refs = audited_result(case, FIXTURES / "positive.json")
        self.assertEqual(len(refs), 2)
        self.assertEqual(result["triage"]["provisional_severity"], "SEV-3")
        self.assertEqual(result["triage"]["urgency"], "elevated")
        self.assertEqual(result["triage"]["confidence"], "low")
        self.assertEqual(result["triage"]["supporting_observation_ids"],
                         ["obs_delivery"])
        self.assertIn("identity_logs_missing", result["quality_warnings"])
        self.assertTrue(any("Reconcile" in item
                            for item in result["outstanding_questions"]))


if __name__ == "__main__":
    unittest.main()
