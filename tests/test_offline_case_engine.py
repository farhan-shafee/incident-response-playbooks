"""Independent offline acceptance, failure-path, and adversarial regression tests."""
from __future__ import annotations

import contextlib
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
from unittest import mock

from ir_lab.contracts import CaseError, document, timestamp
from ir_lab.evidence import (canonical_json, case_from_file, normalized_utf8_v1,
                             validate_artifacts, write_new_file)
from ir_lab.events import verify_event_references
from ir_lab.report import markdown
from ir_lab.triage import evaluate

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "ir_cases"
GOLD = json.loads((ROOT / "tests" / "expected" / "independent_triage_expectations.json").read_text(encoding="utf-8"))


def validate_named(name: str) -> dict:
    case_path = FIXTURES / (name + ".json")
    case = case_from_file(case_path)
    verified = validate_artifacts(case, case_path)
    matched = verify_event_references(case, case_path)
    result = evaluate(case, verified)
    result["correlated_event_references"] = matched
    return result


def projection(result: dict) -> dict:
    triage = result["triage"]
    return {
        "case_id": result["case_id"],
        "severity": triage["provisional_severity"],
        "urgency": triage["urgency"],
        "confidence": triage["confidence"],
        "disposition": triage["disposition"],
        "observations": len(result["observations"]),
        "event_matches": len(result["correlated_event_references"]),
        "actions": [a["kind"] for a in result["proposed_actions"]],
    }


@contextlib.contextmanager
def temporary_case(name: str = "positive"):
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        shutil.copytree(FIXTURES, folder / "case")
        yield folder / "case" / (name + ".json")


def rewrite_case(path: Path, case: dict) -> None:
    path.write_bytes(canonical_json(case))


class IndependentExpectations(unittest.TestCase):
    def test_three_independent_triage_outcomes(self):
        for name, expected in GOLD.items():
            with self.subTest(name=name):
                result = validate_named(name)
                self.assertEqual(projection(result), {k: v for k, v in expected.items() if k != "warnings"})
                for warning in expected["warnings"]:
                    self.assertIn(warning, result["quality_warnings"])
                self.assertFalse(result["triage"]["account_takeover_confirmed"])
                self.assertFalse(result["triage"]["incident_closure_verified"])
                self.assertEqual(result["triage"]["recovery_state"], "unverified")
                self.assertTrue(all(a["approval"] == "not_recorded" and
                                    a["execution"] == "not_recorded" and
                                    a["verification"] == "not_recorded"
                                    for a in result["proposed_actions"]))

    def test_repeated_result_bytes_are_identical(self):
        first = canonical_json(validate_named("positive"))
        for _ in range(5):
            self.assertEqual(first, canonical_json(validate_named("positive")))

    def test_negative_control_wrong_severity_is_detected(self):
        expected = GOLD["positive"]
        result = projection(validate_named("positive"))
        result["severity"] = "SEV-2"  # deliberate wrong outcome; not engine-generated
        with self.assertRaises(AssertionError):
            self.assertEqual(result, {k: v for k, v in expected.items() if k != "warnings"})

    def test_report_html_and_markdown_are_neutralized(self):
        result = validate_named("positive")
        result["observations"][0]["description"] = "<img src=x onerror=1> ![x](https://evil.test) [click](x)"
        rendered = markdown(result).decode("utf-8")
        self.assertNotIn("<img", rendered)
        self.assertNotIn("![x]", rendered)
        self.assertNotIn("[click](x)", rendered)
        self.assertIn("NOT verified", rendered)

    def test_utc_offset_converts_without_losing_precision(self):
        self.assertEqual(timestamp("2026-10-01T09:00:00.123456-04:00", "t"),
                         "2026-10-01T13:00:00.123456Z")
        self.assertEqual(validate_named("positive")["observations"][0]["occurred_at_utc"],
                         "2026-10-01T13:00:00.000000Z")

    def test_normalized_hash_distinct_from_original_hash(self):
        original = (FIXTURES / "artifacts" / "report_raw.txt").read_bytes()
        normalized = normalized_utf8_v1(original)
        self.assertNotEqual(hashlib.sha256(original).hexdigest(), hashlib.sha256(normalized).hexdigest())
        self.assertEqual(normalized, (FIXTURES / "artifacts" / "report_normalized.txt").read_bytes())

    def test_proposed_action_not_claimed_completed(self):
        result = validate_named("positive")
        self.assertTrue(result["proposed_actions"])
        self.assertTrue(all(action["state"] in {"recommended", "assumed_for_exercise"} for action in result["proposed_actions"]))

    def test_benign_explanation_cannot_suppress_credential_report(self):
        case = case_from_file(FIXTURES / "positive.json")
        case = copy.deepcopy(case)
        case["observations"].append({
            "id": "benign_note", "kind": "benign_explanation",
            "source": "reported", "entity_ids": ["user_alex"], "evidence_ids": [],
            "occurred_at": "2026-10-01T13:40:00Z", "description": "Someone assumes this was benign."
        })
        document(case)
        result = evaluate(case, validate_artifacts(case, FIXTURES / "positive.json"))
        self.assertEqual(result["triage"]["provisional_severity"], "SEV-1")

    def test_multiple_recipients_without_click_are_sev_two(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["entities"].append({"id": "user_second", "kind": "user",
                                 "value": "user_second@example.test"})
        only_delivery = copy.deepcopy(case["observations"][0])
        only_delivery["source"] = "reported"
        only_delivery["entity_ids"] = ["user_alex", "user_second"]
        only_delivery["evidence_ids"] = []
        only_delivery.pop("source_event_id")
        case["observations"] = [only_delivery]
        case["actions"] = []
        document(case)
        result = evaluate(case, validate_artifacts(case, FIXTURES / "positive.json"))
        self.assertEqual(result["triage"]["provisional_severity"], "SEV-2")
        self.assertEqual(result["triage"]["confidence"], "low")

    def test_missing_identity_coverage_prevents_benign_disposition(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "benign.json"))
        case["coverage"]["identity_logs"] = "missing"
        document(case)
        result = evaluate(case, validate_artifacts(case, FIXTURES / "benign.json"))
        self.assertNotEqual(result["triage"]["disposition"], "benign_explained")
        self.assertEqual(result["triage"]["confidence"], "low")


class ContractFailures(unittest.TestCase):
    def test_conflicting_duplicate_source_event_is_rejected(self):
        with self.assertRaisesRegex(CaseError, "duplicate source event identity"):
            case_from_file(FIXTURES / "adversarial.json")

    def test_duplicate_global_id(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["observations"][1]["id"] = case["observations"][0]["id"]
        with self.assertRaises(CaseError):
            document(case)

    def test_missing_entity_reference(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["observations"][0]["entity_ids"] = ["unknown_user"]
        with self.assertRaisesRegex(CaseError, "unknown reference"):
            document(case)

    def test_missing_evidence_reference(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["observations"][0]["evidence_ids"] = ["missing_event"]
        with self.assertRaises(CaseError):
            document(case)

    def test_unsupported_version_and_category(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["schema_version"] = "ir-case/999"
        with self.assertRaises(CaseError):
            document(case)
        case["schema_version"] = "ir-case/1.0"
        case["category"] = "ransomware"
        with self.assertRaises(CaseError):
            document(case)

    def test_non_synthetic_case(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["synthetic"] = False
        with self.assertRaises(CaseError):
            document(case)

    def test_phase_two_a_rejects_false_action_approval_and_verified_closure(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["actions"][0]["state"] = "verified"
        with self.assertRaisesRegex(CaseError, "reserved"):
            document(case)
        case["actions"][0]["state"] = "approved"
        with self.assertRaises(CaseError):
            document(case)
        case["actions"][0]["state"] = "recommended"
        case["recovery"]["state"] = "verified"
        with self.assertRaises(CaseError):
            document(case)

    def test_timestamp_rejects_unaware_and_invalid_offsets(self):
        for value in ("2026-10-01T13:00:00", "2026-02-30T12:00:00Z",
                      "2026-10-01T12:00:00+25:00", "not-time",
                      "2026-10-01T12:00:00.1234567Z"):
            with self.subTest(value=value), self.assertRaises(CaseError):
                timestamp(value, "t")

    def test_case_json_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            case_path = Path(temp) / "case.json"
            case_path.write_bytes(b'{"schema_version":1,"schema_version":2}')
            with self.assertRaisesRegex(CaseError, "duplicate object key"):
                case_from_file(case_path)

    def test_excessively_nested_json_is_controlled_error(self):
        with tempfile.TemporaryDirectory() as temp:
            case_path = Path(temp) / "case.json"
            case_path.write_bytes(b"[" * 1500 + b"0" + b"]" * 1500)
            with self.assertRaises(CaseError):
                case_from_file(case_path)

    def test_unicode_surrogate_cannot_escape_into_report(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["observations"][0]["description"] = "\ud800"
        with self.assertRaises(CaseError):
            document(case)

    def test_unexpected_object_alias_rejected(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["is_production"] = False
        with self.assertRaises(CaseError):
            document(case)

    def test_derived_evidence_requires_valid_parent_and_no_cycles(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        derived = next(x for x in case["evidence"] if x["kind"] == "derived")
        derived["parent_id"] = "missing_parent"
        with self.assertRaises(CaseError):
            document(case)
        derived["parent_id"] = "user_report_derived"
        with self.assertRaises(CaseError):
            document(case)

    def test_unsafe_artifact_paths_rejected(self):
        for path in ("../../secrets.txt", "/tmp/secret", "C:\\tokens.txt", "x/../y"):
            with self.subTest(path=path):
                case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
                case["evidence"][0]["path"] = path
                document(case)
                with self.assertRaises(CaseError):
                    validate_artifacts(case, FIXTURES / "positive.json")

    def test_corrupt_sha_and_byte_length(self):
        with temporary_case() as case_path:
            case = case_from_file(case_path)
            case["evidence"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(CaseError, "SHA-256 mismatch"):
                validate_artifacts(document(case), case_path)
            case = case_from_file(case_path)
            case["evidence"][0]["byte_length"] += 1
            with self.assertRaisesRegex(CaseError, "byte length mismatch"):
                validate_artifacts(document(case), case_path)

    def test_missing_artifact(self):
        with temporary_case() as case_path:
            file = case_path.parent / "artifacts" / "mail_events.jsonl"
            file.unlink()
            with self.assertRaisesRegex(CaseError, "missing"):
                validate_artifacts(case_from_file(case_path), case_path)

    def test_derived_lineage_cannot_be_forged_with_a_fresh_hash(self):
        with temporary_case() as case_path:
            case = case_from_file(case_path)
            location = case_path.parent / "artifacts" / "report_normalized.txt"
            bogus = b"Synthetic but unrelated derived evidence.\n"
            location.write_bytes(bogus)
            item = next(x for x in case["evidence"] if x["id"] == "user_report_derived")
            item["byte_length"] = len(bogus)
            item["sha256"] = hashlib.sha256(bogus).hexdigest()
            with self.assertRaisesRegex(CaseError, "derived bytes disagree"):
                validate_artifacts(document(case), case_path)

    def test_unhashable_event_type_must_fail_controlled(self):
        with temporary_case() as case_path:
            case = case_from_file(case_path)
            location = case_path.parent / "artifacts" / "mail_events.jsonl"
            event = json.loads(location.read_bytes())
            event["kind"] = ["not-a-valid-kind"]
            raw = (json.dumps(event, sort_keys=True) + "\n").encode()
            location.write_bytes(raw)
            record = next(x for x in case["evidence"] if x["id"] == "mail_evidence")
            record["byte_length"] = len(raw)
            record["sha256"] = hashlib.sha256(raw).hexdigest()
            validate_artifacts(document(case), case_path)
            with self.assertRaises(CaseError):
                verify_event_references(case, case_path)

    def test_unhashable_observation_kind_must_fail_controlled(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        case["observations"][0]["kind"] = ["invalid"]
        with self.assertRaises(CaseError):
            document(case)

    def test_wrong_normalized_sha(self):
        case = copy.deepcopy(case_from_file(FIXTURES / "positive.json"))
        item = next(x for x in case["evidence"] if "normalization" in x)
        item["normalized_sha256"] = "0" * 64
        with self.assertRaisesRegex(CaseError, "normalized SHA-256 mismatch"):
            validate_artifacts(document(case), FIXTURES / "positive.json")

    def test_artifact_claim_must_match_event_kind_even_with_valid_hash(self):
        with temporary_case() as case_path:
            case = case_from_file(case_path)
            location = case_path.parent / "artifacts" / "mail_events.jsonl"
            original = location.read_bytes()
            modified = original.replace(b'"kind":"message_delivery"', b'"kind":"benign_explanation"')
            self.assertNotEqual(original, modified)
            location.write_bytes(modified)
            manifest = next(x for x in case["evidence"] if x["id"] == "mail_evidence")
            manifest["sha256"] = hashlib.sha256(modified).hexdigest()
            manifest["byte_length"] = len(modified)
            validate_artifacts(document(case), case_path)
            with self.assertRaisesRegex(CaseError, "kind differs"):
                verify_event_references(case, case_path)

    def test_event_identity_changed_with_correct_hash_is_still_rejected(self):
        with temporary_case() as case_path:
            case = case_from_file(case_path)
            location = case_path.parent / "artifacts" / "mail_events.jsonl"
            modified = location.read_bytes().replace(b"mail_001", b"mail_002")
            location.write_bytes(modified)
            item = next(x for x in case["evidence"] if x["id"] == "mail_evidence")
            item["sha256"] = hashlib.sha256(modified).hexdigest()
            item["byte_length"] = len(modified)
            validate_artifacts(document(case), case_path)
            with self.assertRaisesRegex(CaseError, "source event not found"):
                verify_event_references(case, case_path)

    def test_event_time_mismatch_even_if_hash_is_valid(self):
        with temporary_case() as case_path:
            case = case_from_file(case_path)
            location = case_path.parent / "artifacts" / "mail_events.jsonl"
            modified = location.read_bytes().replace(b"09:00:00", b"09:01:00")
            location.write_bytes(modified)
            item = next(x for x in case["evidence"] if x["id"] == "mail_evidence")
            item["sha256"] = hashlib.sha256(modified).hexdigest()
            validate_artifacts(document(case), case_path)
            with self.assertRaisesRegex(CaseError, "event time differs"):
                verify_event_references(case, case_path)

    def test_duplicate_event_json_key_rejected(self):
        with temporary_case() as case_path:
            case = case_from_file(case_path)
            location = case_path.parent / "artifacts" / "mail_events.jsonl"
            original = location.read_bytes()
            modified = original.replace(b'{"entity_ids":', b'{"kind":"message_delivery","entity_ids":')
            location.write_bytes(modified)
            item = next(x for x in case["evidence"] if x["id"] == "mail_evidence")
            item["sha256"] = hashlib.sha256(modified).hexdigest()
            item["byte_length"] = len(modified)
            validate_artifacts(document(case), case_path)
            with self.assertRaisesRegex(CaseError, "duplicate object key"):
                verify_event_references(case, case_path)

    def test_no_network_or_process_executed_by_evaluator(self):
        import socket
        case_path = FIXTURES / "positive.json"
        case = case_from_file(case_path)
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")), \
             mock.patch.object(os, "system", side_effect=AssertionError("shell forbidden")):
            artifacts = validate_artifacts(case, case_path)
            matched = verify_event_references(case, case_path)
            self.assertEqual(len(matched), 2)
            self.assertEqual(evaluate(case, artifacts)["triage"]["urgency"], "urgent")

    def test_source_evidence_unmodified_by_execution(self):
        location = FIXTURES / "artifacts" / "report_raw.txt"
        before = location.read_bytes()
        validate_named("positive")
        self.assertEqual(before, location.read_bytes())


class CLITests(unittest.TestCase):
    def cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-B", "-m", "ir_lab", *map(str, args)],
                              cwd=ROOT, capture_output=True, check=False)

    def test_successful_cli_and_deterministic_repeated_processes(self):
        file = FIXTURES / "positive.json"
        a = self.cli("triage", str(file))
        b = self.cli("triage", str(file))
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        obj = json.loads(a.stdout)
        self.assertEqual(obj["triage"]["provisional_severity"], "SEV-1")
        self.assertIn(b"not_recorded", a.stdout)

    def test_validate_reports_correlated_event_count(self):
        proc = self.cli("validate", str(FIXTURES / "benign.json"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(b"3 correlated event references", proc.stdout)

    def test_cli_rejects_adversarial_case(self):
        result = self.cli("triage", str(FIXTURES / "adversarial.json"))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"duplicate source event identity", result.stderr)

    def test_render_json_markdown_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = FIXTURES / "positive.json"
            j = Path(tmp) / "result.json"
            m = Path(tmp) / "result.md"
            result1 = self.cli("render", str(case), "--format", "json", "--output", str(j))
            result2 = self.cli("render", str(case), "--format", "markdown", "--output", str(m))
            self.assertEqual(result1.returncode, 0, result1.stderr)
            self.assertEqual(result2.returncode, 0, result2.stderr)
            self.assertEqual(j.read_bytes(), canonical_json(validate_named("positive")))
            self.assertIn(b"NOT verified", m.read_bytes())
            before = j.read_bytes()
            again = self.cli("render", str(case), "--format", "json", "--output", str(j))
            self.assertEqual(again.returncode, 2)
            self.assertEqual(j.read_bytes(), before)

    def test_cli_output_cannot_alias_input_artifact(self):
        artifact = FIXTURES / "artifacts" / "mail_events.jsonl"
        before = artifact.read_bytes()
        result = self.cli("render", str(FIXTURES / "positive.json"), "--format", "json",
                          "--output", str(artifact))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(artifact.read_bytes(), before)

    def test_output_creation_error_preserves_other_files(self):
        case_path = FIXTURES / "positive.json"
        case = case_from_file(case_path)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "never_created.json"
            with mock.patch("ir_lab.evidence.os.link", side_effect=OSError(13, "permission denied")):
                with self.assertRaisesRegex(CaseError, "atomically create"):
                    write_new_file(target, b"something\n", case_path, case)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_fixture_regeneration_check_is_read_only(self):
        before = (FIXTURES / "positive.json").read_bytes()
        result = subprocess.run([sys.executable, "-B", "scripts/generate_ir_fixtures.py", "--check"],
                                cwd=ROOT, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, (FIXTURES / "positive.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
