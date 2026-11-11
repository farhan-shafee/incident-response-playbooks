"""Hand-authored replay boundaries independent of the committed simulation fixtures."""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest

from ir_lab.contracts import CaseError
from ir_lab.evidence import canonical_json


def binding(plan, action):
    value = {key: plan[key] for key in ("case_id", "case_sha256", "result_sha256")}
    value["action"] = {**action, "target_ids": sorted(action["target_ids"]),
                       "supporting_observation_ids": sorted(action["supporting_observation_ids"])}
    return hashlib.sha256(canonical_json(value)).hexdigest()


def exercise():
    action = {"action_id": "revoke", "kind": "revoke_sessions", "target_ids": ["alice", "bob"],
              "supporting_observation_ids": ["reported_submission"]}
    plan = {"schema_version": "ir-simulation/1.0", "simulation_id": "unit_simulation",
            "synthetic": True, "case_id": "unit_case", "case_sha256": "1" * 64,
            "result_sha256": "2" * 64, "as_of": "2026-10-05T11:00:00Z",
            "actors": [{"id": f"sim_{role}", "display_name": role, "role": role, "synthetic": True}
                       for role in ("approver", "operator", "verifier", "reviewer")],
            "actions": [action], "evidence": [], "events": [],
            "recovery": {"observation_start": "2026-10-05T09:20:00Z",
                         "observation_end": "2026-10-05T10:20:00Z", "monitoring_refs": [],
                         "residual_risks": ["Synthetic evidence cannot establish real recovery."],
                         "acceptance": {"reviewer_id": "sim_reviewer", "at": "2026-10-05T10:30:00Z",
                                        "rationale": "Bounded synthetic exercise reviewed.",
                                        "residual_risk_acknowledged": True, "closure_requested": True}}}
    def event(event_id, kind, at, old, new, refs, **extra):
        return {"id": event_id, "kind": kind, "at": at, "action_id": "revoke",
                "target_ids": ["alice", "bob"], "previous_state": old, "new_state": new,
                "reason": "Synthetic unit exercise", "evidence_refs": refs, **extra}
    def ref(record_id):
        return {"evidence_id": "records", "record_id": record_id}
    plan["events"] = [event("approve", "approval", "2026-10-05T09:00:00Z", "recommended", "approved_simulated", [],
                            approver_id="sim_approver", expires_at="2026-10-05T10:00:00Z",
                            binding_sha256=binding(plan, action)),
                      event("attempt", "attempt", "2026-10-05T09:05:00Z", "approved_simulated", "attempted_simulated",
                            [ref("ack")], operator_id="sim_operator"),
                      event("verify", "verification", "2026-10-05T09:15:00Z", "attempted_simulated",
                            "verified_effective_synthetic", [ref("verify_alice"), ref("verify_bob")])]
    rows = [{"record_id": "ack", "record_type": "acknowledgement", "action_id": "revoke", "kind": "revoke_sessions",
             "target_ids": ["alice", "bob"], "at": "2026-10-05T09:05:00Z", "operator_id": "sim_operator", "acknowledged": True}]
    for target in ("alice", "bob"):
        rows.append({"record_id": f"verify_{target}", "record_type": "verification", "action_id": "revoke",
                     "kind": "revoke_sessions", "target_id": target, "at": "2026-10-05T09:15:00Z",
                     "verifier_id": "sim_verifier", "observed_state": "no_active_sessions",
                     "window_start": "2026-10-05T09:05:00Z", "window_end": "2026-10-05T09:15:00Z"})
        rows.append({"record_id": f"monitor_{target}", "record_type": "monitoring", "action_id": "revoke",
                     "kind": "revoke_sessions", "target_id": target, "at": "2026-10-05T10:20:00Z",
                     "verifier_id": "sim_verifier", "observed_state": "clear",
                     "window_start": "2026-10-05T09:20:00Z", "window_end": "2026-10-05T10:20:00Z"})
        plan["recovery"]["monitoring_refs"].append(ref(f"monitor_{target}"))
    return plan, {("records", row["record_id"]): row for row in rows}


class ReplayUnitTests(unittest.TestCase):
    def setUp(self):
        try:
            self.replay = importlib.import_module("ir_lab.simulation_engine").replay
        except ModuleNotFoundError:
            self.fail("offline simulation replay has not been implemented")
        self.plan, self.records = exercise()
        self.triage = {"incident_closure_verified": False, "recovery_state": "unverified", "provisional_severity": "SEV-1"}

    def run_replay(self):
        return self.replay(self.plan, {"triage": self.triage}, self.records, [])

    def test_independent_clear_evidence_and_review_allow_only_synthetic_closure(self):
        result = self.run_replay()
        self.assertEqual(result["actions"][0]["state"], "verified_effective_synthetic")
        self.assertIs(result["recovery"]["simulation_closure_accepted"], True)
        self.assertEqual(result["recovery"]["blocking_reasons"], [])
        self.assertEqual(result["phase2a_triage"], self.triage)
        self.assertFalse(result["phase2a_triage"]["incident_closure_verified"])

    def test_report_receipts_show_actors_acknowledgement_and_independent_observations(self):
        result = self.run_replay()
        self.assertIn("actors", result)
        self.assertIn("evidence_records", result)
        self.assertEqual([actor["id"] for actor in result["actors"]],
                         ["sim_approver", "sim_operator", "sim_reviewer", "sim_verifier"])
        indexed = {(row["evidence_id"], row["record_id"]): row for row in result["evidence_records"]}
        self.assertTrue(indexed[("records", "ack")]["acknowledged"])
        observed = indexed[("records", "verify_alice")]
        self.assertEqual(observed["verifier_id"], "sim_verifier")
        self.assertEqual(observed["observed_state"], "no_active_sessions")
        self.assertEqual(observed["window_start"], "2026-10-05T09:05:00Z")
        observed["observed_state"] = "active_session"
        self.assertEqual(self.records[("records", "verify_alice")]["observed_state"], "no_active_sessions")

    def test_replay_is_stateless_and_does_not_mutate_inputs(self):
        before = copy.deepcopy((self.plan, self.records, self.triage))
        first = self.run_replay()
        self.assertEqual(canonical_json(first), canonical_json(self.run_replay()))
        self.assertEqual(before, (self.plan, self.records, self.triage))
        first["phase2a_triage"]["incident_closure_verified"] = True
        self.assertFalse(self.triage["incident_closure_verified"])

    def test_equal_time_receipts_preserve_causal_input_order(self):
        self.plan["events"][0]["id"] = "z_approval"
        self.plan["events"][1].update(id="a_attempt", at="2026-10-05T09:00:00Z")
        self.records[("records", "ack")]["at"] = "2026-10-05T09:00:00Z"
        result = self.run_replay()
        self.assertEqual([event["id"] for event in result["events"]],
                         ["z_approval", "a_attempt", "verify"])

    def test_acknowledgement_alone_cannot_verify_or_close(self):
        self.plan["events"].pop()
        result = self.run_replay()
        self.assertEqual(result["actions"][0]["state"], "attempted_simulated")
        self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_effectiveness_is_derived_per_target_including_missing_unknown_and_adverse(self):
        cases = [("active_session", "no_active_sessions", "partially_effective"),
                 ("active_session", "unknown", "failed"),
                 ("unknown", "unknown", "unverified"),
                 ("no_active_sessions", None, "partially_effective")]
        for alice, bob, expected in cases:
            with self.subTest(alice=alice, bob=bob):
                self.plan, self.records = exercise()
                self.records[("records", "verify_alice")]["observed_state"] = alice
                if bob is None:
                    self.plan["events"][2]["evidence_refs"].pop()
                else:
                    self.records[("records", "verify_bob")]["observed_state"] = bob
                self.plan["events"][2]["new_state"] = expected
                result = self.run_replay()
                self.assertEqual(result["actions"][0]["state"], expected)
                self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_claimed_success_cannot_override_adverse_evidence(self):
        self.records[("records", "verify_alice")]["observed_state"] = "active_session"
        with self.assertRaises(CaseError):
            self.run_replay()

    def test_attempt_requires_unexpired_exact_approval_digest(self):
        for field, value in (("expires_at", "2026-10-05T09:05:00Z"), ("binding_sha256", "0" * 64)):
            with self.subTest(field=field):
                self.plan, self.records = exercise()
                self.plan["events"][0][field] = value
                with self.assertRaises(CaseError):
                    self.run_replay()

    def test_expiry_after_valid_attempt_does_not_erase_effectiveness(self):
        self.plan["events"][0]["expires_at"] = "2026-10-05T09:06:00Z"
        self.assertTrue(self.run_replay()["recovery"]["simulation_closure_accepted"])

    def test_state_scope_chronology_and_duplicate_event_bypasses_reject(self):
        mutations = [lambda p: p["events"].pop(0),
                     lambda p: p["events"][1].update(target_ids=["alice"]),
                     lambda p: p["events"][1].update(previous_state="recommended"),
                     lambda p: p["events"][1].update(at="2026-10-05T08:59:00Z"),
                     lambda p: p["events"].append(copy.deepcopy(p["events"][0]))]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.plan, self.records = exercise()
                mutate(self.plan)
                with self.assertRaises(CaseError):
                    self.run_replay()

    def test_approval_denial_is_terminal_and_never_closes(self):
        self.plan["events"] = self.plan["events"][:1]
        self.plan["events"][0]["new_state"] = "denied"
        result = self.run_replay()
        self.assertEqual(result["actions"][0]["state"], "denied")
        self.assertFalse(result["recovery"]["simulation_closure_accepted"])
        self.plan["events"].append(copy.deepcopy(self.plan["events"][0]))
        self.plan["events"][-1]["id"] = "approve_again"
        with self.assertRaises(CaseError):
            self.run_replay()

    def test_ack_scope_time_actor_and_record_type_bind_to_attempt(self):
        changes = ({"target_ids": ["alice"]}, {"at": "2026-10-05T09:06:00Z"},
                   {"operator_id": "sim_verifier"}, {"kind": "scope_recipients"})
        for change in changes:
            with self.subTest(change=change):
                self.plan, self.records = exercise()
                self.records[("records", "ack")].update(change)
                with self.assertRaises(CaseError):
                    self.run_replay()

    def test_ack_cannot_be_used_as_verification(self):
        self.plan["events"][2]["evidence_refs"] = [{"evidence_id": "records", "record_id": "ack"}]
        with self.assertRaises(CaseError):
            self.run_replay()

    def test_duplicate_target_observations_reject_even_when_identical(self):
        row = copy.deepcopy(self.records[("records", "verify_alice")])
        row["record_id"] = "another_alice"
        self.records[("records", "another_alice")] = row
        self.plan["events"][2]["evidence_refs"].append({"evidence_id": "records", "record_id": "another_alice"})
        with self.assertRaises(CaseError):
            self.run_replay()

    def test_verification_window_must_follow_attempt_and_precede_event(self):
        for field, value in (("window_start", "2026-10-05T09:04:59Z"),
                             ("window_end", "2026-10-05T09:16:00Z"),
                             ("at", "2026-10-05T09:16:00Z")):
            with self.subTest(field=field):
                self.plan, self.records = exercise()
                self.records[("records", "verify_alice")][field] = value
                with self.assertRaises(CaseError):
                    self.run_replay()

    def test_incomplete_adverse_or_short_monitoring_blocks_closure(self):
        mutations = [lambda p, r: p["recovery"]["monitoring_refs"].pop(),
                     lambda p, r: r[("records", "monitor_alice")].update(observed_state="adverse"),
                     lambda p, r: r[("records", "monitor_alice")].update(window_start="2026-10-05T09:21:00Z"),
                     lambda p, r: p.update(as_of="2026-10-05T10:19:00Z")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.plan, self.records = exercise()
                mutate(self.plan, self.records)
                # As-of inconsistent records/events may be rejected before closure evaluation.
                try:
                    result = self.run_replay()
                except CaseError:
                    continue
                self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_acceptance_requires_independent_reviewer_risk_ack_and_all_records_elapsed(self):
        for change in ({"reviewer_id": "sim_operator"}, {"residual_risk_acknowledged": False},
                       {"closure_requested": False}, {"at": "2026-10-05T10:19:00Z"}):
            with self.subTest(change=change):
                self.plan, self.records = exercise()
                self.plan["recovery"]["acceptance"].update(change)
                try:
                    result = self.run_replay()
                except CaseError:
                    continue
                self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_reviewer_acceptance_must_follow_latest_monitoring_instant(self):
        self.plan["recovery"]["acceptance"]["at"] = "2026-10-05T10:20:00Z"
        self.assertFalse(self.run_replay()["recovery"]["simulation_closure_accepted"])

    def test_recovery_window_cannot_start_before_action_verification(self):
        self.plan["recovery"]["observation_start"] = "2026-10-05T09:10:00Z"
        self.records[("records", "monitor_alice")]["window_start"] = "2026-10-05T09:10:00Z"
        self.records[("records", "monitor_bob")]["window_start"] = "2026-10-05T09:10:00Z"
        self.assertFalse(self.run_replay()["recovery"]["simulation_closure_accepted"])

    def test_review_cannot_precede_collection_of_its_used_artifacts(self):
        artifact = {"id": "records", "collected_at": "2026-10-05T10:40:00Z"}
        result = self.replay(self.plan, {"triage": self.triage}, self.records, [artifact])
        self.assertFalse(result["recovery"]["simulation_closure_accepted"])

    def test_adverse_records_cannot_be_hidden_by_omitting_their_references(self):
        for record_type, source in (("verification", "verify_alice"), ("monitoring", "monitor_alice")):
            with self.subTest(record_type=record_type):
                self.plan, self.records = exercise()
                row = copy.deepcopy(self.records[("records", source)])
                row.update(record_id="hidden_adverse", observed_state=("active_session" if record_type == "verification" else "adverse"))
                self.records[("records", "hidden_adverse")] = row
                with self.assertRaisesRegex(CaseError, "conflicting per-target"):
                    self.run_replay()


class EvidenceUnitTests(unittest.TestCase):
    def setUp(self):
        try:
            self.load = importlib.import_module("ir_lab.simulation_verification").load_evidence
        except ModuleNotFoundError:
            self.fail("strict synthetic evidence loading has not been implemented")

    def load_raw(self, raw):
        plan, _ = exercise()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "plan.json"
            (Path(folder) / "rows.jsonl").write_bytes(raw)
            plan["evidence"] = [{"id": "records", "path": "rows.jsonl", "kind": "original",
                                 "sha256": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw),
                                 "source": "synthetic unit exercise", "collected_at": "2026-10-05T10:20:00Z"}]
            return self.load(plan, path)

    def test_loader_checks_every_row_including_unreferenced_malformed_records(self):
        _, rows = exercise()
        good = canonical_json(rows[("records", "ack")]).replace(b"\n", b"")
        with self.assertRaises(CaseError):
            self.load_raw(good + b'\n{"record_id":"unused","record_type":"ignored"}\n')

    def test_loader_returns_scoped_rows_and_verified_artifact_register(self):
        _, rows = exercise()
        raw = b"".join((json.dumps(row) + "\n").encode() for row in rows.values())
        artifacts, loaded = self.load_raw(raw)
        self.assertEqual(len(loaded), 5)
        self.assertEqual(loaded[("records", "ack")]["operator_id"], "sim_operator")
        self.assertEqual(artifacts[0]["sha256_raw"], hashlib.sha256(raw).hexdigest())

    def test_duplicate_json_keys_scoped_ids_and_nonfinite_values_reject(self):
        _, rows = exercise()
        row = json.dumps(rows[("records", "ack")]).encode()
        for raw in (row + b"\n" + row + b"\n", row.replace(b'{"record_id":', b'{"record_id":"dup","record_id":'),
                    row.replace(b'"acknowledged": true', b'"acknowledged": NaN')):
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(CaseError):
                    self.load_raw(raw)

    def test_wrong_roles_unknown_keys_and_bindings_reject(self):
        changes = ({"operator_id": "sim_verifier"}, {"unexpected": True},
                   {"kind": "scope_recipients"}, {"target_ids": ["mallory"]})
        for change in changes:
            with self.subTest(change=change):
                _, rows = exercise()
                row = rows[("records", "ack")]
                row.update(change)
                with self.assertRaises(CaseError):
                    self.load_raw((json.dumps(row) + "\n").encode())


if __name__ == "__main__":
    unittest.main()
