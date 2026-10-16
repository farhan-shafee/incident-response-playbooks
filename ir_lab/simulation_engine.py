"""Stateless approval-gated replay of a bounded synthetic response exercise."""
from __future__ import annotations

from copy import deepcopy

from .contracts import require, timestamp
from .simulation_contracts import action_binding_digest, digest
from .simulation_verification import actor_role, validate_record, verification_outcome


def _refs(refs: list[dict], records: dict[tuple[str, str], dict]) -> list[tuple[tuple[str, str], dict]]:
    selected = []
    seen = set()
    for ref in refs:
        key = (ref["evidence_id"], ref["record_id"])
        require(key in records, "simulation: evidence record reference not found")
        require(key not in seen, "simulation: duplicate evidence reference")
        seen.add(key)
        selected.append((key, records[key]))
    return selected


def _observation(row: dict, action: dict, actors: dict[str, dict], as_of: str,
                 record_type: str, attempt: dict | None, cutoff: str) -> None:
    validate_record(row, {action["action_id"]: action}, actors, as_of)
    require(row["record_type"] == record_type, f"simulation: {record_type} record required")
    require(timestamp(row["at"], "record.at") <= cutoff,
            "simulation: observation postdates event")
    if attempt is not None:
        require(timestamp(row["window_start"], "record.window_start") >=
                timestamp(attempt["at"], "attempt.at"),
                "simulation: observation window precedes attempt")


def _canonical_event(event: dict) -> dict:
    receipt = deepcopy(event)
    receipt["target_ids"] = sorted(receipt["target_ids"])
    receipt["evidence_refs"] = sorted(receipt["evidence_refs"],
                                      key=lambda ref: (ref["evidence_id"], ref["record_id"]))
    return receipt


def _recovery(plan: dict, actions: dict[str, dict], attempts: dict[str, dict],
              records: dict[tuple[str, str], dict], artifacts: list[dict],
              consumed: set[tuple[str, str]], actors: dict[str, dict]) -> dict:
    recovery = deepcopy(plan["recovery"])
    start = timestamp(recovery["observation_start"], "recovery.observation_start")
    end = timestamp(recovery["observation_end"], "recovery.observation_end")
    as_of = timestamp(plan["as_of"], "simulation.as_of")
    require(start < end, "recovery: observation window must have positive duration")
    blockers: set[str] = set()
    if any(action["state"] != "verified_effective_synthetic" for action in actions.values()):
        blockers.add("not_all_actions_verified_effective_synthetic")
    if end > as_of:
        blockers.add("observation_window_not_elapsed")
    verification_times = [timestamp(event["at"], "event.at") for event in plan["events"]
                          if event["kind"] == "verification"]
    if verification_times and start < max(verification_times):
        blockers.add("observation_window_precedes_action_verification")
    latest = max([end, *[timestamp(event["at"], "event.at") for event in plan["events"]]])
    monitored: set[tuple[str, str]] = set()
    for key, row in _refs(recovery["monitoring_refs"], records):
        action_id = row["action_id"]
        require(action_id in actions, "monitoring: unknown action")
        _observation(row, actions[action_id], actors, plan["as_of"], "monitoring",
                     attempts.get(action_id), as_of)
        pair = (action_id, row["target_id"])
        require(pair not in monitored, "monitoring: duplicate or conflicting target observations")
        monitored.add(pair)
        consumed.add(key)
        latest = max(latest, timestamp(row["at"], "record.at"))
        if (timestamp(row["window_start"], "record.window_start") > start or
                timestamp(row["window_end"], "record.window_end") < end):
            blockers.add("monitoring_window_incomplete")
        if row["observed_state"] != "clear":
            blockers.add("monitoring_not_clear")
    required = {(action_id, target) for action_id, action in actions.items()
                for target in action["target_ids"]}
    if monitored != required:
        blockers.add("monitoring_scope_incomplete")
    for key, row in records.items():
        if row["record_type"] in {"verification", "monitoring"} and key not in consumed:
            blockers.add("unconsumed_verification_or_monitoring_records")
        if key in consumed:
            latest = max(latest, timestamp(row["at"], "record.at"))
    used_evidence = {key[0] for key in consumed}
    for artifact in artifacts:
        if artifact["id"] in used_evidence:
            latest = max(latest, timestamp(artifact["collected_at"], "evidence.collected_at"))
    acceptance = recovery["acceptance"]
    if acceptance is None:
        blockers.add("reviewer_acceptance_missing")
    else:
        actor_role(actors, acceptance["reviewer_id"], "reviewer")
        accepted_at = timestamp(acceptance["at"], "acceptance.at")
        require(accepted_at <= as_of, "recovery: acceptance postdates as_of")
        if accepted_at <= latest:
            blockers.add("reviewer_acceptance_precedes_evidence_or_events")
        if acceptance["residual_risk_acknowledged"] is not True:
            blockers.add("residual_risk_not_acknowledged")
        if acceptance["closure_requested"] is not True:
            blockers.add("closure_not_requested")
    recovery.update(state="accepted_synthetic" if not blockers else "unverified",
                    simulation_closure_accepted=not blockers,
                    blocking_reasons=sorted(blockers))
    recovery["monitoring_refs"] = sorted(recovery["monitoring_refs"],
                                          key=lambda ref: (ref["evidence_id"], ref["record_id"]))
    return recovery


def replay(plan: dict, case_result: dict, records: dict[tuple[str, str], dict],
           artifacts: list[dict]) -> dict:
    """Replay already schema-validated inputs, without I/O or persistent state.

    The requested state is checked against the computed transition. An operator's
    acknowledgement is a receipt of an attempt, never proof of effectiveness.
    """
    actors = {actor["id"]: actor for actor in plan["actors"]}
    actions = {action["action_id"]: {**deepcopy(action), "state": "recommended",
                "approval": "not_recorded", "execution": "not_recorded",
                "verification": "not_recorded", "event_ids": [],
                "binding_sha256": action_binding_digest(plan, action)} for action in plan["actions"]}
    require(len(actions) == len(plan["actions"]), "simulation: duplicate action binding")
    approvals: dict[str, dict] = {}
    attempts: dict[str, dict] = {}
    consumed: set[tuple[str, str]] = set()
    seen_events: set[str] = set()
    last_time = None
    as_of = timestamp(plan["as_of"], "simulation.as_of")
    for event in plan["events"]:
        require(event["id"] not in seen_events, "simulation: duplicate event identity")
        seen_events.add(event["id"])
        at = timestamp(event["at"], "event.at")
        require((last_time is None or at >= last_time) and at <= as_of,
                "simulation: event chronology or as_of violated")
        last_time = at
        action_id = event["action_id"]
        require(action_id in actions, "simulation: unknown action")
        action = actions[action_id]
        require(sorted(event["target_ids"]) == sorted(action["target_ids"]),
                "simulation: event scope differs from exact action binding")
        require(event["previous_state"] == action["state"],
                "simulation: previous state differs from replay")
        kind = event["kind"]
        if kind == "approval":
            require(action["state"] == "recommended", "simulation: approval is not a permitted transition")
            actor_role(actors, event["approver_id"], "approver")
            require(not event["evidence_refs"], "approval: evidence references must be empty")
            require(timestamp(event["expires_at"], "approval.expires_at") > at,
                    "approval: expiry must follow approval")
            require(event["binding_sha256"] == action["binding_sha256"], "approval: binding digest differs")
            require(event["new_state"] in {"approved_simulated", "denied"}, "approval: unsupported decision")
            outcome = event["new_state"]
            action["approval"] = outcome
            approvals[action_id] = event
        elif kind == "attempt":
            require(action["state"] == "approved_simulated" and action_id in approvals,
                    "simulation: attempt requires approval")
            actor_role(actors, event["operator_id"], "operator")
            require(at < timestamp(approvals[action_id]["expires_at"], "approval.expires_at"),
                    "simulation: approval expired at attempt")
            selected = _refs(event["evidence_refs"], records)
            require(len(selected) == 1, "attempt: exactly one acknowledgement required")
            key, row = selected[0]
            validate_record(row, actions, actors, plan["as_of"])
            require(row["record_type"] == "acknowledgement", "attempt: acknowledgement required")
            require(row["action_id"] == action_id and row["operator_id"] == event["operator_id"] and
                    timestamp(row["at"], "record.at") == at,
                    "attempt: acknowledgement action, operator or time differs")
            require(key not in consumed, "attempt: acknowledgement already consumed")
            consumed.add(key)
            outcome = "attempted_simulated"
            action["execution"] = outcome
            action["acknowledged"] = row["acknowledged"]
            attempts[action_id] = event
        elif kind == "verification":
            require(action["state"] == "attempted_simulated" and action_id in attempts,
                    "simulation: verification requires an attempted action")
            selected = _refs(event["evidence_refs"], records)
            rows = []
            for key, row in selected:
                require(key not in consumed, "verification: evidence record already consumed")
                _observation(row, action, actors, plan["as_of"], "verification", attempts[action_id], at)
                consumed.add(key)
                rows.append(row)
            outcome = verification_outcome(action, rows)
            action["verification"] = outcome
        else:
            require(False, "simulation: unsupported event kind")
        require(event["new_state"] == outcome, "simulation: claimed new state differs from derived outcome")
        action["state"] = outcome
        action["event_ids"].append(event["id"])
    recovery = _recovery(plan, actions, attempts, records, artifacts, consumed, actors)
    result_actions = []
    for action_id in sorted(actions):
        action = actions[action_id]
        action["target_ids"] = sorted(action["target_ids"])
        action["supporting_observation_ids"] = sorted(action["supporting_observation_ids"])
        result_actions.append(action)
    return {"schema_version": "ir-simulation-result/1.0", "synthetic": True,
            "simulation_id": plan["simulation_id"], "case_id": plan["case_id"],
            "case_sha256": plan["case_sha256"], "result_sha256": plan["result_sha256"],
            "plan_sha256": digest(plan), "as_of": plan["as_of"],
            "actors": sorted(deepcopy(plan["actors"]), key=lambda actor: actor["id"]),
            "actions": result_actions,
            "events": [_canonical_event(event) for event in plan["events"]],
            "recovery": recovery, "evidence": sorted(deepcopy(artifacts), key=lambda item: item["id"]),
            "evidence_records": [{"evidence_id": evidence_id, **deepcopy(records[(evidence_id, record_id)])}
                                 for evidence_id, record_id in sorted(records)],
            "phase2a_triage": deepcopy(case_result["triage"]),
            "limitations": [
                "Offline synthetic exercise only; no account, session, message, endpoint or service was changed.",
                "Simulated approval is not operational authority; actors are fictional annotations, not authenticated identities.",
                "Hashes and action bindings establish consistency, not signatures or production forensic authenticity.",
                "Supplied synthetic observations are not independently acquired evidence or proof of real recovery.",
                "Replay is stateless and deterministic; it is not a signed, tamper-proof persistent audit log.",
                "Phase 2A incident_closure_verified remains false; synthetic closure never verifies a real incident."
            ]}
