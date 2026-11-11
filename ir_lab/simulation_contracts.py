"""Strict synthetic simulation inputs, pinned to a validated Phase 2A context."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import (CaseError, SHA, document, identifier, object_fields,
                        require, string, timestamp, unique_refs)
from .evidence import MAX_CASE_BYTES, canonical_json, json_pairs, path_is_redirect

VERSION = "ir-simulation/1.0"
STATES = frozenset({"recommended", "approved_simulated", "denied", "attempted_simulated",
                    "partially_effective", "failed", "verified_effective_synthetic", "unverified"})
ROLES = frozenset({"approver", "operator", "verifier", "reviewer"})
MAX_EVENTS = 512


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def action_binding_digest(plan: dict, action: dict) -> str:
    bound = {**action, "target_ids": sorted(action["target_ids"]),
             "supporting_observation_ids": sorted(action["supporting_observation_ids"])}
    return digest({"case_id": plan["case_id"], "case_sha256": plan["case_sha256"],
                   "result_sha256": plan["result_sha256"], "action": bound})


def references(value: object, evidence_ids: set[str], label: str) -> list[dict]:
    require(type(value) is list and len(value) <= MAX_EVENTS, f"{label}: invalid references")
    seen = set()
    for ref in value:
        object_fields(ref, {"evidence_id", "record_id"}, set(), label)
        identifier(ref["evidence_id"], label)
        identifier(ref["record_id"], label)
        require(ref["evidence_id"] in evidence_ids, f"{label}: unknown artifact")
        key = (ref["evidence_id"], ref["record_id"])
        require(key not in seen, f"{label}: duplicate reference")
        seen.add(key)
    return value


def actor_role(plan: dict, actor_id: object, role: str) -> None:
    identifier(actor_id, role)
    require(any(a["id"] == actor_id and a["role"] == role for a in plan["actors"]),
            f"simulation: unknown synthetic {role}")


def validate_plan(plan: object, case: dict, result: dict) -> dict:
    """Validate metadata/bindings; caller supplies the fully verified case/result.

    Evidence bytes and legal transitions are checked separately before any output.
    No input boolean constitutes effectiveness, recovery or closure proof.
    """
    document(case)
    object_fields(plan, {"schema_version", "simulation_id", "synthetic", "case_id",
                         "case_sha256", "result_sha256", "as_of", "actors", "actions",
                         "evidence", "events", "recovery"}, set(), "simulation")
    require(plan["schema_version"] == VERSION, "simulation: unsupported schema_version")
    require(plan["synthetic"] is True, "simulation: synthetic must be true")
    identifier(plan["simulation_id"], "simulation_id")
    require(plan["case_id"] == case["case_id"] == result["case_id"], "simulation: wrong case binding")
    for name, expected in (("case_sha256", digest(case)), ("result_sha256", digest(result))):
        require(type(plan[name]) is str and SHA.fullmatch(plan[name]) is not None and
                plan[name] == expected, f"simulation: stale or incorrect {name}")
    require(result.get("synthetic") is True and "correlated_event_references" in result,
            "simulation: complete validated Phase 2A result required")
    as_of = timestamp(plan["as_of"], "simulation.as_of")
    for name, maximum in (("actors", 16), ("actions", 80), ("evidence", 80), ("events", MAX_EVENTS)):
        require(type(plan[name]) is list and len(plan[name]) <= maximum,
                f"simulation.{name}: expected bounded array")
    reserved = {x["id"] for group in ("entities", "evidence", "observations", "actions") for x in case[group]}
    for actor in plan["actors"]:
        object_fields(actor, {"id", "display_name", "role", "synthetic"}, set(), "actor")
        name = identifier(actor["id"], "actor.id")
        require(name.startswith("sim_") and name not in reserved, "actor: duplicate or non-synthetic ID")
        reserved.add(name)
        require(actor["synthetic"] is True, "actor: must be explicitly synthetic")
        require(type(actor["role"]) is str and actor["role"] in ROLES, "actor: unsupported role")
        string(actor["display_name"], "actor.display_name", limit=160)

    expected_actions = {a["id"]: a for a in result["proposed_actions"]}
    require(bool(expected_actions), "simulation: case has no proposed actions")
    require(len(expected_actions) == len(result["proposed_actions"]), "simulation: duplicate Phase 2A action")
    seen_actions = set()
    for action in plan["actions"]:
        object_fields(action, {"action_id", "kind", "target_ids", "supporting_observation_ids"},
                      set(), "simulation.action")
        action_id = identifier(action["action_id"], "simulation.action_id")
        require(action_id in expected_actions and action_id not in seen_actions,
                "simulation: unknown or duplicate action ID")
        seen_actions.add(action_id)
        expected = expected_actions[action_id]
        require(action["kind"] == expected["kind"], "simulation: action kind drift")
        for name in ("target_ids", "supporting_observation_ids"):
            unique_refs(action[name], set(expected[name]), f"simulation.action.{name}", nonempty=True)
            require(sorted(action[name]) == sorted(expected[name]), f"simulation: {name} scope drift")
    require(seen_actions == set(expected_actions), "simulation: every proposed action must be bound")
    reserved.update(expected_actions)

    # Reuse the exact Phase 2A descriptor contract (including parent/cycle rules)
    # without weakening or changing ir-case/1.0. Document validation performs no I/O.
    document({**case, "evidence": [*case["evidence"], *plan["evidence"]]})
    evidence_ids = {e["id"] for e in plan["evidence"]}
    require(not evidence_ids.intersection(reserved), "simulation: duplicate artifact/actor identifier")
    reserved.update(evidence_ids)
    for e in plan["evidence"]:
        require(e.get("parent_id", e["id"]) in evidence_ids,
                "simulation: derived parent must be retained in simulation evidence")
        require(timestamp(e["collected_at"], "evidence.collected_at") <= as_of,
                "simulation: evidence collected after as_of")

    bindings = {a["action_id"]: a for a in plan["actions"]}
    lower_bound = max([timestamp(o["occurred_at"], "observation") for o in case["observations"]] +
                      [timestamp(e["collected_at"], "collection") for e in case["evidence"]])
    require(as_of >= lower_bound, "simulation: as_of precedes validated case evidence")
    previous_time = lower_bound
    event_fields = {"id", "at", "action_id", "target_ids", "previous_state", "new_state",
                    "kind", "reason", "evidence_refs"}
    extras = {"approval": {"approver_id", "expires_at", "binding_sha256"},
              "attempt": {"operator_id"}, "verification": set()}
    for event in plan["events"]:
        require(type(event) is dict and type(event.get("kind")) is str and
                event["kind"] in extras, "simulation.event: unsupported kind")
        object_fields(event, event_fields | extras[event["kind"]], set(), "simulation.event")
        name = identifier(event["id"], "event.id")
        require(name not in reserved, "simulation: duplicate event/global ID")
        reserved.add(name)
        require(type(event["action_id"]) is str and event["action_id"] in bindings,
                "simulation.event: unknown action")
        action = bindings[event["action_id"]]
        unique_refs(event["target_ids"], set(action["target_ids"]), "event.target_ids", nonempty=True)
        require(sorted(event["target_ids"]) == sorted(action["target_ids"]), "simulation.event: scope drift")
        for state in ("previous_state", "new_state"):
            require(type(event[state]) is str and event[state] in STATES, "simulation.event: unknown state")
        at = timestamp(event["at"], "event.at")
        require(previous_time <= at <= as_of, "simulation: events out of order or outside as_of")
        previous_time = at
        string(event["reason"], "event.reason")
        references(event["evidence_refs"], evidence_ids, "event.evidence_refs")
        if event["kind"] == "approval":
            actor_role(plan, event["approver_id"], "approver")
            require(at < timestamp(event["expires_at"], "approval.expires_at"), "approval: invalid expiry")
            require(event["binding_sha256"] == action_binding_digest(plan, action),
                    "approval: stale case/action binding")
            require(not event["evidence_refs"], "approval: evidence refs belong to attempts/verification")
        elif event["kind"] == "attempt":
            actor_role(plan, event["operator_id"], "operator")
            require(len(event["evidence_refs"]) == 1, "attempt: exactly one acknowledgement required")

    recovery = plan["recovery"]
    object_fields(recovery, {"observation_start", "observation_end", "monitoring_refs",
                             "residual_risks", "acceptance"}, set(), "recovery")
    start = timestamp(recovery["observation_start"], "recovery.observation_start")
    end = timestamp(recovery["observation_end"], "recovery.observation_end")
    require(start < end, "recovery: invalid observation window")
    references(recovery["monitoring_refs"], evidence_ids, "recovery.monitoring_refs")
    risks = recovery["residual_risks"]
    require(type(risks) is list and len(risks) <= 80, "recovery: invalid residual risks")
    for risk in risks:
        string(risk, "residual risk")
    if recovery["acceptance"] is not None:
        accepted = recovery["acceptance"]
        object_fields(accepted, {"reviewer_id", "at", "rationale", "residual_risk_acknowledged",
                                 "closure_requested"}, set(), "recovery.acceptance")
        actor_role(plan, accepted["reviewer_id"], "reviewer")
        require(timestamp(accepted["at"], "acceptance.at") <= as_of, "acceptance: after as_of")
        string(accepted["rationale"], "acceptance.rationale")
        require(type(accepted["residual_risk_acknowledged"]) is bool and
                type(accepted["closure_requested"]) is bool, "acceptance: expected boolean requests")
    return plan


def load_plan(path: str | Path, case: dict, result: dict) -> dict:
    file = Path(path)
    require(file.is_file() and not path_is_redirect(file), "simulation: missing or redirected plan")
    try:
        with file.open("rb") as stream:
            raw = stream.read(MAX_CASE_BYTES + 1)
        require(len(raw) <= MAX_CASE_BYTES, "simulation: plan too large")
        plan = json.loads(raw.decode("utf-8"), object_pairs_hook=json_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(CaseError("JSON: nonfinite number")))
    except CaseError:
        raise
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise CaseError("simulation: invalid UTF-8 JSON, number or nesting") from exc
    except OSError as exc:
        raise CaseError("simulation: cannot read plan") from exc
    return validate_plan(plan, case, result)
