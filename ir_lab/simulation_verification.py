"""Strict local synthetic response records and independent outcome derivation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import (CaseError, identifier, object_fields, require, timestamp,
                        unique_refs)
from .evidence import MAX_EVIDENCE_BYTES, json_pairs, safe_artifact, validate_artifacts

MAX_RECORDS = 1000
OBSERVED_STATES = {
    "investigate_signins": ("review_complete", "unauthorized_access_present"),
    "review_authentication_methods": ("trusted_methods_only", "untrusted_method_present"),
    "revoke_sessions": ("no_active_sessions", "active_session"),
    "quarantine_message": ("quarantined", "delivered"),
    "scope_recipients": ("scope_complete", "scope_incomplete"),
}
ACK_FIELDS = {"record_id", "record_type", "action_id", "kind", "target_ids", "at",
              "operator_id", "acknowledged"}
OBSERVATION_FIELDS = {"record_id", "record_type", "action_id", "kind", "target_id",
                      "at", "verifier_id", "observed_state", "window_start", "window_end"}


def actor_role(actors: dict[str, dict], actor_id: str, expected: str) -> None:
    """Roles are fictional annotations; they are never authenticated authority."""
    identifier(actor_id, "record.actor_id")
    require(actor_id in actors and actors[actor_id]["role"] == expected,
            f"simulation: {expected} role required")


def validate_record(row: dict, actions: dict[str, dict], actors: dict[str, dict],
                    as_of: str) -> dict:
    """Validate every supplied record, including records not nominated by events."""
    require(type(row) is dict, "simulation record: expected object")
    record_type = row.get("record_type")
    require(type(record_type) is str and
            record_type in {"acknowledgement", "verification", "monitoring"},
            "simulation record: unsupported record type")
    object_fields(row, ACK_FIELDS if record_type == "acknowledgement" else OBSERVATION_FIELDS,
                  set(), "simulation record")
    identifier(row["record_id"], "record.record_id")
    action_id = identifier(row["action_id"], "record.action_id")
    require(action_id in actions, "simulation record: unknown action")
    action = actions[action_id]
    require(row["kind"] == action["kind"], "simulation record: action kind differs")
    at = timestamp(row["at"], "record.at")
    require(at <= timestamp(as_of, "simulation.as_of"), "simulation record: future record")
    if record_type == "acknowledgement":
        targets = unique_refs(row["target_ids"], set(action["target_ids"]),
                              "record.target_ids", nonempty=True)
        require(sorted(targets) == sorted(action["target_ids"]),
                "acknowledgement: exact action targets required")
        actor_role(actors, row["operator_id"], "operator")
        require(type(row["acknowledged"]) is bool, "acknowledgement: expected boolean")
    else:
        identifier(row["target_id"], "record.target_id")
        require(row["target_id"] in action["target_ids"], "observation: target outside action scope")
        actor_role(actors, row["verifier_id"], "verifier")
        valid = ({"clear", "adverse", "unknown"} if record_type == "monitoring" else
                 {*OBSERVED_STATES[action["kind"]], "unknown"})
        require(type(row["observed_state"]) is str and row["observed_state"] in valid,
                "observation: unsupported state for action kind")
        start = timestamp(row["window_start"], "record.window_start")
        end = timestamp(row["window_end"], "record.window_end")
        require(start <= end <= at, "observation: invalid observation window")
    return row


def validate_unique_outcome_records(records: dict[tuple[str, str], dict]) -> None:
    """One outcome per type/action/target across ALL supplied artifacts in v1.

    Checking selected references alone permits a favorable event transition to
    conceal an adverse, unreferenced row. Retries/time-series reconciliation are
    unsupported, so even identical duplicate target outcomes fail closed.
    """
    seen: set[tuple[str, str, str]] = set()
    for row in records.values():
        if row["record_type"] not in {"verification", "monitoring"}:
            continue
        key = (row["record_type"], row["action_id"], row["target_id"])
        require(key not in seen, "simulation evidence: duplicate or conflicting per-target outcome records")
        seen.add(key)


def load_evidence(plan: dict, path: str | Path) -> tuple[list[dict], dict[tuple[str, str], dict]]:
    """Hash bounded local files, then parse and validate all UTF-8 JSONL rows.

    A second bounded read and digest comparison prevents parsing changed bytes
    after the artifact validator has returned. No acquisition or response occurs.
    """
    artifacts = validate_artifacts({"evidence": plan["evidence"]}, path)
    actions = {item["action_id"]: item for item in plan["actions"]}
    actors = {item["id"]: item for item in plan["actors"]}
    records: dict[tuple[str, str], dict] = {}
    for item in plan["evidence"]:
        require(item["path"].endswith(".jsonl"), "simulation evidence: JSONL artifact required")
        location = safe_artifact(Path(path).parent, item["path"])
        try:
            with location.open("rb") as stream:
                raw = stream.read(MAX_EVIDENCE_BYTES + 1)
            require(len(raw) <= MAX_EVIDENCE_BYTES and len(raw) == item["byte_length"] and
                    hashlib.sha256(raw).hexdigest() == item["sha256"],
                    "simulation evidence: source changed since integrity verification")
            lines = raw.decode("utf-8").split("\n")
        except (OSError, UnicodeError) as exc:
            raise CaseError("simulation evidence: cannot read UTF-8 JSONL") from exc
        if lines and lines[-1] == "":
            lines.pop()
        require(len(lines) <= MAX_RECORDS, "simulation evidence: too many records")
        collected = timestamp(item["collected_at"], "evidence.collected_at")
        require(collected <= timestamp(plan["as_of"], "simulation.as_of"),
                "simulation evidence: future collection")
        for line in lines:
            require(bool(line.strip()), "simulation evidence: blank record")
            try:
                row = json.loads(line, object_pairs_hook=json_pairs,
                                 parse_constant=lambda _: (_ for _ in ()).throw(
                                     CaseError("simulation JSON: nonfinite number")))
            except CaseError:
                raise
            except (json.JSONDecodeError, RecursionError, ValueError, OverflowError) as exc:
                raise CaseError("simulation evidence: malformed JSONL, oversized number, or excessive nesting") from exc
            validate_record(row, actions, actors, plan["as_of"])
            require(timestamp(row["at"], "record.at") <= collected,
                    "simulation evidence: record postdates collection")
            key = (item["id"], row["record_id"])
            require(key not in records, "simulation evidence: duplicate scoped record identity")
            records[key] = row
    validate_unique_outcome_records(records)
    return artifacts, records


def verification_outcome(action: dict, rows: list[dict]) -> str:
    """Derive one terminal synthetic outcome from unique target observations."""
    effective, adverse = OBSERVED_STATES[action["kind"]]
    seen: set[str] = set()
    states: list[str] = []
    for row in rows:
        require(row["target_id"] not in seen,
                "verification: duplicate or conflicting target observations")
        seen.add(row["target_id"])
        states.append(row["observed_state"])
    good = states.count(effective)
    if good == len(action["target_ids"]):
        return "verified_effective_synthetic"
    if good:
        return "partially_effective"
    if adverse in states:
        return "failed"
    return "unverified"
