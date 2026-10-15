"""Strict v1 synthetic incident-case contract. No external packages or I/O."""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

CASE_VERSION = "ir-case/1.0"
RESULT_VERSION = "ir-result/1.0"
ID = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$")
UTC_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
SHA = re.compile(r"^[0-9a-f]{64}$")
KINDS = {"message_delivery", "link_click", "credential_submission_report",
         "suspicious_sign_in", "authorized_activity", "benign_explanation",
         "identity_log_gap"}
ACTIONS = {"investigate_signins", "quarantine_message", "revoke_sessions",
           "review_authentication_methods", "scope_recipients"}
MAX_CASE_ITEMS = 80


class CaseError(ValueError):
    """Controlled invalid-input response; never contains artifact bytes."""


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise CaseError(explanation)


def object_fields(obj: Any, required: set[str], optional: set[str], label: str) -> dict:
    require(type(obj) is dict, f"{label}: expected object")
    missing = required - obj.keys()
    extra = obj.keys() - required - optional
    require(not missing and not extra, f"{label}: missing={sorted(missing)} unexpected={sorted(extra)}")
    return obj


def string(value: Any, label: str, *, limit: int = 500) -> str:
    require(type(value) is str and 0 < len(value) <= limit and
            not any(ord(c) < 32 or ord(c) == 127 for c in value),
            f"{label}: expected nonempty text without control characters")
    return value


def identifier(value: Any, label: str) -> str:
    require(type(value) is str and ID.fullmatch(value) is not None,
            f"{label}: invalid identifier")
    return value


def timestamp(value: Any, label: str) -> str:
    require(type(value) is str and UTC_TIME.fullmatch(value) is not None,
            f"{label}: offset-aware ISO 8601 timestamp required")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(dt.utcoffset() is not None and abs(dt.utcoffset().total_seconds()) < 86400,
                f"{label}: invalid UTC offset")
        return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise CaseError(f"{label}: invalid timestamp") from exc


def unique_refs(value: Any, valid: set[str], label: str, *, nonempty: bool = False) -> list[str]:
    require(type(value) is list and len(value) <= MAX_CASE_ITEMS and
            (bool(value) or not nonempty), f"{label}: invalid reference list")
    seen: set[str] = set()
    for ref in value:
        identifier(ref, label)
        require(ref in valid, f"{label}: unknown reference {ref}")
        require(ref not in seen, f"{label}: duplicate reference {ref}")
        seen.add(ref)
    return value


def document(case: Any) -> dict:
    """Validate schema, scoped references, and incident-state safety. No file reads."""
    object_fields(case, {"schema_version", "case_id", "synthetic", "category",
                         "entities", "evidence", "observations", "actions",
                         "coverage", "recovery"}, set(), "case")
    require(case["schema_version"] == CASE_VERSION, "case: unsupported schema version")
    identifier(case["case_id"], "case_id")
    require(case["synthetic"] is True, "case: only explicitly synthetic cases supported")
    require(case["category"] == "phishing", "case: Phase 2A supports phishing only")
    for group in ("entities", "evidence", "observations", "actions"):
        require(type(case[group]) is list and len(case[group]) <= MAX_CASE_ITEMS,
                f"{group}: expected bounded array")
    require(bool(case["entities"]) and bool(case["observations"]), "case: entities/observations required")

    ids: set[str] = set()
    def reserve(obj: dict, label: str) -> str:
        name = identifier(obj["id"], f"{label}.id")
        require(name not in ids, f"case: duplicate global identifier {name}")
        ids.add(name)
        return name

    entities: set[str] = set()
    for item in case["entities"]:
        object_fields(item, {"id", "kind", "value"}, set(), "entity")
        entities.add(reserve(item, "entity"))
        require(item["kind"] in ("user", "mailbox", "host", "ip"), "entity: invalid kind")
        string(item["value"], "entity.value", limit=160)

    evidence: set[str] = set()
    for item in case["evidence"]:
        object_fields(item, {"id", "path", "kind", "sha256", "byte_length",
                             "source", "collected_at"},
                      {"parent_id", "transformation", "normalization", "normalized_sha256"},
                      "evidence")
        evidence.add(reserve(item, "evidence"))
        string(item["path"], "evidence.path", limit=200)
        require(item["kind"] in ("original", "derived"), "evidence: invalid kind")
        require(type(item["sha256"]) is str and SHA.fullmatch(item["sha256"]) is not None,
                "evidence: invalid raw SHA-256")
        require(type(item["byte_length"]) is int and 0 <= item["byte_length"] <= 524288,
                "evidence: invalid byte length")
        string(item["source"], "evidence.source")
        timestamp(item["collected_at"], "evidence.collected_at")
        if item["kind"] == "derived":
            require("parent_id" in item and "transformation" in item, "derived evidence: parent and transformation required")
            identifier(item["parent_id"], "derived.parent_id")
            require(item["transformation"] == "utf8-bom-crlf-v1",
                    "derived evidence: unsupported transformation")
        else:
            require("parent_id" not in item and "transformation" not in item,
                    "original evidence must not claim derivation")
        has_normalization = "normalization" in item
        require(has_normalization == ("normalized_sha256" in item),
                "normalized digest requires explicit normalization and vice versa")
        if has_normalization:
            require(item["normalization"] == "utf8-bom-crlf-v1", "unsupported normalization")
            require(type(item["normalized_sha256"]) is str and SHA.fullmatch(item["normalized_sha256"]) is not None,
                    "invalid normalized SHA-256")
    for item in case["evidence"]:
        if item["kind"] == "derived":
            require(item["parent_id"] in evidence and item["parent_id"] != item["id"],
                    "derived evidence: missing/self parent")
    parent_map = {x["id"]: x.get("parent_id") for x in case["evidence"]}
    for evid in evidence:
        seen: set[str] = set()
        current: str | None = evid
        while current is not None:
            require(current not in seen, "evidence: derivation cycle")
            seen.add(current)
            current = parent_map[current]

    observation_ids: set[str] = set()
    event_ids: set[tuple[str, str]] = set()
    for item in case["observations"]:
        object_fields(item, {"id", "kind", "source", "entity_ids", "evidence_ids",
                             "occurred_at", "description"}, {"source_event_id"}, "observation")
        observation_ids.add(reserve(item, "observation"))
        require(type(item["kind"]) is str and item["kind"] in KINDS, "observation: unsupported kind")
        require(item["source"] in ("reported", "artifact"), "observation: unsupported source")
        unique_refs(item["entity_ids"], entities, "observation.entity_ids", nonempty=True)
        unique_refs(item["evidence_ids"], evidence, "observation.evidence_ids")
        timestamp(item["occurred_at"], "observation.occurred_at")
        string(item["description"], "observation.description")
        if item["source"] == "artifact":
            require(bool(item["evidence_ids"]), "artifact observation needs source evidence")
            require("source_event_id" in item, "artifact observation needs scoped event identity")
        if "source_event_id" in item:
            ev_id = identifier(item["source_event_id"], "source_event_id")
            for ref in item["evidence_ids"] if item["evidence_ids"] else ["reported"]:
                key = (ref, ev_id)
                require(key not in event_ids, "observation: conflicting/duplicate source event identity")
                event_ids.add(key)

    for item in case["actions"]:
        object_fields(item, {"id", "kind", "target_ids", "state", "reason"}, set(), "action")
        reserve(item, "action")
        require(type(item["kind"]) is str and item["kind"] in ACTIONS, "action: unsupported proposed action")
        unique_refs(item["target_ids"], entities, "action.target_ids", nonempty=True)
        string(item["reason"], "action.reason")
        require(item["state"] in ("recommended", "assumed_for_exercise"),
                "action: approval, execution and verification states are reserved for a later phase")

    object_fields(case["coverage"], {"identity_logs", "mail_logs", "endpoint_logs"},
                  set(), "coverage")
    for item in case["coverage"].values():
        require(item in ("available", "missing", "unknown"),
                "coverage: expected available/missing/unknown")
    object_fields(case["recovery"], {"state"}, set(), "recovery")
    require(case["recovery"]["state"] == "unverified",
            "recovery: verified closure requires a later evidence-backed workflow")
    return case
