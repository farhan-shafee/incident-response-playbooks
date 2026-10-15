"""Correlate claimed artifact observations against actual hashed JSONL event rows."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import CaseError, KINDS, identifier, object_fields, require, timestamp, unique_refs
from .evidence import MAX_EVIDENCE_BYTES, json_pairs, safe_artifact


def verify_event_references(case: dict, case_path: str | Path) -> list[dict]:
    """Fail closed on missing, contradictory, duplicate or forged event references.

    A matching row is only synthetic consistency evidence, NOT forensic authenticity.
    """
    base = Path(case_path).parent
    listed = {item["id"]: item for item in case["evidence"]}
    usable = {item for obs in case["observations"] if obs["source"] == "artifact"
              for item in obs["evidence_ids"]}
    streams: dict[str, dict[str, dict]] = {}
    for evidence_id in sorted(usable):
        item = listed[evidence_id]
        require(item["path"].endswith(".jsonl"),
                "artifact observation must reference a structured JSONL event stream")
        location = safe_artifact(base, item["path"])
        try:
            raw = location.read_bytes()
            require(len(raw) <= MAX_EVIDENCE_BYTES and
                    hashlib.sha256(raw).hexdigest() == item["sha256"],
                    "event source changed since integrity verification")
            lines = raw.decode("utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise CaseError("event stream: cannot read UTF-8 JSONL") from exc
        require(len(lines) <= 1000, "event stream: too many records")
        parsed: dict[str, dict] = {}
        for line in lines:
            require(bool(line.strip()), "event stream: blank record")
            try:
                row = json.loads(line, object_pairs_hook=json_pairs)
            except json.JSONDecodeError as exc:
                raise CaseError("event stream: malformed JSONL") from exc
            object_fields(row, {"event_id", "kind", "entity_ids", "occurred_at"},
                          {"summary"}, "event")
            event_id = identifier(row["event_id"], "event.event_id")
            require(event_id not in parsed, "event stream: duplicate event identity")
            require(type(row["kind"]) is str and row["kind"] in KINDS,
                    "event: unsupported kind")
            require(type(row["entity_ids"]) is list and bool(row["entity_ids"]),
                    "event: invalid entity references")
            unique_entities: set[str] = set()
            for entity_id in row["entity_ids"]:
                identifier(entity_id, "event.entity_id")
                require(entity_id not in unique_entities, "event: duplicate entity ID")
                unique_entities.add(entity_id)
            timestamp(row["occurred_at"], "event.occurred_at")
            if "summary" in row:
                require(type(row["summary"]) is str and len(row["summary"]) <= 500,
                        "event: invalid summary")
            parsed[event_id] = row
        streams[evidence_id] = parsed

    matched = []
    for obs in case["observations"]:
        if obs["source"] != "artifact":
            continue
        for evidence_id in obs["evidence_ids"]:
            source = streams[evidence_id]
            event_id = obs["source_event_id"]
            require(event_id in source, f"observation {obs['id']}: source event not found")
            row = source[event_id]
            require(row["kind"] == obs["kind"], f"observation {obs['id']}: kind differs from event")
            require(sorted(row["entity_ids"]) == sorted(obs["entity_ids"]),
                    f"observation {obs['id']}: entity IDs differ from event")
            require(timestamp(row["occurred_at"], "event.occurred_at") ==
                    timestamp(obs["occurred_at"], "observation.occurred_at"),
                    f"observation {obs['id']}: event time differs from artifact")
            matched.append({"observation_id": obs["id"], "evidence_id": evidence_id,
                            "event_id": event_id})
    return sorted(matched, key=lambda e: (e["observation_id"], e["evidence_id"]))
