"""Create/check deterministic synthetic incident fixtures. No real data or network."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "ir_cases"


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def log(*events: dict) -> bytes:
    return b"".join((json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                    for item in events)


def create() -> dict[str, bytes]:
    mail_at = "2026-10-01T09:00:00-04:00"
    login_at = "2026-10-01T13:15:00Z"
    benign_at = "2026-10-03T10:00:00Z"
    event_mail = {"event_id": "mail_001", "kind": "message_delivery",
                  "entity_ids": ["user_alex"], "occurred_at": mail_at,
                  "summary": "Synthetic invoice-login lure delivered"}
    event_login = {"event_id": "login_001", "kind": "suspicious_sign_in",
                   "entity_ids": ["user_alex"], "occurred_at": login_at,
                   "summary": "Synthetic unusual sign-in alert, authorization unknown"}
    raw_report = b"\xef\xbb\xbfSynthetic user report: entered a password on an unfamiliar invoice page.\r\n"
    normalized = raw_report.decode("utf-8-sig").replace("\r\n", "\n").encode("utf-8")
    blobs = {
        "artifacts/mail_events.jsonl": log(event_mail),
        "artifacts/identity_events.jsonl": log(event_login),
        "artifacts/report_raw.txt": raw_report,
        "artifacts/report_normalized.txt": normalized,
        "artifacts/incomplete_note.txt":
            b"Synthetic caller reports entering a password; service logs not collected.\n",
        "artifacts/benign_events.jsonl": log(
            {"event_id": "benign_mail_001", "kind": "message_delivery",
             "entity_ids": ["user_ben"], "occurred_at": benign_at,
             "summary": "Authorized internal simulation email"},
            {"event_id": "authorized_001", "kind": "authorized_activity",
             "entity_ids": ["user_ben"], "occurred_at": "2026-10-03T10:01:00Z",
             "summary": "Scheduled simulation activity recorded by owner"},
            {"event_id": "explanation_001", "kind": "benign_explanation",
             "entity_ids": ["user_ben"], "occurred_at": "2026-10-03T10:02:00Z",
             "summary": "Change ticket tied to the synthetic simulation"})
    }

    def evidence(identifier: str, path: str, source: str, **extra: object) -> dict:
        raw = blobs[path]
        return {"id": identifier, "path": path, "kind": "original",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "byte_length": len(raw), "source": source,
                "collected_at": "2026-10-04T12:00:00Z", **extra}

    def obs(identifier: str, kind: str, source: str, user: str, event_at: str,
            description: str, ev_ids: list[str], event_id: str | None = None) -> dict:
        result = {"id": identifier, "kind": kind, "source": source,
                  "entity_ids": [user], "evidence_ids": ev_ids,
                  "occurred_at": event_at, "description": description}
        if event_id is not None:
            result["source_event_id"] = event_id
        return result

    def case(case_id: str, user: str, evidence_items: list[dict],
             observations: list[dict], coverage: dict, actions: list[dict] | None = None) -> dict:
        return {"schema_version": "ir-case/1.0", "case_id": case_id,
                "synthetic": True, "category": "phishing",
                "entities": [{"id": user, "kind": "user", "value": user + "@example.test"}],
                "evidence": evidence_items, "observations": observations,
                "actions": actions or [], "coverage": coverage,
                "recovery": {"state": "unverified"}}

    raw_evidence = evidence("user_report_raw", "artifacts/report_raw.txt",
                            "Synthetic user statement",
                            normalization="utf8-bom-crlf-v1",
                            normalized_sha256=hashlib.sha256(normalized).hexdigest())
    derived = evidence("user_report_derived", "artifacts/report_normalized.txt",
                       "Derived copy of synthetic statement")
    derived.update(kind="derived", parent_id="user_report_raw",
                   transformation="utf8-bom-crlf-v1")
    positive = case("LAB-IR-POSITIVE", "user_alex", [
        evidence("mail_evidence", "artifacts/mail_events.jsonl", "Synthetic message audit"),
        evidence("identity_evidence", "artifacts/identity_events.jsonl", "Synthetic sign-in audit"),
        raw_evidence, derived
    ], [
        obs("obs_delivery", "message_delivery", "artifact", "user_alex", mail_at,
            "Synthetic invoice-themed phishing message delivered.", ["mail_evidence"], "mail_001"),
        obs("obs_submission", "credential_submission_report", "reported", "user_alex",
            "2026-10-01T09:05:00-04:00",
            "User reports entering credentials; account takeover not confirmed.",
            ["user_report_raw"]),
        obs("obs_signin", "suspicious_sign_in", "artifact", "user_alex", login_at,
            "Unfamiliar sign-in alert; legitimacy and success remain undetermined.",
            ["identity_evidence"], "login_001")
    ], {"identity_logs": "available", "mail_logs": "available", "endpoint_logs": "missing"}, [
        {"id": "action_revoke", "kind": "revoke_sessions", "target_ids": ["user_alex"],
         "state": "recommended", "reason": "Consider authorized session controls; not executed."}
    ])

    benign = case("LAB-IR-BENIGN", "user_ben", [
        evidence("benign_log", "artifacts/benign_events.jsonl", "Synthetic approved activity audit")
    ], [
        obs("obs_ben_mail", "message_delivery", "artifact", "user_ben", benign_at,
            "Synthetic planned exercise email arrived.", ["benign_log"], "benign_mail_001"),
        obs("obs_ben_auth", "authorized_activity", "artifact", "user_ben",
            "2026-10-03T10:01:00Z", "Approved simulation activity recorded.",
            ["benign_log"], "authorized_001"),
        obs("obs_ben_explain", "benign_explanation", "artifact", "user_ben",
            "2026-10-03T10:02:00Z", "Change-control record explains activity.",
            ["benign_log"], "explanation_001")
    ], {"identity_logs": "available", "mail_logs": "available", "endpoint_logs": "available"})

    incomplete = case("LAB-IR-INCOMPLETE", "user_casey", [
        evidence("reported_note", "artifacts/incomplete_note.txt", "Synthetic telephone report")
    ], [
        obs("obs_report_only", "credential_submission_report", "reported", "user_casey",
            "2026-10-02T17:00:00Z", "Caller reports credential submission; logs unavailable.",
            ["reported_note"])
    ], {"identity_logs": "missing", "mail_logs": "missing", "endpoint_logs": "unknown"})

    adversarial = copy.deepcopy(positive)
    adversarial["case_id"] = "LAB-IR-ADVERSARIAL"
    duplicate = copy.deepcopy(positive["observations"][0])
    duplicate["id"] = "obs_conflict"
    duplicate["kind"] = "suspicious_sign_in"
    adversarial["observations"].append(duplicate)
    cases = {"positive.json": positive, "benign.json": benign,
             "incomplete.json": incomplete, "adversarial.json": adversarial}
    return {**blobs, **{name: encoded(doc) for name, doc in cases.items()}}


def main() -> None:
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true",
                       help="Create fixture files without overwriting anything")
    group.add_argument("--check", action="store_true",
                       help="Read-only byte-for-byte reproducibility verification")
    args = p.parse_args()
    files = create()
    for name, raw in files.items():
        dest = ROOT / name
        if args.write:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("xb") as stream:
                stream.write(raw)
        else:
            assert dest.read_bytes() == raw, f"Fixture drift: {name}"
    print(f"{'CREATED' if args.write else 'PASS'} {len(files)} deterministic synthetic fixtures")


if __name__ == "__main__":
    main()
