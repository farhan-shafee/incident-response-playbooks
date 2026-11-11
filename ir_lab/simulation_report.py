"""Deterministic Markdown receipts for synthetic approvals and simulated outcomes."""
from __future__ import annotations

import json

from .report import safe


def markdown(result: dict) -> bytes:
    recovery = result["recovery"]
    text = ["# Synthetic Incident Response Simulation", "",
            "> Offline exercise only. No real account, mailbox, session, endpoint or service changed.",
            "> All approvals, attempts, observations and closure decisions below are SIMULATED.", "",
            f"- Simulation: {safe(result['simulation_id'])}",
            f"- Case: {safe(result['case_id'])}",
            f"- Simulated as-of: {safe(result['as_of'])}",
            f"- Canonical case SHA-256: {safe(result['case_sha256'])}",
            f"- Phase 2A result SHA-256: {safe(result['result_sha256'])}",
            f"- Simulation plan SHA-256: {safe(result['plan_sha256'])}", "",
            "## Fictional Exercise Actors", ""]
    for actor in result["actors"]:
        text.append(f"- {safe(actor['id'])}: {safe(actor['display_name'])} "
                    f"(synthetic {safe(actor['role'])}).")
    text.extend(["", "## Simulated Action Outcomes", "",
            "Acknowledgement is not effectiveness. Each outcome is bounded to its synthetic evidence.", "",
            "| Action | Kind | Targets | Simulated state | Supporting observations |",
            "|---|---|---|---|---|"])
    for a in result["actions"]:
        text.append("| " + " | ".join(safe(v) for v in
                    (a["action_id"], a["kind"], ", ".join(a["target_ids"]), a["state"],
                     ", ".join(a["supporting_observation_ids"]))) + " |")
    text.extend(["", "### Simulated Status Receipts", ""])
    for a in result["actions"]:
        for field in ("approval", "execution", "verification"):
            if field in a:
                receipt = json.dumps(a[field], sort_keys=True, ensure_ascii=True)
                text.append(f"- {safe(a['action_id'])} simulated {field}: {safe(receipt)}")
    text.extend(["", "## Replayed Synthetic Event History", "",
                 "| Event | UTC instant | Action | Previous | New | Reason | Evidence references |",
                 "|---|---|---|---|---|---|---|"])
    for e in result["events"]:
        refs = ", ".join(r["evidence_id"] + ":" + r["record_id"] for r in e["evidence_refs"])
        text.append("| " + " | ".join(safe(v) for v in
                    (e["id"], e["at"], e["action_id"], e["previous_state"],
                     e["new_state"], e["reason"], refs or "none")) + " |")
    text.extend(["", "## Independent Synthetic Observations", "",
                 "An operator acknowledgement and a verifier's observed state are separate records.", ""])
    for row in result["evidence_records"]:
        reference = row["evidence_id"] + ":" + row["record_id"]
        if row["record_type"] == "acknowledgement":
            text.append(f"- {safe(reference)}: simulated {safe(row['kind'])} attempt for "
                        f"{safe(', '.join(row['target_ids']))}; operator {safe(row['operator_id'])}; "
                        f"Acknowledged: {str(row['acknowledged']).lower()}; at {safe(row['at'])}.")
        else:
            text.append(f"- {safe(reference)}: synthetic {safe(row['record_type'])} for "
                        f"{safe(row['action_id'])}/{safe(row['target_id'])}; "
                        f"observed {safe(row['observed_state'])}; verifier {safe(row['verifier_id'])}; "
                        f"window {safe(row['window_start'])} to {safe(row['window_end'])}; "
                        f"observed at {safe(row['at'])}.")
    text.extend(["", "## Integrity-Checked Synthetic Evidence", "",
                 "Hashes show consistency with the supplied manifest, not authenticity or forensic custody.", ""])
    for e in result["evidence"]:
        text.append(f"- {safe(e['id'])}: {safe(e['path'])}; {safe(e['kind'])}; "
                    f"{e['byte_length']} bytes; raw SHA-256 {safe(e['sha256_raw'])}; "
                    f"source {safe(e['source'])}; collected {safe(e['collected_at'])}.")
        if "parent_id" in e:
            text.append(f"  - Derived from {safe(e['parent_id'])} using {safe(e['transformation'])}.")
        if "sha256_normalized" in e:
            text.append(f"  - Normalized SHA-256 {safe(e['sha256_normalized'])} "
                        f"using {safe(e['normalization'])}.")
    text.extend(["", "## Simulated Recovery and Closure", "",
                 f"- Simulated recovery state: {safe(recovery['state'])}",
                 f"- Simulation closure accepted: {str(recovery['simulation_closure_accepted']).lower()}",
                 "- Real incident containment/recovery/closure: NOT verified by this simulator."])
    for reason in recovery["blocking_reasons"]:
        text.append("- Open gate: " + safe(reason))
    for field in ("residual_risks", "acceptance", "observation_start", "observation_end"):
        if field in recovery:
            text.append(f"- {safe(field)}: {safe(json.dumps(recovery[field], sort_keys=True, ensure_ascii=True))}")
    text.extend(["", "## Unchanged Phase 2A Assessment", "",
                 "The original triage assessment is retained; synthetic closure never rewrites it.", "",
                 safe(json.dumps(result["phase2a_triage"], sort_keys=True, ensure_ascii=True)),
                 "", "## Limitations", ""])
    text.extend("- " + safe(v) for v in result["limitations"])
    return ("\n".join(text) + "\n").encode("utf-8")
