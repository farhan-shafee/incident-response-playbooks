"""Evidence-scoped Markdown rendering of validated offline triage results."""
from __future__ import annotations

import html


def safe(value: object) -> str:
    """Escape Markdown syntax, literal HTML and autolinks from synthetic inputs."""
    raw = html.escape(str(value), quote=True)
    metacharacters = set("\\*_{}[]()#+-.!|" + chr(96))
    return "".join("\\" + char if char in metacharacters else char for char in raw)


def markdown(result: dict) -> bytes:
    triage = result["triage"]
    text = [
        "# Synthetic Incident Investigation Report",
        "",
        "> Offline, synthetic case only. This report is not a record of production",
        "> activity or proof that response, recovery, or incident closure occurred.",
        "",
        "## Case and Decision",
        "",
        f"- Case: {safe(result['case_id'])}",
        f"- Category: {safe(result['category'])}",
        f"- Disposition: {safe(triage['disposition'])}",
        f"- Provisional severity: {safe(triage['provisional_severity'])}",
        f"- Urgency: {safe(triage['urgency'])}",
        f"- Confidence: {safe(triage['confidence'])}",
        f"- Evidence rule: {safe(result['policy_ref'])}",
        f"- Rationale: {safe(triage['reason'])}",
        "- Supporting observation IDs: " +
            safe(", ".join(triage.get("supporting_observation_ids", [])) or "not supplied"),
        "- Successful account takeover: NOT established",
        "- Containment, recovery and case closure: NOT verified",
        "",
        "## Scoped Entities",
        "",
    ]
    for entity in result.get("entities", []):
        text.append(f"- {safe(entity['id'])} ({safe(entity['kind'])}): "
                    f"{safe(entity['value'])}")
    text.extend([
        "",
        "## Event Timeline",
        "",
        "| UTC event time | Observation | Kind | Entity IDs | Source event ID | Evidence IDs |",
        "|---|---|---|---|---|---|",
    ])
    for obs in result["observations"]:
        text.append("| " + " | ".join(safe(x) for x in (
            obs["occurred_at_utc"], obs["id"], obs["kind"],
            ", ".join(obs["entity_ids"]),
            obs.get("source_event_id", "reported; no source event ID"),
            ", ".join(obs["evidence_ids"]) or "none",
        )) + " |")
    text.extend(["", "### Observation Details", ""])
    for obs in result["observations"]:
        explains = obs.get("explains_observation_ids", [])
        linked = (f"; specifically explains: {safe(', '.join(explains))}"
                  if explains else "")
        text.append(f"- **{safe(obs['id'])}:** {safe(obs['description'])} "
                    f"(source time: {safe(obs['occurred_at_source'])}; "
                    f"entities: {safe(', '.join(obs['entity_ids']))}{linked})")
    text.extend(["", "### Correlated Synthetic Source Events", ""])
    if not result.get("correlated_event_references"):
        text.append("- No artifact-correlated event references supplied.")
    for reference in result.get("correlated_event_references", []):
        text.append(f"- Observation {safe(reference['observation_id'])} matched "
                    f"event {safe(reference['event_id'])} in "
                    f"artifact {safe(reference['evidence_id'])}.")
    text.extend([
        "",
        "## Integrity-Checked Synthetic Evidence",
        "",
        "A SHA-256 match establishes consistency with the supplied case manifest; "
        "it does not independently prove acquisition authenticity, custody, "
        "complete telemetry or the meaning of events.",
        "",
    ])
    if not result["evidence"]:
        text.append("- No original or derived evidence artifacts supplied.")
    for item in result["evidence"]:
        text.append(f"- {safe(item['id'])}: {safe(item['path'])} "
                    f"({safe(item['kind'])}; {item['byte_length']} raw bytes; "
                    f"raw SHA-256 {safe(item['sha256_raw'])}; "
                    f"source: {safe(item['source'])}; "
                    f"collected: {safe(item['collected_at'])})")
        if "parent_id" in item:
            text.append(f"  - Derived from: {safe(item['parent_id'])} "
                        f"using {safe(item['transformation'])}.")
        if "sha256_normalized" in item:
            text.append(f"  - Explicit normalized digest "
                        f"({safe(item['normalization'])}): "
                        f"{safe(item['sha256_normalized'])}.")
    text.extend([
        "",
        "## Unverified Proposed Response Actions",
        "",
        "Proposals are not approvals, attempts, executed actions, or verified outcomes.",
        "",
    ])
    if not result["proposed_actions"]:
        text.append("- None; maintain investigation disposition and preserve evidence.")
    for item in result["proposed_actions"]:
        text.append(f"- {safe(item['id'])}: {safe(item['kind'])} for "
                    f"{safe(', '.join(item['target_ids']))}; "
                    f"{safe(item['state'])}. {safe(item['reason'])} "
                    f"Supporting observation IDs: "
                    f"{safe(', '.join(item.get('supporting_observation_ids', [])))}. "
                    "Approval: not recorded; execution: not recorded; verification: not recorded.")
    text.extend(["", "## Data Quality Warnings", ""])
    text.extend("- " + safe(x) for x in result["quality_warnings"])
    text.extend(["", "## Outstanding Investigation Questions", ""])
    if result["outstanding_questions"]:
        text.extend("- " + safe(x) for x in result["outstanding_questions"])
    else:
        text.append("- None for the current bounded decision; reevaluate as new evidence arrives.")
    text.extend(["", "## Scope and Limitations", ""])
    text.extend("- " + safe(x) for x in result["limitations"])
    text.append("")
    return ("\n".join(text)).encode("utf-8")
