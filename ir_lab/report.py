"""Render evidence-bounded reports from validated result data."""
from __future__ import annotations

import html


def safe(value: object) -> str:
    """Neutralize Markdown formatting, HTML, autolinks and inline code."""
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
        "- Successful account takeover: NOT established",
        "- Containment, recovery and case closure: NOT verified",
        "",
        "## Event Timeline",
        "",
        "| UTC event time | Observation | Type | Source | Evidence IDs |",
        "|---|---|---|---|---|",
    ]
    for obs in result["observations"]:
        text.append("| " + " | ".join(safe(x) for x in (
            obs["occurred_at_utc"], obs["id"], obs["kind"], obs["source"],
            ", ".join(obs["evidence_ids"]) or "none"
        )) + " |")
    text.extend(["", "### Observation Details", ""])
    for obs in result["observations"]:
        text.append(f"- **{safe(obs['id'])}:** {safe(obs['description'])} "
                    f"(source time: {safe(obs['occurred_at_source'])}; "
                    f"entities: {safe(', '.join(obs['entity_ids']))})")
    text.extend(["", "## Integrity-Checked Synthetic Evidence", "",
                 "A SHA-256 match demonstrates file consistency with this case manifest; "
                 "it does not establish independent acquisition authenticity or full custody.", ""])
    if not result["evidence"]:
        text.append("- No original or derived evidence artifacts supplied.")
    for item in result["evidence"]:
        text.append(f"- {safe(item['id'])}: {safe(item['path'])} "
                    f"({safe(item['kind'])}; {item['byte_length']} raw bytes; "
                    f"raw SHA-256 {safe(item['sha256_raw'])})")
    text.extend(["", "## Unverified Proposed Response Actions", "",
                 "Proposals are not approvals, attempts, executed actions, or verified outcomes.", ""])
    if not result["proposed_actions"]:
        text.append("- None; maintain investigation disposition and preserve evidence.")
    for item in result["proposed_actions"]:
        text.append(f"- {safe(item['id'])}: {safe(item['kind'])} for "
                    f"{safe(', '.join(item['target_ids']))}; "
                    f"{safe(item['state'])}. {safe(item['reason'])} "
                    "Approval: not recorded; execution: not recorded; verification: not recorded.")
    text.extend(["", "## Data Quality Warnings", ""])
    text.extend("- " + safe(x) for x in result["quality_warnings"])
    text.extend(["", "## Outstanding Investigation Questions", ""])
    if result["outstanding_questions"]:
        text.extend("- " + safe(x) for x in result["outstanding_questions"])
    else:
        text.append("- None for the case's current bounded disposition; reevaluate if new information emerges.")
    text.extend(["", "## Scope and Limitations", ""])
    text.extend("- " + safe(x) for x in result["limitations"])
    text.append("")
    return ("\n".join(text)).encode("utf-8")
