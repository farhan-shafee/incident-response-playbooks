"""Conservative evidence-aware phishing triage; pure deterministic logic."""
from __future__ import annotations

from .contracts import RESULT_VERSION, timestamp

POLICY = "playbooks/phishing.md#severity-criteria"
NEXT_STEPS = {
    "investigate_signins": "Review time-bounded identity sign-ins, MFA and session coverage.",
    "review_authentication_methods": "Review registered MFA, recovery methods and trusted devices.",
    "revoke_sessions": "Propose scoped revocation; human approval and app-specific verification required.",
    "scope_recipients": "Scope recipients, delivery, exposure and mailbox activity.",
    "quarantine_message": "Propose message quarantine; verify recipient scope and administrative approval.",
}


def evaluate(case: dict, artifacts: list[dict]) -> dict:
    """Produce explained triage, never an auto-declared incident or verified response."""
    observations = sorted(case["observations"], key=lambda o: o["id"])
    kinds = {obs["kind"] for obs in observations}
    submitted = "credential_submission_report" in kinds
    suspicious = "suspicious_sign_in" in kinds
    clicked = "link_click" in kinds
    delivered = "message_delivery" in kinds
    coverage = case["coverage"]
    types = {entity["id"]: entity["kind"] for entity in case["entities"]}
    recipients = {ent for obs in observations if obs["kind"] == "message_delivery"
                  for ent in obs["entity_ids"] if types[ent] in ("user", "mailbox")}
    multiple_recipients = len(recipients) > 1
    benign_supported = ("benign_explanation" in kinds and
                       "authorized_activity" in kinds and
                       not submitted and not suspicious and not clicked and
                       coverage["identity_logs"] == "available" and
                       all(o["source"] == "artifact" for o in observations
                           if o["kind"] in {"benign_explanation", "authorized_activity"}))
    if submitted:
        severity, urgency, disposition, rule = (
            "SEV-1", "urgent", "suspected_incident",
            "Reported credential submission triggers provisional SEV-1; takeover remains unproven.")
    elif benign_supported:
        severity, urgency, disposition, rule = (
            "none", "routine", "benign_explained",
            "Corroborated authorized-activity explanation with no reported credential exposure.")
    elif clicked or multiple_recipients:
        severity, urgency, disposition, rule = (
            "SEV-2", "elevated", "needs_investigation",
            "Link interaction or multiple reported recipients meets the phishing SEV-2 criterion; malicious access is not established.")
    elif delivered and not suspicious:
        severity, urgency, disposition, rule = (
            "SEV-3", "routine", "needs_investigation",
            "Single suspicious message with no recorded interaction meets SEV-3; check unknowns.")
    else:
        severity, urgency, disposition, rule = (
            "pending", "elevated", "needs_investigation",
            "Available facts do not establish a phishing severity criterion; escalate separately as warranted.")

    supported = [obs for obs in observations if obs["source"] == "artifact"]
    incomplete = (coverage["identity_logs"] != "available" or
                  "identity_log_gap" in kinds)
    confidence = "medium" if supported and not incomplete else "low"
    warnings = ["offline_synthetic_data_only", "containment_and_recovery_unverified"]
    for category in sorted(coverage):
        if coverage[category] != "available":
            warnings.append(f"{category}_{coverage[category]}")
    if not supported:
        warnings.append("no_artifact_correlated_observations")
    if submitted or suspicious:
        warnings.append("successful_account_takeover_not_established")
    if benign_supported:
        warnings.append("benign_explanation_is_case_scoped_not_universal")

    questions = []
    if submitted:
        questions.extend([
            "Did any unauthorized authentication actually succeed after the reported submission?",
            "Are MFA, recovery methods, sessions, OAuth grants and mailbox rules accounted for?",
            "What authorized containment actions were attempted and independently verified?",
        ])
    elif suspicious:
        questions.append("Do access logs substantiate unauthorized account use?")
    if coverage["identity_logs"] != "available":
        questions.append("What identity-provider coverage or independent evidence can close the sign-in gap?")
    if coverage["mail_logs"] != "available":
        questions.append("Can message recipients, delivery, and downstream mailbox access be scoped?")
    if not questions and not benign_supported:
        questions.append("What further evidence would confirm or refute the phishing hypothesis?")

    entities = sorted(case["entities"], key=lambda e: e["id"])
    timeline = [{
        "id": obs["id"],
        "kind": obs["kind"],
        "source": obs["source"],
        "occurred_at_source": obs["occurred_at"],
        "occurred_at_utc": timestamp(obs["occurred_at"], "observation.occurred_at"),
        "entity_ids": sorted(obs["entity_ids"]),
        "evidence_ids": sorted(obs["evidence_ids"]),
        "description": obs["description"],
    } for obs in observations]
    timeline.sort(key=lambda row: (row["occurred_at_utc"], row["id"]))

    proposed = [{
        "id": item["id"], "kind": item["kind"],
        "target_ids": sorted(item["target_ids"]),
        "state": item["state"], "reason": item["reason"],
        "approval": "not_recorded", "execution": "not_recorded",
        "verification": "not_recorded"
    } for item in sorted(case["actions"], key=lambda a: a["id"])]

    if not benign_supported:
        recommended = (["scope_recipients", "investigate_signins",
                        "review_authentication_methods", "revoke_sessions"]
                       if submitted else
                       ["scope_recipients", "investigate_signins"] if clicked or suspicious
                       else ["scope_recipients"])
        target = [x["id"] for x in entities if x["kind"] in ("user", "mailbox")]
        if not target:
            target = [entities[0]["id"]]
        already = {(a["kind"], tuple(a["target_ids"])) for a in proposed}
        for kind in recommended:
            key = (kind, tuple(sorted(target)))
            if key in already:
                continue
            proposed.append({
                "id": f"policy_{kind}", "kind": kind,
                "target_ids": sorted(target), "state": "recommended",
                "reason": NEXT_STEPS[kind],
                "approval": "not_recorded", "execution": "not_recorded",
                "verification": "not_recorded"
            })
    proposed.sort(key=lambda a: (a["kind"], a["id"]))

    return {
        "schema_version": RESULT_VERSION,
        "case_id": case["case_id"],
        "synthetic": True,
        "category": case["category"],
        "policy_ref": POLICY,
        "triage": {
            "disposition": disposition,
            "provisional_severity": severity,
            "urgency": urgency,
            "confidence": confidence,
            "reason": rule,
            "account_takeover_confirmed": False,
            "recovery_state": "unverified",
            "incident_closure_verified": False
        },
        "observations": timeline,
        "evidence": artifacts,
        "quality_warnings": sorted(warnings),
        "outstanding_questions": questions,
        "proposed_actions": proposed,
        "limitations": [
            "Synthetic artifacts and event matching do not establish production forensic authenticity.",
            "No identity-provider, mailbox, endpoint or other live response action was performed.",
            "Proposed actions never constitute approval, execution, verification or recovery."
        ]
    }
