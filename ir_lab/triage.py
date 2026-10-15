"""Conservative, entity- and observation-scoped synthetic phishing triage."""
from __future__ import annotations

from .contracts import (ACTION_TARGET_KINDS, ACTION_TRIGGER_KINDS, RESULT_VERSION,
                        require, timestamp)

POLICY = "playbooks/phishing.md#severity-criteria"
NEXT_STEPS = {
    "investigate_signins": "Review time-bounded identity sign-ins, MFA and session coverage.",
    "review_authentication_methods": "Review registered MFA, recovery methods and trusted devices.",
    "revoke_sessions": "Propose scoped revocation; human approval and app-specific verification required.",
    "scope_recipients": "Scope recipients, delivery, exposure and mailbox activity.",
    "quarantine_message": "Propose message quarantine; verify recipient scope and administrative approval.",
}
BENIGN_KINDS = frozenset({"message_delivery", "authorized_activity", "benign_explanation"})


def action_evidence(kind: str, targets: list[str], observations: list[dict]) -> list[str]:
    """List actual triggering observations for an action's exact entity scope."""
    return sorted(obs["id"] for obs in observations
                  if obs["kind"] in ACTION_TRIGGER_KINDS[kind] and
                  set(obs["entity_ids"]).intersection(targets))


def matched_benign_explanation(observations: list[dict], visibility_ok: bool) -> bool:
    """Every delivered event must have directly correlated, explicitly linked
    authorization AND benign explanation for its exact affected entity set.

    A label attached to an unrelated user/event cannot clear an unexplained
    delivery. Inputs were already checked against retained event rows.
    """
    delivered = [obs for obs in observations if obs["kind"] == "message_delivery"]
    if not visibility_ok or not delivered or any(o["kind"] not in BENIGN_KINDS
                                                for o in observations):
        return False
    if any(o["source"] != "artifact" for o in observations):
        return False
    authors = [o for o in observations if o["kind"] == "authorized_activity"]
    reasons = [o for o in observations if o["kind"] == "benign_explanation"]
    if not authors or not reasons:
        return False
    # Unlinked or extra unexplained authorization evidence must not produce
    # a case-wide benign finding.
    if any(not o.get("explains_observation_ids") for o in authors + reasons):
        return False
    for delivery in delivered:
        linked = lambda other: (delivery["id"] in other.get("explains_observation_ids", [])
                                and set(delivery["entity_ids"]).issubset(other["entity_ids"]))
        if not any(linked(o) for o in authors) or not any(linked(o) for o in reasons):
            return False
    return True


def evaluate(case: dict, artifacts: list[dict]) -> dict:
    """Pure triage of already validated local evidence; never real containment."""
    observations = sorted(case["observations"], key=lambda o: o["id"])
    kinds = {obs["kind"] for obs in observations}
    submitted = "credential_submission_report" in kinds
    suspicious = "suspicious_sign_in" in kinds
    clicked = "link_click" in kinds
    delivered = "message_delivery" in kinds

    coverage = case["coverage"]
    explicit_identity_gap = "identity_log_gap" in kinds
    visibility_ok = (coverage["identity_logs"] == "available" and
                     coverage["mail_logs"] == "available" and
                     not explicit_identity_gap)
    benign_supported = matched_benign_explanation(observations, visibility_ok)

    entities = sorted(case["entities"], key=lambda e: e["id"])
    types = {e["id"]: e["kind"] for e in entities}
    recipients = {ent for obs in observations if obs["kind"] == "message_delivery"
                  for ent in obs["entity_ids"] if types[ent] in {"user", "mailbox"}}
    multiple_recipients = len(recipients) > 1
    if submitted:
        severity, urgency, disposition, rule = (
            "SEV-1", "urgent", "suspected_incident",
            "Reported credential submission triggers provisional SEV-1; takeover remains unproven.")
        decision_obs = [o["id"] for o in observations if o["kind"] == "credential_submission_report"]
    elif benign_supported:
        severity, urgency, disposition, rule = (
            "none", "routine", "benign_explained",
            "Artifact-correlated authorization and benign explanations explicitly cover every delivered event and entity.")
        decision_obs = [o["id"] for o in observations]
    elif clicked or multiple_recipients:
        severity, urgency, disposition, rule = (
            "SEV-2", "elevated", "needs_investigation",
            "Link interaction or multiple recipients meets the phishing SEV-2 criterion; account access remains unconfirmed.")
        decision_obs = [o["id"] for o in observations
                        if o["kind"] == "link_click" or
                        (multiple_recipients and o["kind"] == "message_delivery")]
    elif delivered and not suspicious:
        severity, urgency, disposition, rule = (
            "SEV-3", "routine", "needs_investigation",
            "A suspicious delivered message with no documented interaction meets SEV-3; consider unknowns.")
        decision_obs = [o["id"] for o in observations if o["kind"] == "message_delivery"]
    else:
        severity, urgency, disposition, rule = (
            "pending", "elevated", "needs_investigation",
            "Available observations do not substantiate a phishing severity criterion; escalate independently as warranted.")
        decision_obs = [o["id"] for o in observations
                        if o["kind"] in {"suspicious_sign_in", "identity_log_gap"}]

    # A reported logging gap remains a gap even when the summary coverage says
    # "available"; such disagreement must be reconciled rather than cleared.
    if explicit_identity_gap and urgency == "routine":
        urgency = "elevated"

    supported = [obs for obs in observations if obs["source"] == "artifact"]
    incomplete = (coverage["identity_logs"] != "available" or
                  explicit_identity_gap)
    confidence = "medium" if supported and not incomplete else "low"

    warnings = ["offline_synthetic_data_only", "containment_and_recovery_unverified"]
    for category in sorted(coverage):
        if coverage[category] != "available":
            warnings.append(f"{category}_{coverage[category]}")
    if explicit_identity_gap:
        warnings.append("explicit_identity_log_gap")
        if coverage["identity_logs"] == "available":
            warnings.append("identity_coverage_contradiction")
    if not supported:
        warnings.append("no_artifact_correlated_observations")
    if submitted or suspicious:
        warnings.append("successful_account_takeover_not_established")
    if benign_supported:
        warnings.append("benign_explanation_is_case_scoped_not_universal")
    elif {"authorized_activity", "benign_explanation"}.intersection(kinds):
        warnings.append("benign_evidence_does_not_explain_all_affected_events")

    questions: list[str] = []
    if submitted:
        questions.extend([
            "Did any unauthorized authentication actually succeed after the reported submission?",
            "Are MFA, recovery methods, sessions, OAuth grants and mailbox rules accounted for?",
            "What authorized containment actions were attempted and independently verified?",
        ])
    elif suspicious:
        questions.append("Do access logs substantiate unauthorized account use?")
    if coverage["identity_logs"] != "available" or explicit_identity_gap:
        questions.append(
            "Reconcile any explicit identity log gap with declared coverage and locate independent authentication evidence.")
    if coverage["mail_logs"] != "available":
        questions.append("Can message recipients, delivery, and downstream mailbox access be scoped?")
    if "benign_evidence_does_not_explain_all_affected_events" in warnings:
        questions.append(
            "Which specific deliveries and affected entities are explicitly covered by artifact-backed authorization and explanations?")
    if not questions and not benign_supported:
        questions.append("What further evidence would confirm or refute the phishing hypothesis?")

    timeline = [{
        "id": obs["id"], "kind": obs["kind"], "source": obs["source"],
        "occurred_at_source": obs["occurred_at"],
        "occurred_at_utc": timestamp(obs["occurred_at"], "observation.occurred_at"),
        "entity_ids": sorted(obs["entity_ids"]),
        "evidence_ids": sorted(obs["evidence_ids"]),
        "description": obs["description"],
        **({"source_event_id": obs["source_event_id"]}
           if "source_event_id" in obs else {}),
        **({"explains_observation_ids": sorted(obs["explains_observation_ids"])}
           if "explains_observation_ids" in obs else {})
    } for obs in observations]
    timeline.sort(key=lambda row: (row["occurred_at_utc"], row["id"]))

    proposed = [{
        "id": item["id"], "kind": item["kind"],
        "target_ids": sorted(item["target_ids"]),
        "supporting_observation_ids": action_evidence(
            item["kind"], item["target_ids"], observations),
        "state": item["state"], "reason": item["reason"],
        "approval": "not_recorded", "execution": "not_recorded",
        "verification": "not_recorded"
    } for item in sorted(case["actions"], key=lambda a: a["id"])]

    reserved_ids = {item["id"] for group in ("entities", "evidence", "observations", "actions")
                    for item in case[group]}
    if not benign_supported:
        recommended = (["scope_recipients", "investigate_signins",
                        "review_authentication_methods", "revoke_sessions"]
                       if submitted else
                       ["scope_recipients", "investigate_signins"]
                       if clicked or suspicious else
                       ["scope_recipients"] if delivered else [])
        existing = {(a["kind"], tuple(a["target_ids"])) for a in proposed}
        missing_identity_mapping = False
        for kind in recommended:
            triggering = [obs for obs in observations
                          if obs["kind"] in ACTION_TRIGGER_KINDS[kind]]
            target_ids = sorted({
                entity_id for obs in triggering for entity_id in obs["entity_ids"]
                if types[entity_id] in ACTION_TARGET_KINDS[kind]
            })
            if not target_ids:
                if kind in {"investigate_signins", "review_authentication_methods", "revoke_sessions"}:
                    missing_identity_mapping = True
                continue
            key = (kind, tuple(target_ids))
            if key in existing:
                continue
            base_id = f"policy_{kind}"
            identifier = base_id
            count = 2
            while identifier in reserved_ids:
                identifier = f"{base_id}_{count}"
                count += 1
            reserved_ids.add(identifier)
            supporting = action_evidence(kind, target_ids, observations)
            require(bool(supporting), "generated action must have supporting observations")
            proposed.append({
                "id": identifier, "kind": kind,
                "target_ids": target_ids,
                "supporting_observation_ids": supporting,
                "state": "recommended",
                "reason": NEXT_STEPS[kind],
                "approval": "not_recorded",
                "execution": "not_recorded", "verification": "not_recorded"
            })
            existing.add(key)
        if missing_identity_mapping:
            warnings.append("identity_action_target_mapping_missing")
            questions.append(
                "Identify and corroborate the affected user identity before proposing sign-in, authentication-method, or session actions.")

    proposed.sort(key=lambda a: (a["kind"], a["id"]))
    require(len({a["id"] for a in proposed}) == len(proposed),
            "result: duplicate proposed action identifiers")

    return {
        "schema_version": RESULT_VERSION,
        "case_id": case["case_id"],
        "synthetic": True,
        "category": case["category"],
        "policy_ref": POLICY,
        "entities": entities,
        "triage": {
            "disposition": disposition,
            "provisional_severity": severity,
            "urgency": urgency,
            "confidence": confidence,
            "reason": rule,
            "supporting_observation_ids": sorted(decision_obs),
            "account_takeover_confirmed": False,
            "recovery_state": "unverified",
            "incident_closure_verified": False
        },
        "observations": timeline,
        "evidence": artifacts,
        "quality_warnings": sorted(set(warnings)),
        "outstanding_questions": questions,
        "proposed_actions": proposed,
        "limitations": [
            "Synthetic artifacts and event matching do not establish production forensic authenticity.",
            "Only nominated, correlated observations are evaluated; unreferenced log rows are not independently hunted.",
            "No identity-provider, mailbox, endpoint or other live response action was performed.",
            "Proposed actions never constitute approval, execution, verification or recovery."
        ]
    }
