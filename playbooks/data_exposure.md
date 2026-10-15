# Data Exposure Incident Response Playbook

## Objective
Assess, contain, and remediate unauthorized data access or disclosure while supporting legal/compliance workflows.

## Severity Criteria
- **Low (SEV-3):** Suspected exposure with low-sensitivity data and limited scope.
- **Medium (SEV-2):** Confirmed exposure of internal/sensitive data with moderate scope.
- **High (SEV-1):** Exposure of regulated/high-value data or broad external disclosure.

## Initial Triage Steps
1. Confirm exposure vector (misconfiguration, credential abuse, sharing error, app flaw).
2. Classify data sensitivity and ownership.
3. Determine exposure window and access scope.
4. Identify affected systems and identities.

## Evidence to Collect
- Access and audit logs with source IDs, enabled event categories, collection/search windows, retention, and known gaps.
- Configuration/policy snapshots and change history showing whether and when an access path was available; do not equate exposure with observed access or exfiltration.
- Data inventory, classification, authorized owner, and sensitivity/regulated-data determination, with sources for those claims.
- Relevant approval tickets, alerts, discovery times, and decision records for legal/privacy review as needed.
- Preserve originals, configuration states, and relevant metadata before changes where feasible; document urgent risk-reduction exceptions and evidence limitations.

## Containment Steps
Use [documented response approval and verification](../docs/incident_response_methodology.md#response-action-status). Name the resource owner, approved target scope, service dependencies, and authorized emergency delegate.
- Propose the narrowest public/share access restriction and credential rotation justified by actual exposure risk; avoid disabling unrelated workloads or losing essential responder access.
- Verify effective external denial and intended internal access through approved tests, not only a successful policy-update request. Record failures and propagation delays.
- Preserve available access logs and snapshots, balancing urgent containment with preservation; record when collection could not precede necessary changes.
- Track affected identities, scope, unknown exposures, and corrective-action owner; an open permission alone does not prove data was read or copied.

## Eradication Steps
- Correct supported root causes (ACL, storage policy, configuration, or application flaw) through authorized and reviewable changes.
- Remove unauthorized copies or access artifacts **only from systems under authorized control** after preservation/legal decisions. For copies held by third parties or external systems, coordinate with counsel, affected parties, or relevant service providers; do not attempt unauthorized deletion.
- Propose protective checks for similar assets; verify each control's configuration and coverage before marking it complete.

## Recovery Steps
- Restore and test a least-privilege access model with positive authorized-access and negative unauthorized-access checks; record the resource and observation window.
- Validate effective configurations against approved baseline, including propagation behavior and logging availability.
- Monitor for repeat access anomalies within a defined window, document residual exposure uncertainty, and refer notification obligations to privacy/legal decision owners. Record accepted residual risk and closure criteria; absent logs cannot establish no disclosure.

## Communication / Escalation Guidance
- Engage legal/compliance/privacy early for regulated data.
- Use approved stakeholder messaging and update cadence.
- Track notification decisions and rationale.

## Post-Incident Review Steps
- Document root cause and data governance gaps.
- Prioritize preventive actions and ownership.

## MITRE ATT&CK Mapping (Useful)
- T1530: Data from Cloud Storage
- T1213: Data from Information Repositories
