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
- Access logs and audit trails for exposed data stores.
- Configuration snapshots and change history.
- Data inventory/classification references.
- Relevant tickets, alerts, and timestamps.

## Containment Steps
- Revoke public/shared access and rotate exposed credentials.
- Restrict access to minimum required users.
- Preserve logs and snapshots for investigation.

## Eradication Steps
- Correct root cause (ACL/policy/config/code flaw).
- Remove unauthorized copies or access artifacts where feasible.
- Apply preventive controls to similar assets.

## Recovery Steps
- Restore secure access model.
- Validate data store configuration against baseline.
- Monitor for continued abnormal access.

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
