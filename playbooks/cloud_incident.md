# Cloud Incident Response Playbook

## Objective
Contain suspicious cloud activity and restore trusted cloud configuration across identity, compute, storage, and network services.

## Severity Criteria
- **Low (SEV-3):** Single anomalous cloud event, no persistence/data access confirmed.
- **Medium (SEV-2):** Unauthorized resource/API activity with limited impact.
- **High (SEV-1):** Privilege abuse, large-scale configuration tampering, or sensitive data exposure.

## Initial Triage Steps
1. Validate suspicious API activity and actor identity.
2. Identify impacted accounts/subscriptions/projects and regions.
3. Review IAM changes, key usage, and unusual resource creation.
4. Determine potential data access/exfiltration.

## Evidence to Collect
- Cloud audit logs (management and data events).
- IAM policy/role change history.
- Storage/object access logs.
- Network flow logs and security group/firewall changes.

## Containment Steps
- Disable/rotate compromised keys and credentials.
- Revoke suspicious sessions and temporary credentials.
- Isolate affected resources and lock down network access.

## Eradication Steps
- Remove unauthorized resources and backdoor IAM artifacts.
- Revert malicious or risky cloud configurations.
- Patch vulnerable workloads/images.

## Recovery Steps
- Rebuild/restore affected workloads from known-good templates.
- Re-enable services with guardrails and monitoring.
- Validate least-privilege and logging coverage.

## Communication / Escalation Guidance
- Escalate to cloud platform owners and security leadership for SEV-1.
- Coordinate legal/privacy review if regulated data exposure is possible.

## Post-Incident Review Steps
- Improve cloud detection coverage and IAM governance.
- Add preventive controls (MFA, SCP/policy guardrails, key hygiene).

## MITRE ATT&CK Mapping (Useful)
- T1078: Valid Accounts
- T1098: Account Manipulation
- T1530: Data from Cloud Storage
