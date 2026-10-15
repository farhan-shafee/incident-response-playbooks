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
- Cloud management audit events and, **where separately enabled**, relevant data-access events; document account/region, time bounds, retention, permissions, and source coverage. Management-event history alone cannot prove absence of object-level reads.
- IAM policy/role, authentication method, credential metadata, and change history without exposing secrets.
- Storage/object access logs and policy/configuration snapshots, distinguishing observed access from permissive configuration.
- Network flow records, security-group/firewall changes, and affected workload/service dependencies.
- Preserve scoped original exports and configuration history before destructive changes where feasible, recording source event IDs, acquisition, hashes where available, and visibility gaps.

## Containment Steps
Apply the [approval and verification policy](../docs/incident_response_methodology.md#response-action-status) to every proposed action. Name the cloud and workload owners, target resources, authorized role, dependencies, fallback access, and emergency-delegation rules.
- For credible **active credential misuse**, authorized emergency responders may immediately disable or rotate the narrowly scoped affected credential even when service dependencies cannot be fully mapped first. Record the emergency approver/delegation, key/account scope, suspected abuse, uncertain service impact, alternate responder access, and a safe workload-recovery plan; coordinate with affected owners as soon as feasible. Do not reinstate a potentially compromised key merely to reverse an outage. For lower-urgency changes, map dependencies and stage alternate credentials first. In both cases, verify old-credential rejection and legitimate service access afterward; a successful disable/rotation request alone proves neither.
- Coordinate temporary-session and token restrictions with identity owners; token/provider/application invalidation can be delayed or incomplete. Distinguish request acceptance from verified revocation.
- Consider targeted resource/network isolation with service owners and an impact/rollback plan; do not apply broad subscription/project changes from a single anomalous event.
- Record proposed, approved, attempted, verified, failed, and unknown containment results separately and include any targets not reached.

## Eradication Steps
- Before deleting suspicious resources or backdoor IAM artifacts, preserve configurations, logs, access relationships, and snapshot evidence as warranted. Document urgent exceptions and evidence loss.
- Remove only substantiated unauthorized resources and privileges in an authorized scope, with owner-approved change records and effectiveness checks.
- Revert risky configurations and patch affected workloads using verified baselines; do not call an unfamiliar API source malicious without corroboration.

## Recovery Steps
- Rebuild or restore workloads from known-good templates and verify dependencies, identity permissions, workload behavior, and effective access controls.
- Re-enable services only with approved guardrails, rollback readiness, bounded monitoring, and verified management/data-log coverage appropriate to the product.
- Record impact, coverage limitations, residual risk, follow-up ownership, acceptance checks, and case-reopening triggers. A successful API response is not itself proof of recovery or closure.

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
