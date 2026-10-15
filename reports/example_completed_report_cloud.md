# Example Incident Report (Illustrative Lab): Suspicious Cloud Key Activity

> Synthetic discussion scenario. No original cloud logs, response action records, or recovery checks accompany this example. No actual compromise, containment, or incident closure has been verified.

## Incident Details

- Incident ID: LAB-2026-002
- Category: Cloud Incident / Suspected Service-Key Misuse
- Severity: Pending criteria-based classification (anomalous API calls are reported; event count, authorization, scope, and impact are unverified)
- Triage urgency: Prompt investigation of possible service-key misuse; escalate urgently for credible active abuse or high-impact privileges without waiting for a final severity score.
- Status: Illustrative exercise; containment, recovery, and closure unverified

## Summary

The exercise describes unusual API activity from an unfamiliar source associated with a service key. The source and usage have **not** been corroborated with provider logs, account ownership, change records, or expected service behavior. An unfamiliar source alone does not prove key compromise, unauthorized activity, or data access. Reassess severity if privilege abuse, sensitive data exposure, or wider impact is supported.

## Key Actions

These are recommended investigation and response steps, **not executed or verified actions**. Any hypothetical completion is an exercise assumption; no approval or effectiveness records are provided.

| Proposed action | Evidence and verification needed |
|---|---|
| Preserve scoped management/data event records, credential metadata, IAM changes, and relevant service dependencies before disruptive changes where feasible. | Source systems, log coverage and retention, bounded time windows, relevant event IDs, and artifact references; do not expose key material. |
| Evaluate key disablement/rotation and session controls with the authorized cloud and service owners. | Authority, target account/key scope, service impact and alternate-access plan; attempted-change records and subsequent checks that old access is rejected and legitimate workloads still work. |
| Investigate identity, policy changes, affected resources, and possible object-level access. | Provider-specific audit evidence, enabled data-event coverage, bounded searches, and contrary/benign explanations; missing data events cannot prove no access occurred. |
| Recommend guardrail and least-privilege improvements based on supported findings. | Approved owner, applicable baseline, implementation record, and independently checked effectiveness before claiming completion. |

## Outcome

Key compromise, unauthorized actions, affected resources, and downstream data access **remain unverified**. No statement that destructive activity was absent, that sessions were revoked, or that the key was successfully rotated is supported by this illustrative report.

### Evidence and Visibility Gaps

- No actual API call IDs, audit exports, storage access events, credential ownership details, or service dependency inventory are provided.
- No preserved artifacts, action approvals, scope/time-bound searches, monitoring observations, or recovery evidence exist for this exercise.

### Recovery and Closure Requirements

- Verify scoped credential revocation or rotation using appropriate provider and consuming-application checks, including expected propagation behavior.
- Verify authorization, policy configuration, service functionality, and bounded post-response monitoring.
- Record coverage limits, alternative explanations, residual risk, owner acceptance, and a justified closure disposition. Until then, leave containment, recovery, and closure unverified.
