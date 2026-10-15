# Example Completed Report (Lab): Phishing Credential Harvest

> Illustrative walkthrough only. No supporting artifacts or action records are provided; containment, recovery, and incident closure have not been verified.

## Incident Details

- Incident ID: LAB-2026-001
- Category: Phishing / Potential Account Compromise
- Severity: Provisional SEV-1 (High)
- Status: Illustrative exercise; response outcomes and closure unverified

## Summary

This illustrative narrative describes a finance-themed phishing email delivered to multiple recipients and reports that one user submitted credentials. These are reported exercise facts without corroborating email or identity artifacts. Successful account takeover has not been established.

Initial SEV-1 escalation follows the [phishing playbook's credential-submission criterion](../playbooks/phishing.md#severity-criteria) and the [methodology's overlapping-playbook convention](../docs/incident_response_methodology.md#severity-and-escalation). Account-compromise guidance supports follow-on investigation; it does not lower this initial priority or confirm takeover. Confidence remains limited by the missing evidence, while the reported credential exposure warrants prompt assessment.

## Key Actions

The following are recommended exercise actions. Any assumed completion is hypothetical: no approval, attempted execution, or verified effectiveness is documented.

| Recommended action | Verification required before recording an outcome |
|---|---|
| Assess message scope and propose quarantine and targeted indicator blocking. | Authorized scope, message identifiers, administrative action records, and checks showing which targets were actually contained. |
| Coordinate password reset and session/token revocation with the identity administrator. | Authorization and action records, plus provider/application-specific checks of affected access; a request alone does not establish successful revocation. |
| Investigate sign-ins, mailbox rules, OAuth grants, and related endpoint activity; preserve relevant artifacts before changes where feasible. | Search records identifying sources, accounts/assets, time bounds, results, and coverage limitations. Any negative finding remains limited to that verified search. |

## Outcome

Containment, recovery, and closure remain unverified. The example establishes neither the presence nor absence of malicious persistence, lateral movement, or downstream data access. No supporting logs or search records substantiate negative findings.

### Evidence and Visibility Gaps

- Raw email/message identifiers, the user report, identity/MFA/token and mailbox audit logs, and relevant endpoint telemetry are not supplied.
- Affected-account/asset scope, search windows, logging coverage/retention, action approvals, attempted-action records, and outcome checks are not documented.

### Recovery and Closure Requirements

- Verify the effectiveness and scope of authorized mail and identity containment, including applicable session-revocation limits.
- Verify trusted authentication/recovery methods and user access; investigate and remediate unauthorized persistence if found.
- Document bounded investigation results, remaining visibility gaps, and an assigned monitoring period with checks for renewed abuse and functioning controls.
- Record reviewer acceptance of recovery, residual risk, and closure criteria. Until those records exist, retain the unverified status; control improvements and awareness guidance remain proposed follow-up work.
