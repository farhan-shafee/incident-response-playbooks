# Account Compromise Incident Response Playbook

## Objective
Contain unauthorized account access, remove attacker persistence, and restore secure identity posture.

## Severity Criteria
- **Low (SEV-3):** Suspicious login, no confirmed account takeover.
- **Medium (SEV-2):** Confirmed takeover of a standard user account.
- **High (SEV-1):** Privileged account takeover or broad identity abuse.

## Initial Triage Steps
1. Validate suspicious login indicators (impossible travel, unusual device, unusual ASN).
2. Check MFA prompts/failures and token anomalies.
3. Identify privilege level and accessed resources.
4. Scope additional accounts with related indicators.

## Evidence to Collect
- Identity provider sign-in logs.
- MFA challenge logs and session/token activity.
- Mailbox and SaaS audit logs.
- Recent admin actions tied to compromised identity.

## Containment Steps
- Reset password and enforce strong reauthentication.
- Revoke active sessions and refresh tokens.
- Temporarily disable account for high-risk cases.

## Eradication Steps
- Remove attacker persistence (forwarding rules, OAuth grants, API keys).
- Rotate linked secrets for privileged/service identities.
- Remove unauthorized role/group assignments.

## Recovery Steps
- Restore account with conditional access and MFA enforced.
- Monitor for repeat anomalies and downstream abuse.

## Communication / Escalation Guidance
- Escalate immediately for privileged accounts or sensitive data access.
- Notify affected stakeholders if downstream systems were accessed.

## Post-Incident Review Steps
- Improve identity detections and access policies.
- Review user awareness and phishing resistance measures.

## MITRE ATT&CK Mapping (Useful)
- T1078: Valid Accounts
- T1556: Modify Authentication Process
- T1098: Account Manipulation
