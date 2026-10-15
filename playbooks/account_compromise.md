# Account Compromise Incident Response Playbook

## Objective
Contain unauthorized account access, remove attacker persistence, and restore secure identity posture.

## Severity Criteria
- **Low (SEV-3):** Suspicious login, no confirmed account takeover.
- **Medium (SEV-2):** Confirmed takeover of a standard user account.
- **High (SEV-1):** Privileged account takeover or broad identity abuse.

## Initial Triage Steps
1. Assess sign-in signals (travel velocity, device, ASN, conditional-access policy, VPN/proxy context) alongside known user behavior; an anomaly is not automatically a confirmed takeover.
2. Investigate MFA prompts and failures, refresh-token/session anomalies, **new authentication method registrations**, recovery-channel changes, and unfamiliar trusted devices.
3. Identify identity privileges and resources plausibly reached; distinguish suspicious access attempts from successful use of a resource.
4. Scope other potentially affected accounts and review benign explanations, conflicting observations, and logging gaps. Record suspected, confirmed, benign, or insufficient-evidence disposition and reassess severity as supported.

## Evidence to Collect
- Time-bounded identity-provider sign-in/audit logs, source event IDs, user/tenant scope, status meanings, and coverage/retention limits.
- MFA/authentication registration changes, recovery email/phone ownership changes, registered devices, and token/session records where exposed by the provider.
- Mailbox and SaaS access/audit history, OAuth grants, app consents, forwarding changes, and associated external-party effects.
- Recent admin, credential, recovery, role/group, and policy changes tied to the identity; retain relevant originals and provenance where possible.
- Explicitly record unavailable sources and provider-specific session visibility. Absence of an audit event cannot prove a device or session was never used.

## Containment Steps
Treat response controls as **proposals requiring approved account, service, and application scope**, using the [response action policy](../docs/incident_response_methodology.md#response-action-status). For privileged/service identities, plan alternate admin access and dependencies.
- Coordinate an authorized credential reset or high-assurance reauthentication; verify actual enforcement rather than treating the request as a completed reset.
- Request provider-supported session and refresh-token invalidation for affected identities/apps. Application cookies, federated sessions, and existing access tokens may persist until expiry or application-specific revocation; verify propagation and residual access separately.
- Consider temporary account restrictions when risk warrants them, documenting business impact, affected users, rollback/recovery owner, and emergency authority.
- Distinguish recommended, authorized, attempted, verified, partial, and unknown results per target and session class.

## Eradication Steps
- Investigate and remove **confirmed unauthorized** MFA/authentication methods, recovery channels, trusted devices, mailbox forwarding, OAuth grants, tokens, and API keys under authorized scope; preserve supporting change history first where feasible.
- Rotate linked secrets for privileged/service identities only with owner coordination, dependency review, and verification that old access is no longer effective.
- Review and correct unauthorized role/group grants or access policies with evidence of the old state and a scoped approval record; unknown changes require investigation rather than automatic deletion.

## Recovery Steps
- Restore identity access after verifying approved authentication method registrations, recovery-channel ownership, trusted devices, applicable MFA and conditional-access policy, and legitimate user functionality.
- Perform bounded provider/application session and downstream-access checks; document revocation limitations and time-limited monitoring for recurring abuse.
- Record owner acceptance, residual risk, contrary/missing evidence, and reopening criteria. Do not infer confirmed takeover or verified containment from token-revocation requests alone.

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
