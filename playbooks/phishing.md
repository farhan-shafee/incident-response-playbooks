# Phishing Incident Response Playbook

## Objective
Contain and remediate suspected phishing activity while minimizing credential theft and business email compromise risk.

## Severity Criteria
- **Low (SEV-3):** Single suspicious email, no user interaction.
- **Medium (SEV-2):** Multiple recipients and/or link clicks, no confirmed credential theft.
- **High (SEV-1):** Credential submission, mailbox takeover, fraud attempts, or lateral activity.

## Initial Triage Steps
1. Validate sender, domains, URL indicators, and attachment evidence with safe analysis procedures. Do not open suspicious attachments, run code, or follow live links on production endpoints merely to enrich an indicator.
2. Distinguish opened, clicked, reportedly submitted credentials, and downloaded/executed payloads. Credential submission triggers provisional SEV-1 under this playbook but **does not establish successful account takeover**.
3. Scope affected recipients, message identifiers, mailbox access, and related endpoint/identity events; consider benign, uncertain, and unrelated events.
4. Investigate post-interaction sign-ins, unexpected MFA or recovery-method registrations, OAuth grants, forwarding rules, and known logging gaps.

## Evidence to Collect
- Email headers, original MIME, message IDs and delivery metadata; preserve source, collection time, and artifact references in an approved location.
- URL/redirect and attachment indicators from **authorized safe analysis** or retained telemetry. Do not run untrusted payloads or exfiltrate confidential message content to public analysis services.
- Time-bounded endpoint, identity, authentication registration, recovery-channel, and mailbox events with source event IDs and retention/visibility limits.
- Relevant user reports and action/approval records; preserve original evidence separately from sanitized investigation notes when feasible.

## Containment Steps
These are proposed actions requiring a recorded authorized responder, scope, impact assessment, and verification under the [response action policy](../docs/incident_response_methodology.md#response-action-status).
- Propose targeted or tenant-wide message quarantine based on verified recipient scope and messaging-admin authorization; verify which messages were actually affected.
- Propose scoped sender/domain/URL/hash blocks after assessing false positives and legitimate traffic; verify applied control state and ownership of expiry/rollback.
- Coordinate credential reset, MFA/recovery-method review, and session/token invalidation with the identity owner when reported submission or abuse warrants it. Provider, federation, and application session limits require separate effectiveness checks.
- Investigate suspicious mailbox forwarding, delegate access, OAuth grants, and attacker-added authentication registrations before authorized removal; preserve relevant audit records and verify the corrected state.

## Eradication Steps
- Evaluate supported malicious artifacts or app grants with response owners and an evidence-preservation decision before removal, especially when deleting messages, endpoint files, or cloud audit context.
- Remove only corroborated unauthorized OAuth permissions, rules, and endpoint persistence under approved scope, recording attempted and verified outcomes separately.
- Propose measurable anti-phishing and impersonation controls without claiming deployment until configuration and effectiveness have been checked.

## Recovery Steps
- Verify authorized mailbox/user functionality, trusted MFA and recovery method ownership, and effective access controls after approved changes.
- Monitor bounded identity/mailbox/endpoint indicators and document token/session invalidation limitations and coverage gaps.
- Obtain owner acceptance of observed outcomes, residual risk, and defined reopening criteria. Suggested resets or quarantine do not themselves prove containment or recovery.

## Communication / Escalation Guidance
- Escalate to SEV-1 if credential theft or fraud indicators exist.
- Notify identity admin and messaging admin early.
- Provide stakeholder updates at defined intervals until closure.

## Post-Incident Review Steps
- Review why controls allowed delivery/user interaction.
- Update detections, mail rules, and user training content.
- Document lessons in the PIR template.

## MITRE ATT&CK Mapping (Useful)
- T1566: Phishing
- T1078: Valid Accounts
- T1114: Email Collection
