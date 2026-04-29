# Phishing Incident Response Playbook

## Objective
Contain and remediate suspected phishing activity while minimizing credential theft and business email compromise risk.

## Severity Criteria
- **Low (SEV-3):** Single suspicious email, no user interaction.
- **Medium (SEV-2):** Multiple recipients and/or link clicks, no confirmed credential theft.
- **High (SEV-1):** Credential submission, mailbox takeover, fraud attempts, or lateral activity.

## Initial Triage Steps
1. Validate sender, domains, URLs, and attachment hashes.
2. Determine user interaction (opened, clicked, submitted credentials, downloaded file).
3. Scope affected users, mailboxes, and related detections.
4. Check for suspicious login activity after interaction.

## Evidence to Collect
- Full email headers and raw MIME.
- URL redirect chain and domain/IP enrichment.
- Endpoint telemetry from recipients.
- Identity and mailbox audit logs.

## Containment Steps
- Quarantine message tenant-wide.
- Block sender/domain/URL/file hash as applicable.
- Force password reset and revoke sessions for impacted users.
- Disable suspicious mailbox forwarding/inbox rules.

## Eradication Steps
- Remove malicious artifacts from endpoints.
- Revoke malicious OAuth app consent/tokens.
- Tighten anti-phishing and impersonation controls.

## Recovery Steps
- Restore user access with MFA verification.
- Monitor for recurring phishing indicators.
- Confirm detection and blocking controls are functioning.

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
