# Ransomware Incident Response Playbook

## Objective
Stop encryption spread, preserve evidence, and restore critical services from trusted recovery points.

## Severity Criteria
- **Medium (SEV-2):** Suspected pre-encryption ransomware behavior on limited hosts.
- **High (SEV-1):** Active encryption, ransom note, data exfiltration indicators, or broad impact.

## Initial Triage Steps
1. Confirm encryption behavior and ransom artifacts.
2. Identify patient zero and potential lateral movement.
3. Determine impact to critical systems and backups.
4. Assess exfiltration indicators.

## Evidence to Collect
- Ransom note, encrypted extension patterns, and malware hashes.
- Endpoint process and network telemetry.
- Authentication logs for lateral movement.
- Backup job logs and restoration status.

## Containment Steps
- Isolate infected systems and network segments.
- Disable affected accounts and high-risk service accounts.
- Block known C2/exfiltration infrastructure.

## Eradication Steps
- Remove ransomware tooling and persistence.
- Close exploited pathways (RDP/VPN/vulnerable services).
- Validate environment for dormant footholds.

## Recovery Steps
- Restore prioritized systems from clean backups.
- Validate integrity before production return.
- Maintain intensified monitoring post-recovery.

## Communication / Escalation Guidance
- Immediate executive/legal escalation for SEV-1.
- Coordinate potential regulatory/privacy notifications per policy.
- Keep updates consistent and timestamped.

## Post-Incident Review Steps
- Review segmentation, IAM, backup, and detection maturity.
- Record actions, decisions, and improvement backlog.

## MITRE ATT&CK Mapping (Useful)
- T1486: Data Encrypted for Impact
- T1021: Remote Services
- T1562: Impair Defenses
