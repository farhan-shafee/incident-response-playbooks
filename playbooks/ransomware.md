# Ransomware Incident Response Playbook

## Objective
Stop encryption spread, preserve evidence, and restore critical services from trusted recovery points.

## Severity Criteria
- **Medium (SEV-2):** Suspected pre-encryption ransomware behavior on limited hosts.
- **High (SEV-1):** Active encryption, ransom note, data exfiltration indicators, or broad impact.

## Initial Triage Steps
1. Assess **suspected pre-encryption activity** (ransomware staging, destructive tooling, backup tampering, unusual remote execution, or mass-file operations) as well as actual encryption or ransom artifacts. Do not wait for confirmed encryption before escalating credible broad-impact risk.
2. Identify candidate initial access, affected identity/host scope, likely propagation paths, and evidence limitations; do not assume a confirmed patient zero.
3. Determine business-critical dependencies and whether backup storage, management identities, recovery credentials, or immutability controls are threatened.
4. Assess data-access/exfiltration indicators separately from exposure, encryption, and confirmed disclosure; record provisional severity and uncertainty.

## Evidence to Collect
- Ransom notes, file-change metadata, suspicious process and script records, and hashes of actually retained artifacts.
- Endpoint process and network telemetry with source event IDs, capture times, and collection scope.
- Authentication, management, and remote-execution logs supporting or contradicting lateral-movement hypotheses.
- Backup configuration and job histories, restore-point provenance, change histories, and health/immutability status; avoid exposing recovery secrets.
- Preserve available originals and log coverage before destructive recovery actions where feasible; document emergency exceptions, missing telemetry, and evidence loss.

## Containment Steps
Actions require **recorded approval** under the [response action status policy](../docs/incident_response_methodology.md#response-action-status). For emergency delegated authority, record the authorizing role, scope, rationale, and escalation.
- Coordinate bounded isolation of affected hosts or segments with system/network owners, checking service and evidence-acquisition dependencies. Do not imply every suspicious host is confirmed infected.
- Coordinate narrowly scoped identity/service-account restrictions with administrators; account for critical service dependencies, backup-plane access, and an approved alternate recovery path.
- Protect backup control planes, offline/immutable copies, and management credentials while considering containment and restoration; do not reconnect untrusted production systems to recovery storage.
- Evaluate targeted infrastructure blocks and record rollbacks, monitoring, and independent verification of effective isolation or access restrictions, including failed or partially contained targets.

## Eradication Steps
- Record a preservation decision before removing suspected tooling or persistence or rebuilding systems. Document urgent containment exceptions if evidence must be sacrificed to stop spread.
- Remove or rebuild only authorized, scoped assets after investigative and integrity assessment; close supported initial-access pathways (such as exposed remote services or vulnerabilities).
- Test for possible dormant access and persistence without claiming absence of every foothold based on incomplete telemetry.

## Recovery Steps
- Validate restore-point integrity, trust, coverage, and recovery isolation before promoting prioritized services; do not equate successful restore execution with safe production recovery.
- Test business functionality, identity permissions, backup-plane integrity, connectivity, and defined persistence checks with responsible owners.
- Keep enhanced monitoring for an explicit, approved interval; record check outcomes, residual risk, reopening criteria, and closure authorization. Unverified systems remain in a pending or partial recovery state.

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
