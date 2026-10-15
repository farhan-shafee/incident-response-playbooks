# Example Incident Report (Illustrative Lab): Storage Policy Exposure

> Synthetic discussion scenario. No storage policy snapshots, access logs, approved remediation records, or verification evidence are supplied. The report does not establish who accessed data or whether a disclosure occurred.

## Incident Details

- Incident ID: LAB-2026-004
- Category: Data Exposure / Suspected Storage-Policy Misconfiguration
- Severity: Provisional SEV-2 (pending data classification, actual exposure window, and access scope; escalate for regulated or broad sensitive exposure)
- Status: Illustrative exercise; containment, recovery, and closure unverified

## Summary

The scenario describes a storage policy that may have permitted unintended external access to internal documents. A permissive policy is an exposure concern, **not proof of access, copying, exfiltration, or regulated-data disclosure**. No original configuration, access records, or information classification has been provided to establish impact.

## Key Actions

The actions below are **proposed**, not performed. No external-access restriction, credential rotation, log review, or notification decision has been verified.

| Proposed action | Evidence and verification needed |
|---|---|
| Preserve storage-policy versions, configuration/change history, access logs, and data inventory before changing permissions when feasible. | Source, retrieval method, artifact identifiers, acquisition time, retention and logging coverage; distinguish access from policy exposure. |
| Propose the narrowest authorized access restriction and credential rotation needed to reduce risk. | Affected resource/identity scope, named approver, service dependency and rollback plan; tested effective permissions and continued authorized access afterward. |
| Investigate exposure window, accessible objects, possible reads/downloads, and alternate explanations. | Bounded source searches, data-event availability, classification evidence, logging gaps, and applicable provider semantics; missing events cannot prove no access. |
| Refer suspected regulated-data impact and notification questions to authorized privacy/legal owners. | Discovery facts, decision owner, counsel-determined obligations and deadlines, approved communications, and decisions pending additional evidence. |

## Outcome

The scope of any exposure and whether unauthorized access or disclosure occurred **remain unknown**. Neither "no regulated-data disclosure" nor successful containment, logging review, or completed preventive controls can be concluded from this example.

### Evidence and Visibility Gaps

- No original storage permissions, object/data classification, access event IDs, policy-change audit trail, or time-bounded collection results are provided.
- No approval, applied policy snapshot, verification of effective access, privacy decision, or monitoring and closure evidence is available.

### Recovery and Closure Requirements

- Confirm authorized effective access, test intended users and blocked external paths, and document policy baseline changes.
- Record the remaining exposure uncertainty, logging limitations, monitoring, and legal/privacy referral decisions as appropriate.
- Do not attempt removal of copies held by third parties or systems outside authorized control; use legal/provider processes. Require reviewer acceptance of residual risk before verified closure.
