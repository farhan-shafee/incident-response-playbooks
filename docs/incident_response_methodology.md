# Incident Response Methodology (Portfolio Lab)

This lab uses the following operational phases. [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) integrates incident response into cybersecurity risk management through CSF 2.0. The phases and decision conventions below organize this educational lab; they are not verbatim NIST requirements.

1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

## Triage and Assessment

- Separate directly observed facts and their sources from reported information that has not been corroborated. Label explanations as working hypotheses; an indicator alone does not establish compromise.
- Record the reviewer's triage disposition and rationale: pending investigation, suspected or declared incident, benign activity/false positive, or insufficient evidence. For an incident declaration, state the criteria applied and what remains unconfirmed.
- Describe known and potential business impact, affected assets/users, scope, and visibility gaps. Record analyst confidence separately, including missing or contradictory evidence.

## Severity and Escalation

- Assign a provisional severity using applicable playbook criteria and the assessed impact and scope. Severity expresses response priority; it does not establish successful account compromise or validate every hypothesis.
- For this lab, when playbooks overlap, use the highest applicable documented severity for initial escalation (SEV-1 is highest), unless an authorized reviewer records a justified alternative and its basis. For example, reported phishing credential submission invokes the phishing playbook's SEV-1 criterion; invoking account-compromise guidance does not lower it to SEV-2 or confirm takeover.
- Record response urgency separately: how promptly assessment, escalation, or a proposed action is needed. Escalate credible high-impact suspicions involving critical systems, privileged identities, regulated data, or multiple systems before all evidence is available; low confidence does not automatically reduce urgency.
- Reassess severity, scope, confidence, and urgency when new evidence, contrary findings, wider impact, or action failures change the assessment. Record the reviewer, rationale, supporting sources, and unresolved questions for any change.

## Response Action Status

Use explicit status labels for each action; a recommendation or severity assignment grants no operational authority.

| Status | Meaning |
|---|---|
| Recommended | Proposed action with a reason and target scope; no approval or execution is implied. |
| Authorized / approved | An approver or delegated authority and permitted scope are recorded; execution is not implied. |
| Attempted | An execution attempt and its reported result are recorded; effectiveness still requires verification. |
| Verified | Referenced checks support the stated outcome for the specified targets and observation period. |
| Unknown / partially verified | Evidence is missing, conflicting, or covers only part of the targets/outcome. Record failures, remaining checks, and the next owner. |
| Assumed for exercise | A hypothetical action or outcome used for discussion; no real approval, attempt, or verified result is claimed. |

Preserve these distinctions in handoffs and stakeholder updates. Record relevant evidence-preservation and service-impact considerations before consequential changes where feasible; urgent authorized containment may run alongside collection, with the tradeoff documented.

## Documentation Expectations

- Every incident starts with an intake form.
- Analysts maintain a UTC timeline of key decisions/actions, preserving source timestamps and distinguishing event, collection, decision, and action times.
- Evidence collection is documented with source, timestamp, and artifact references. Record search scope, visibility limits, and missing evidence; absent logs do not establish that an activity did not occur.
- Stakeholder updates are concise, objective, and periodic.
- Recovery and closure require defined checks, supporting evidence, residual-risk documentation, and reviewer acceptance. Otherwise retain an unverified outcome or explicitly label any illustrative closure assumption.

## Portfolio Lab Boundaries

- Scenarios are sanitized and educational.
- No production customer data is stored.
- No claims of enterprise command authority are implied.
