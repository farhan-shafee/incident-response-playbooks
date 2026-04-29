# Incident Response Playbook Portfolio Lab

This repository is a **portfolio lab** that demonstrates how I structure and document incident response (IR) work for SOC Analyst / Security Analyst / Junior IR-focused roles.

> Important: This repo is **not** production incident response experience and does not claim real-world incident command ownership.

## Purpose

- Demonstrate practical IR thinking across common incident categories.
- Show reusable playbook and documentation patterns.
- Provide realistic, sanitized walkthrough content for interview discussion.

## Repository Structure

- `playbooks/` — Response playbooks for common incident types.
- `templates/` — Intake, evidence, timeline, stakeholder update, and PIR templates.
- `docs/` — Methodology and operating assumptions.
- `scenarios/` — Lab scenarios used to practice triage and escalation.
- `reports/` — Example completed lab reports.
- `scripts/` — Local validation checks.
- `.github/workflows/` — CI execution of local validation.

## Included Playbooks

- Phishing
- Malware
- Ransomware
- Account Compromise
- Cloud Incident
- Data Exposure

Every playbook includes:

- Objective
- Severity criteria
- Initial triage steps
- Evidence to collect
- Containment steps
- Eradication steps
- Recovery steps
- Communication/escalation guidance
- Post-incident review steps
- MITRE ATT&CK mapping (where useful)

## Suggested Workflow

1. Pick a scenario in `scenarios/`.
2. Execute the matching playbook from `playbooks/`.
3. Fill out `templates/incident_intake_form.md` and `templates/timeline_template.md`.
4. Track artifacts using `templates/evidence_collection_checklist.md`.
5. Publish periodic updates via `templates/stakeholder_update_template.md`.
6. Complete closure and improvements in `templates/post_incident_review_template.md`.
7. Write a final report in `reports/`.

## Skills Demonstrated

- Incident categorization and severity assignment.
- Structured triage and escalation.
- Evidence-oriented investigation notes.
- Stakeholder communication discipline.
- Post-incident corrective action planning.

## Limitations

- No real company data, incidents, or sensitive artifacts.
- No production claims, response metrics, or breach ownership assertions.
- Platform/tool references are intentionally generic.

## Validation

```bash
make validate
```
