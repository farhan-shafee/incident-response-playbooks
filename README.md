# Incident Response Playbook Portfolio Lab

This repository is a **portfolio lab** that demonstrates how I structure and document incident response (IR) work for SOC Analyst / Security Analyst / Junior IR-focused roles.

> Important: This repo is **not** evidence of production incident command ownership. It is a practical lab for process design, triage thinking, and repeatable investigation workflows.

## Purpose

- Demonstrate practical IR thinking across common incident categories.
- Show reusable playbook and documentation patterns.
- Provide templates for intake, evidence handling, timeline tracking, stakeholder updates, and post-incident review.
- Show clear boundaries between lab exercises and real-world production response.

## Who This Is For

- Recruiters evaluating portfolio quality for SOC/IR positions.
- Hiring managers reviewing communication and incident process maturity.
- Security engineers reviewing technical credibility of triage and containment workflows.

## Repository Structure

- `playbooks/` — Incident-specific response playbooks.
- `templates/` — Reusable forms/checklists for intake, evidence, communication, timeline, and PIR.
- `docs/` — IR methodology and operating guidance.
- `scenarios/` — Sample lab incidents for practice and walkthrough.
- `reports/` — Example completed reports based on scenarios.
- `scripts/` — Validation scripts for basic quality checks.
- `.github/workflows/` — CI checks for markdown and repository hygiene.

## Included Playbooks

- Phishing
- Malware
- Ransomware
- Account Compromise
- Cloud Incident
- Data Exposure

Each playbook includes:

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

## Suggested Lab Workflow

1. Select a scenario from `scenarios/`.
2. Use the relevant playbook in `playbooks/` to run triage and response steps.
3. Record findings in `templates/incident_intake_form.md` and `templates/timeline_template.md`.
4. Track evidence using `templates/evidence_collection_checklist.md`.
5. Draft updates with `templates/stakeholder_update_template.md`.
6. Finalize incident output in `reports/` using the completed report examples as reference.
7. Run `make validate` to check repo quality.

## Skills Demonstrated

- Incident categorization and severity assignment.
- Structured triage and escalation decisions.
- Evidence-oriented response documentation.
- Stakeholder communication during incidents.
- Post-incident review and control improvement planning.
- MITRE ATT&CK-informed analysis.

## Limitations

- No sensitive or real customer/company incident data is included.
- No claims of production breach ownership or enterprise incident command.
- Cloud, endpoint, and SIEM tool references are platform-agnostic.
- Example scenarios are educational and sanitized.

## Quick Start

```bash
make validate
```

Then pick one scenario and run it end-to-end with the mapped playbook.

## License

See `LICENSE`.
