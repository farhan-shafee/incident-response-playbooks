#!/usr/bin/env bash
set -euo pipefail

required_files=(
  README.md LICENSE SECURITY.md CONTRIBUTING.md Makefile
  docs/incident_response_methodology.md
  templates/incident_intake_form.md
  templates/evidence_collection_checklist.md
  templates/stakeholder_update_template.md
  templates/post_incident_review_template.md
  templates/timeline_template.md
  playbooks/phishing.md playbooks/malware.md playbooks/ransomware.md
  playbooks/account_compromise.md playbooks/cloud_incident.md playbooks/data_exposure.md
)

required_sections=(
  "## Objective"
  "## Severity Criteria"
  "## Initial Triage Steps"
  "## Evidence to Collect"
  "## Containment Steps"
  "## Eradication Steps"
  "## Recovery Steps"
  "## Communication / Escalation Guidance"
  "## Post-Incident Review Steps"
)

for f in "${required_files[@]}"; do
  [[ -f "$f" ]] || { echo "Missing required file: $f"; exit 1; }
done

for p in playbooks/*.md; do
  for section in "${required_sections[@]}"; do
    grep -q "^${section}$" "$p" || { echo "Missing section '${section}' in ${p}"; exit 1; }
  done
done

echo "Validation passed: required files and playbook sections are present."
