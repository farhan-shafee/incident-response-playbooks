#!/usr/bin/env bash
set -euo pipefail

required_files=(
  README.md
  LICENSE
  SECURITY.md
  CONTRIBUTING.md
  Makefile
  docs/incident_response_methodology.md
  templates/incident_intake_form.md
  templates/evidence_collection_checklist.md
  templates/stakeholder_update_template.md
  templates/post_incident_review_template.md
  templates/timeline_template.md
  playbooks/phishing.md
  playbooks/malware.md
  playbooks/ransomware.md
  playbooks/account_compromise.md
  playbooks/cloud_incident.md
  playbooks/data_exposure.md
)

for f in "${required_files[@]}"; do
  [[ -f "$f" ]] || { echo "Missing required file: $f"; exit 1; }
done

echo "All required portfolio-lab files are present."
