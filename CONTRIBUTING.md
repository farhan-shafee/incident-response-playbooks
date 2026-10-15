# Contributing

Thanks for your interest in improving this incident response portfolio lab.

## Guidelines

- Keep incident cases, user identities, hosts, domains, indicators, logs, and outcomes **synthetic and educational**. Use documentation/example-only identifiers where appropriate.
- Do **not** include real production incidents, customer telemetry, confidential files, credentials, or protected data in pull requests or issue discussions—even if superficially anonymized. This repository does not serve as an approved publication or disclosure channel for production work.
- Label reported exercise facts, hypotheses, proposals, assumed action completions, and verified results distinctly. Never claim production incident-command authority or treat an illustrative "Resolved (Lab)" statement as verified containment, recovery, or closure.
- Preserve unknowns, visibility limits, provisional severity, action authorization, evidence preservation, and response verification in proposed playbook changes. Follow [incident response methodology](docs/incident_response_methodology.md).
- Prefer UTC for derived chronology while retaining source timestamp and offset information where the source provides them. Do not invent forensic evidence, original-byte hashes, approval records, incident timestamps, or a custody chain.
- Keep required playbook headings consistent across all incident types.
- Use the process described in [SECURITY.md](SECURITY.md) for potentially sensitive reporting; never post secrets or a sensitive security issue in a public GitHub issue.
- **Never** add live containment integrations, malware execution, credential/secret retrieval, or production account changes to this synthetic-only repository. Any separately authorized operational work belongs in a distinct, purpose-built project with its own governance and safety controls; approval elsewhere does not override this lab's boundaries.

## Validation

Run the existing structural validator from the repository root with Git Bash (Bash and grep required):

```bash
bash scripts/validate_repo.sh
```

If Make is installed, `make validate` is an optional equivalent. These checks verify file and heading presence only; they do **not** test incident response outcomes or validate evidence.
