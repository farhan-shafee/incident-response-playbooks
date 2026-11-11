# Incident Response Playbook Portfolio Lab

A **synthetic-only cybersecurity engineering portfolio** combining six incident-response playbooks with a working offline Python case-validation and phishing-triage engine.

## Working Phase 2B — Offline Response Simulation

The lab now replays synthetic approval, attempt and verification events against
the **actual Phase 2A recommendations**. It validates exact case/result/action
bindings, refuses expired or changed approval scope, and evaluates independent
synthetic observations instead of trusting an operation acknowledgement.

    Validated case -> proposed actions -> scoped simulated approval
    -> simulated attempt receipt -> independent state observations
    -> monitoring and residual-risk review -> simulated closure decision

There is no live response adapter. Every actor, approval and outcome is an exercise
input; the engine never revokes a real session or quarantines a real message.
Original Phase 2A triage remains unchanged even when simulated closure is accepted.

### Run the response exercise

Use Python 3.11+ from the repository root; no installation or dependencies required:

    python -B -m ir_lab simulation-validate fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/success.json
    python -B -m ir_lab simulate fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/misleading_success.json
    python -B -m ir_lab simulation-render fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/partial.json --format markdown --output response-simulation.md

Choose a **new** output filename with an existing parent directory. Validation and
stdout simulation create no report files. Rendering refuses existing destinations,
input aliases, symlink parents and Windows reparse/junction parents.

| Plan | Independently expected result |
|---|---|
| success | Five actions effective in synthetic evidence; complete monitoring and reviewer acceptance; simulated closure true |
| denied | Five denials; no attempted actions; closure false |
| partial | Four actions effective; session revocation failed; closure false |
| misleading_success | Revocation acknowledged true, but active session observed; revocation failed and closure false |
| expired | Attempt after approval expiry rejects with exit 2 and no report |
| missing_approval | All actions remain recommended; closure false |

JSON and Markdown expose exact targets, supporting observations, fictional actors,
transition history, acknowledgement and verification records, artifact hashes and
blocked recovery gates. Repeated replay is stateless and deterministic.

    python -B scripts/generate_simulation_fixtures.py --check
    python -O -B scripts/generate_simulation_fixtures.py --check
    python -B -m unittest discover -s tests -v

See [Response Simulation](docs/SIMULATION_ENGINE.md) for the separate
`ir-simulation/1.0` contract, state machine, safety rules, limitations and demo.

> This lab is not production incident response experience, native SIEM/EDR coverage, or a system that executes containment. It does not imply operational incident-command authority or verified real-world recovery.

## Working Phase 2A — Offline Case Engine

The implemented Python 3.11+ standard-library package validates structured incident cases, checks retained evidence SHA-256 digests, correlates artifact-sourced observations against actual JSONL event rows, and returns deterministic, explained triage decisions. It supports the phishing category as a **first vertical slice** only.

A reported credential submission triggers provisional SEV-1 under this lab's phishing policy, but does **not** confirm account takeover. The engine distinguishes severity, urgency, confidence, missing evidence, proposed actions, and unverified recovery. **Benign explanations must be backed by observations linked to the exact deliveries and affected identities**; a benign event for another user cannot suppress investigation. Explicit logging gaps cannot be cleared by a contradictory coverage label. Proposed actions are limited to supported identity targets and carry unique IDs and observation references.

Reproducible synthetic cases:

| Case | Expected decision | Limitation |
|---|---|---|
| Positive phishing report | Provisional SEV-1, urgent suspected incident | No confirmed takeover or containment |
| Benign/authorized activity | Benign explanation within this bounded synthetic case | No broad assurance outside this case |
| Incomplete reported submission | Provisional SEV-1, low confidence and visibility gaps | Identity/mail coverage missing |
| Adversarial duplicate/conflict | Controlled rejection | No misleading report generated |

### Quick start

From the repository root with Python 3.11 or later:

    python -B -m ir_lab validate fixtures/ir_cases/positive.json
    python -B -m ir_lab triage fixtures/ir_cases/positive.json
    python -B -m ir_lab validate fixtures/ir_cases/benign.json
    python -B -m ir_lab validate fixtures/ir_cases/incomplete.json

Write a reproducible **new** report (destination must not exist):

    python -B -m ir_lab render fixtures/ir_cases/positive.json --format json --output incident-result.json
    python -B -m ir_lab render fixtures/ir_cases/positive.json --format markdown --output incident-report.md

The engine does not write during validation or triage. Rendering refuses overwrite, source aliases and unsafe paths. JSON/Markdown results include scoped entity information, corroborated source event IDs, decision/action evidence references, and separate raw/normalized artifact digests where applicable. It never connects to real identity providers, runs a user-supplied command, or changes a service or account. **Only nominated observations are evaluated; unreferenced JSONL events are not hunted or independently assessed.** All artifacts are synthetic; an intact hash is not independently proven forensic authenticity.

### Run verification

    python -B scripts/generate_ir_fixtures.py --check
    python -B -m unittest discover -s tests -v

On Windows, Bash structural validation uses Git Bash when present:

    bash scripts/validate_repo.sh

When Make is installed, the original shortcut remains:

    make validate

GitHub Actions now preserves that documentation validator and runs offline case behavior and negative tests on Ubuntu/Windows with Python 3.11/3.13.

For case structure, action-state safety, original-vs-derived artifact hashing, time and event correlation, CLI behavior, and known limitations, see [Offline Case Engine](docs/OFFLINE_CASE_ENGINE.md).

## Existing Playbook Collection

- Phishing
- Malware
- Ransomware
- Account Compromise
- Cloud Incident
- Data Exposure

Each playbook documents an objective, severity criteria, triage, evidence, proposed containment, eradication, recovery, communications, post-incident review and useful ATT&CK mappings. The runbooks are educational guidance, **not executed response logic**.

## Repository Structure

- [ir_lab](ir_lab) — Implemented offline case contract, evidence and event validation, deterministic phishing triage and report generation
- [fixtures/ir_cases](fixtures/ir_cases) — Immutable committed synthetic original/derived artifacts and four case inputs
- [tests](tests) — Independent decision expectations, adversarial/negative tests, CLI and safety checks
- [docs](docs) — Methodology and detailed offline case engine contract
- [playbooks](playbooks) — Six human-focused response guides
- [templates](templates) — Intake, evidence checklist, timeline, stakeholder update, post-incident review
- [scenarios](scenarios) — Tabletop exercise prompts
- [reports](reports) — **Illustrative** legacy reports; not proof of completed response
- [scripts](scripts) — Existing Bash structure validation and deterministic fixture generation
- [.github/workflows](.github/workflows) — Offline cross-platform CI

## Five-Minute Interview Walkthrough

1. Show [Incident Response Methodology](docs/incident_response_methodology.md) and explain why severity is independent of confirmation, action approval and recovery.
2. Validate the positive fixture and show raw-vs-normalized evidence digests plus correlated source-event IDs.
3. Triage the positive case, explaining provisional SEV-1 and why the account-takeover flag and recovery status are still unverified.
4. Compare benign and incomplete cases; explain how corroborating events and absent log coverage change disposition and confidence.
5. Validate the adversarial fixture (expected nonzero exit), show independently authored expected **action target and unique-ID** results, and discuss the additional unrelated-user, logging-gap, hostile-JSON and output-alias negative controls.

## Limits and Next Milestones

The lab does **not** implement a malware/ransomware triage engine, continuous monitoring, real forensic evidence acquisition, a backend/database, a UI, native Sentinel/Defender/SOAR integration, or executable containment. Phase 2B adds a bounded synthetic response simulation only.

Next: a separate milestone may accept a versioned synthetic handoff from the [Threat Hunting Playbooks](https://github.com/farhan-shafee/threat-hunting-playbooks) project. **No integration currently exists.** A hunt candidate would still require analyst classification and explicit simulation bindings; it would never authorize a real response.

No real customer data, production metrics, authenticated sessions, secret material, malicious executable files, or verified incident-response outcomes are included in this lab.
