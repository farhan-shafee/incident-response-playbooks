# Offline Incident Case Engine — Phase 2A

**Scope:** deterministic, synthetic-only phishing case investigation and triage. This is not a real production incident command system, native SIEM integration, or independent forensic acquisition.

## Architecture

    Versioned case JSON -> contract and source-reference validation
    -> raw artifact SHA-256 and optional separately labeled normalization
    -> JSONL event ID/kind/entity/time correlation
    -> conservative phishing triage policy
    -> deterministic JSON or sanitized Markdown report

There is **no** network enrichment, cloud credential access, subprocess execution from fixtures, response execution, or automatically verified containment/recovery.

## Versioned incident contract

Schema: **ir-case/1.0**. The input must have these exact top-level fields:

| Key | Meaning |
|---|---|
| schema_version | ir-case/1.0 only |
| case_id | bounded unique identifier |
| synthetic | boolean true; all other values rejected |
| category | phishing only in Phase 2A |
| entities | nonempty list with ID, kind (user/mailbox/host/ip), value |
| evidence | list of raw-byte-hashed local artifacts |
| observations | nonempty list of reported or correlated artifact facts |
| actions | proposed or assumed-for-exercise actions only |
| coverage | identity_logs, mail_logs and endpoint_logs: available/missing/unknown |
| recovery | state must be unverified |

Unknown object fields and duplicate JSON keys fail closed. All entity, artifact, observation and action identifiers are globally unique within a case. Cross-references are checked, dates must include a UTC offset, and array/byte sizes are bounded.

### Evidence artifacts

Each descriptor needs ID, relative path, kind (original/derived), lowercase SHA-256 of exact original **raw bytes**, byte length, source and collection timestamp. Relative evidence paths use only safe forward-slash components; symlink and traversal paths are rejected. Sources are never modified by evaluation.

The only recognized derived transformation is **utf8-bom-crlf-v1** (remove optional BOM and change CRLF to LF on UTF-8 text). A derived artifact must identify its parent, and the derived bytes must match that parent transformation. A separate normalized_sha256 may be supplied only with an explicit matching normalization identifier. Neither digest establishes actual collection authenticity, trustworthy provenance, legal custody or record completeness.

### Observations and source-event matching

Each observation includes ID, kind, source, entity_ids, evidence_ids, occurred_at and description. Artifact-sourced facts additionally require source_event_id and referenced retained **JSONL** evidence.

Permitted event kinds: message_delivery, link_click, credential_submission_report, suspicious_sign_in, authorized_activity, benign_explanation, identity_log_gap.

Each JSONL row must contain event_id, kind, entity_ids and occurred_at, with optional summary. After SHA verification, the engine independently checks that a referenced row exists and agrees on event ID, kind, entity set and UTC instant. Incorrect or duplicate event IDs, source/observation conflicts, corrupted hashes and malformed source rows cause controlled failure. It preserves the original source offset and UTC microseconds. JSONL records are separated only by LF (including CRLF input), **not** by Unicode line separators inside JSON strings. Invalid timezone minutes, oversized integers, and excessively nested JSON/JSONL cause controlled rejection.

For authorization and benign-explanation observations, the optional list **explains_observation_ids** explicitly names the delivery observation(s) and their affected entities. A purported explanation cannot cite a delivery for a different entity. Only *artifact-backed authorization and explanation records that link to every relevant delivery and its identities* can support a benign case disposition. Unlinked labels may remain investigative observations but cannot clear an incident. An explicit identity_log_gap observation overrides contradictory declared log availability for confidence, warnings, investigation, and benign eligibility.

A reported observation remains *reported* even if a user-report text artifact exists; it is not promoted to directly verified telemetry.

### Severity and safety boundaries

This phase implements the repository's phishing severity convention:

- Reported credential submission: **provisional SEV-1**, urgent triage, but **not confirmed account takeover**.
- Link interaction or multiple reported recipients: provisional SEV-2 if no reported submission.
- Single suspicious delivery without interaction: provisional SEV-3 when applicable.
- Artifact-correlated, **observation- and identity-linked** authorization and benign explanations for *every* delivered event: a case-scoped benign disposition only when identity/mail coverage is consistent and no conflicting indicators or explicit log gaps exist.
- No supported criterion: severity pending, urgency assessed separately.

Confidence is a conservative educational label, not a statistical probability. Missing identity logs, explicitly reported logging gaps, contradictory coverage or incomplete evidence reduce assurance. Warnings and outstanding questions explicitly communicate unknowns; they cannot be cleared solely by a matching benign label.

Generated proposed actions are scoped to compatible **user/mailbox identities actually linked to triggering observations**; host/IP-only records never authorize identity-action targets. Unsupported identity mapping produces a warning/question rather than fallback actions against unrelated assets. Input proposed actions are also checked for compatible and observation-relevant targets. Generated IDs are deterministic and unique across all existing case IDs, using stable suffixes if necessary.

Allowed input action states are recommended and assumed_for_exercise. Any approved/attempted/verified state is reserved for future simulation, and rejected now. Approval, execution and verification remain **not_recorded** on the report. Recovery is always unverified. No response action runs.

## CLI from repository root

Python 3.11+ and standard library only. No pip, Docker, server or commercial API required.

    python -B -m ir_lab validate fixtures/ir_cases/positive.json
    python -B -m ir_lab triage fixtures/ir_cases/benign.json
    python -B -m ir_lab render fixtures/ir_cases/positive.json --format json --output incident-report.json
    python -B -m ir_lab render fixtures/ir_cases/positive.json --format markdown --output incident-report.md

Output destinations must be new, must have an existing parent directory, and must not alias a source case or retained evidence. File creation is atomic and no-clobber; a failed operation cleans up temporary output. Exit code 0 means success, 2 means a controlled invalid case/CLI/output failure. The output schema is **ir-result/1.0**.

Committed synthetic artifacts and case manifests can be verified offline:

    python -B scripts/generate_ir_fixtures.py --check

The fixture generator's write mode only creates missing files; it refuses to overwrite existing ones. Both ordinary and optimized Python (-O) fixture checks **actually read and compare retained bytes**. The scanner does **not** independently hunt every row in an artifact: it checks *nominated case observations*. Unreferenced JSONL records may exist without changing the verdict, and future IR workflows must not infer that unreferenced telemetry was comprehensively investigated. Physical artifact aliases (hardlinks and Windows trailing-dot paths) are rejected as duplicate evidence.

## Reproducible engineering evidence

    python -B -m unittest discover -s tests -v
    python -B scripts/generate_ir_fixtures.py --check

Independent expected results live in tests/expected/independent_triage_expectations.json, not in the engine; these now explicitly check **action targets, action IDs and decision-basis observation IDs**, not just action kinds. The mutation negative control injects a faulty severity evaluator into the real case acceptance path and proves the independent expectation detects it. Tests also cover unrelated benign evidence, contradictory identity log gaps, host-only and unrelated action scope, ID collisions, invalid timezone offset minutes, large/deep JSON, UTF-8 Unicode line separators in JSONL, Windows/hardlink file aliases, optimized fixture verification, evidence hashes/lineage, unsafe paths, Markdown injection, and safe no-clobber outputs.

CI retains Bash documentation validation and additionally runs the Python suite on Ubuntu/Windows and Python 3.11/3.13. Green CI demonstrates behavior in this **offline synthetic scope only**, not real-world response effectiveness.

## Future integration

Phase 2B may implement **pure in-memory simulated response states**, explicit approval, partial failure and checked recovery. Phase 2C may consume a versioned, pinned synthetic result from the separate [Threat Hunting Playbooks](https://github.com/farhan-shafee/threat-hunting-playbooks) project. Such a finding would require human review and would never automatically trigger a real account or network change. **There is no current cross-repository integration.**
