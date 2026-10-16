# Offline Response Simulation — Phase 2B

This is a synthetic, deterministic exercise. It changes no account, session,
message, endpoint or service. Simulated approval is not operational authority.

## Implemented architecture

Validated Phase 2A case + canonical result -> exact digest/action bindings ->
strict simulation contract -> hashed synthetic evidence -> event replay ->
independent state observations -> recovery gates -> JSON/Markdown receipts.

Implementation is deliberately separate from `ir-case/1.0`:

1. `ir_lab/simulation_contracts.py` checks schema, digests and scope.
2. `simulation_verification.py` hashes local JSONL and evaluates record structure and outcomes.
3. `simulation_engine.py` replays approvals/attempts and evaluates recovery gates.
4. `simulation_report.py` renders synthetic evidence receipts; the CLI preserves Phase 2A behavior.
5. Synthetic fixtures and literal expected outcomes are authored separately from
   the simulation evaluator. Tests include deliberately faulty replay outcomes.
6. The existing five CI jobs check fixtures and behavior on Ubuntu/Windows with
   Python 3.11/3.13, including fixture checks under optimized Python.

## Contract: ir-simulation/1.0

All objects reject unknown keys. All IDs are bounded identifiers. Lists are
bounded and references must resolve. Every timestamp is an explicit offset-aware
ISO timestamp using Phase 2A's strict parser. Canonical JSON uses sorted keys,
two-space indentation, UTF-8 and one final LF. No clock or random ID enters a report.

Top-level fields:

| Field | Meaning |
|---|---|
| schema_version | `ir-simulation/1.0` |
| simulation_id, synthetic | Exercise ID and literal `true` |
| case_id | Exact validated Phase 2A case ID |
| case_sha256 | SHA-256 of canonical validated case JSON; not raw file bytes |
| result_sha256 | SHA-256 of complete canonical Phase 2A result including event references |
| as_of | Explicit latest simulated instant |
| actors | `{id, display_name, role, synthetic}`; IDs start `sim_`, roles approver/operator/verifier/reviewer |
| actions | Every actual proposed action, exactly once; `{action_id, kind, target_ids, supporting_observation_ids}` |
| evidence | Phase 2A artifact descriptors, relative to the plan; actual raw bytes checked |
| events | Ordered, bounded transition requests, replayed and checked |
| recovery | Observation window, monitoring references, residual risks and optional acceptance |

All Phase 2A proposals are required for this bounded exercise's closure; the plan
cannot omit or mark a failed action optional. Action binding digest is SHA-256 of
canonical `{case_id, case_sha256, result_sha256, action}` where action is its exact
binding with sorted target/support IDs. It is consistency binding, not a signature.
Actors are fictional annotations, not authenticated identities or access control.

Each event has `id, at, action_id, target_ids, previous_state, new_state, kind,
reason, evidence_refs`. A reference is `{evidence_id, record_id}`.

- `approval`: also `approver_id, expires_at, binding_sha256`. Empty evidence refs;
  new state is `approved_simulated` or `denied`. Expiry must follow approval.
- `attempt`: also `operator_id`. Exactly one acknowledgement reference. Exact
  approved targets required; approval must still be valid at attempted time.
- `verification`: evidence references identify separate verification records.
  New state must equal the evaluator's derived outcome, never a self-declared flag.

## State machine

`recommended -> approved_simulated | denied`

`approved_simulated -> attempted_simulated`

`attempted_simulated -> verified_effective_synthetic | partially_effective | failed | unverified`

All other transitions reject. Terminal outcomes cannot be overwritten or retried
in v1. Conflicting/replayed approvals, duplicate events, scope drift and ordering
violations reject the plan. Missing approval leaves an action recommended.
Expiry is exclusive at attempt time; later expiry does not erase a valid past attempt.

## Synthetic evidence records

All plan artifacts are bounded UTF-8 JSONL files. Duplicate keys, duplicate scoped
record IDs and invalid references reject. Acknowledgement and verification are
different record types; an acknowledgement can never serve as verification.

Acknowledgement keys: `record_id, record_type` (`acknowledgement`), `action_id,
kind, target_ids, at, operator_id, acknowledged` (boolean).

Verification keys: `record_id, record_type` (`verification`), `action_id, kind,
target_id, at, verifier_id, observed_state, window_start, window_end`.

The verifier role differs from operator/approver. Observation windows cannot
precede the attempt, and must finish by the record/event/as-of instant.

| Action | Effective observation | Adverse observation |
|---|---|---|
| investigate_signins | review_complete | unauthorized_access_present |
| review_authentication_methods | trusted_methods_only | untrusted_method_present |
| revoke_sessions | no_active_sessions | active_session |
| quarantine_message | quarantined | delivered |
| scope_recipients | scope_complete | scope_incomplete |

`unknown` is also permitted. Every target must have independent effective evidence
for a verified outcome. Some effective targets with missing/adverse/unknown targets
are partially effective; adverse evidence without effective targets is failed;
otherwise the outcome is unverified. Duplicate/conflicting observations for a target
reject across **all supplied artifacts**, including unreferenced records, instead
of choosing the most favorable record. V1 allows one verification and one monitoring
record per action/target; retries and time-series reconciliation are unsupported.

Monitoring records use the same shape as verification with `record_type=monitoring`
and `observed_state=clear|adverse|unknown`. They refer to exact actions and targets.

## Recovery and closure

`recovery` contains `observation_start, observation_end, monitoring_refs,
residual_risks, acceptance`. Acceptance is null or `{reviewer_id, at, rationale,
residual_risk_acknowledged, closure_requested}`. These booleans are requests and
acknowledgements, not proof of effectiveness.

Closure requires every bound action verified effective, complete clear monitoring
for every action/target across the requested window, an elapsed window at `as_of`,
and explicit synthetic reviewer acceptance strictly after all relevant events/observations
with residual risk acknowledged. Otherwise reasons remain visible and closure is
false. The result's `simulation_closure_accepted` never changes Phase 2A's original
`incident_closure_verified=false` or claims real recovery.

The recovery window starts at or after the last action-verification event. Records
cannot postdate their artifact's collection or the supplied `as_of`; acceptance
must also follow collection of its used evidence. Unconsumed verification/monitoring
records block closure, so an adverse supplied row cannot be hidden by omitting its
reference. Duplicate/conflicting per-target verification or monitoring rejects.
Recovery is `accepted_synthetic` only when every gate passes; otherwise it remains
`unverified`, with explicit blocking reasons and individual action outcomes.

Replay is stateless: identical case, plan and artifact bytes yield identical output.
Re-running does not append history or execute any action. Event history is checked
in input order and retained in that causal order, including timestamp ties. This is not a signed,
tamper-proof audit log or independently acquired evidence.

## Internal interfaces

- `simulation_contracts.digest(value) -> str`, `action_binding_digest(plan, action) -> str`
- `simulation_contracts.validate_plan(plan, case, result) -> dict`
- `simulation_contracts.load_plan(path, case, result) -> dict`
- `simulation_verification.load_evidence(plan, path) -> (artifact_register, records)`;
  records are indexed by `(evidence_id, record_id)`.
- `simulation_engine.replay(plan, case_result, records, artifacts) -> dict`;
  validated input only, pure replay, returns `ir-simulation-result/1.0` with
  `actions` (binding plus `state` and simulated status receipts), `events`,
  `recovery` (`state, simulation_closure_accepted, blocking_reasons`), `evidence`,
  unchanged `phase2a_triage`, digests and explicit safety limitations.
- `simulation_report.markdown(result) -> bytes`

CLI: `simulation-validate CASE --plan PLAN`, `simulate CASE --plan PLAN` (JSON
stdout), `simulation-render CASE --plan PLAN --format json|markdown --output NEW`.
No disk report without explicit output; existing files/inputs are preserved.

Exit 0 means the requested validation/replay/render completed, **not** that closure
was accepted. Exit 2 means invalid arguments, schema, bindings, evidence, transition
or destination. Denied and partially effective simulations are valid assessments
and return 0 with closure false. Expired attempted authorization rejects with 2.

## Reproduction and five-minute interview demonstration

Run from the repository root with Python 3.11+; `--output` must name a new file:

    python -B -m ir_lab simulation-validate fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/success.json
    python -B -m ir_lab simulate fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/success.json
    python -B -m ir_lab simulate fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/denied.json
    python -B -m ir_lab simulate fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/partial.json
    python -B -m ir_lab simulate fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/misleading_success.json
    python -B -m ir_lab simulation-render fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/success.json --format json --output response-result.json
    python -B -m ir_lab simulation-render fixtures/ir_cases/response_case.json --plan fixtures/ir_simulations/misleading_success.json --format markdown --output response-report.md

Representative result fields, verified by independent literal expectations:

| Plan | Session action state | Acknowledgement | Simulation closure |
|---|---|---|---|
| success | verified_effective_synthetic | true | true |
| denied | denied | not recorded | false |
| partial | failed | false | false |
| misleading_success | failed (active_session observed) | true | false |
| missing_approval | recommended | not recorded | false |
| expired | rejected before output | not accepted | no report |

1. Show `response_case.json`: it extends the positive phishing fixture with a
   justified quarantine proposal; the original case/evidence is preserved.
2. Validate success and show the case/result/action digests plus scoped approval.
3. Compare denied/missing approval with the success history. No attempt is inferred.
4. Open the misleading-success Markdown report: operator acknowledgement true is
   displayed separately from the verifier's active-session record and failed state.
5. Compare complete success monitoring/reviewer acceptance with partial failure;
   show the blocked closure reasons and unchanged original Phase 2A assessment.

Check retained inputs and behavioral expectations:

    python -B scripts/generate_ir_fixtures.py --check
    python -B scripts/generate_simulation_fixtures.py --check
    python -O -B scripts/generate_simulation_fixtures.py --check
    python -B -m unittest discover -s tests -v

The simulation generator uses Phase 2A only to compute input consistency bindings.
It does not import the simulation evaluator. Its expected outcomes are literal
author decisions, checked by tests and by mutation of the real replay path.
`--write` only creates a complete new fixture set and refuses existing destinations.

## Limits

First phishing exercise only. No real response adapters, external enrichment,
authentication, cryptographic approval identity, persistent ledger, retries, UI,
database or Threat Hunting integration. Analyst classifications and synthetic
records are supplied inputs; a hash does not make them authentic production facts.
