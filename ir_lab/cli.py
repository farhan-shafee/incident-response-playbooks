"""Offline command line: validate, triage, render without network/response operations."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .contracts import CaseError
from .evidence import canonical_json, case_from_file, safe_artifact, validate_artifacts, write_new_file
from .events import verify_event_references
from .report import markdown
from .triage import evaluate


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m ir_lab",
        description="Validate and triage explicitly synthetic phishing cases OFFLINE; never execute response actions.")
    commands = p.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate case schema, hashes and correlated event rows")
    validate.add_argument("case", help="Path to JSON case file")
    triage = commands.add_parser("triage", help="Print deterministic JSON triage to stdout")
    triage.add_argument("case")
    render = commands.add_parser("render", help="Write a NEW deterministic JSON or Markdown report")
    render.add_argument("case")
    render.add_argument("--format", choices=("json", "markdown"), required=True)
    render.add_argument("--output", required=True, help="Path must not exist; no overwrite allowed")
    for name, help_text in (
        ("simulation-validate", "Validate synthetic plan, evidence and replay without creating output"),
        ("simulate", "Replay synthetic approvals/actions and print deterministic JSON"),
        ("simulation-render", "Write a NEW deterministic synthetic simulation report"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("case", help="Validated Phase 2A case JSON")
        command.add_argument("--plan", required=True, help="Local ir-simulation/1.0 plan JSON")
        if name == "simulation-render":
            command.add_argument("--format", choices=("json", "markdown"), required=True)
            command.add_argument("--output", required=True, help="NEW destination; no overwrite allowed")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        case = case_from_file(args.case)
        artifacts = validate_artifacts(case, args.case)
        matched = verify_event_references(case, args.case)
        if args.command == "validate":
            print(f"VALID synthetic case {case['case_id']}; "
                  f"{len(artifacts)} hashed artifacts; {len(matched)} correlated event references")
            return 0
        result = evaluate(case, artifacts)
        result["correlated_event_references"] = matched
        if args.command in {"simulation-validate", "simulate", "simulation-render"}:
            # Separate versioned contract; the Phase 2A result is never mutated.
            from .simulation_contracts import load_plan
            from .simulation_engine import replay
            from .simulation_report import markdown as simulation_markdown
            from .simulation_verification import load_evidence

            plan = load_plan(args.plan, case, result)
            simulation_artifacts, records = load_evidence(plan, args.plan)
            simulation = replay(plan, result, records, simulation_artifacts)
            if args.command == "simulation-validate":
                print(f"VALID synthetic simulation {plan['simulation_id']}; "
                      f"{len(simulation['events'])} replayed events; no real actions executed")
                return 0
            if args.command == "simulate":
                sys.stdout.buffer.write(canonical_json(simulation))
                return 0
            raw = canonical_json(simulation) if args.format == "json" else simulation_markdown(simulation)
            # Guard both input trees, even though they may reside in different directories.
            forbidden = {Path(args.case).resolve(), Path(args.plan).resolve()}
            for source, manifest in ((args.case, case), (args.plan, plan)):
                forbidden.update(safe_artifact(Path(source).parent, e["path"]).resolve()
                                 for e in manifest["evidence"])
            from .contracts import require
            require(Path(args.output).resolve() not in forbidden, "output: cannot alias simulation inputs")
            write_new_file(args.output, raw, args.plan, plan)
            print(f"CREATED {args.format} SYNTHETIC simulation report for {plan['simulation_id']}")
            return 0
        if args.command == "triage":
            sys.stdout.buffer.write(canonical_json(result))
            return 0
        raw = canonical_json(result) if args.format == "json" else markdown(result)
        write_new_file(args.output, raw, args.case, case)
        print(f"CREATED {args.format} report for {case['case_id']}")
        return 0
    except CaseError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
