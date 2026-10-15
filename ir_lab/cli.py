"""Offline command line: validate, triage, render without network/response operations."""
from __future__ import annotations

import argparse
import sys

from .contracts import CaseError
from .evidence import canonical_json, case_from_file, validate_artifacts, write_new_file
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
