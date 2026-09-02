"""The command line. Exit codes are a contract, because this lives in CI.

    0  no findings (an all-clear the pipeline can trust)
    1  findings at or above the fail threshold
    2  bad input (could not read the plan)

Unevaluated resources never change the exit code on their own — they are surfaced so a
human decides, but "could not check this one" is not the same as "this one failed" and must
not silently fail a build. It is reported, and `--strict` promotes it if a team wants that.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .engine import scan
from .model import Report, Severity
from .plan import load_resources

_COLOR = {"critical": "\033[41m\033[97m", "high": "\033[91m", "medium": "\033[93m",
          "low": "\033[90m", "reset": "\033[0m", "dim": "\033[2m"}


def _c(text: str, key: str, enabled: bool) -> str:
    return f"{_COLOR[key]}{text}{_COLOR['reset']}" if enabled else text


def render_text(report: Report, color: bool) -> str:
    out: list[str] = []
    if not report.findings:
        out.append(_c("entraform: no identity misconfigurations found", "low", color)
                   + _c(f"  ({report.resources_scanned} resources scanned)", "dim", color))
    else:
        out.append(f"entraform found {len(report.findings)} issue(s) "
                   f"in {report.resources_scanned} resources:\n")
        for f in report.sorted_findings():
            tag = _c(f" {f.severity.value.upper()} ", f.severity.value, color)
            out.append(f"{tag} {_c(f.rule_id, 'dim', color)}  {f.resource}")
            out.append(f"    {f.title}")
            out.append(_c(f"    {f.detail}", "dim", color))
            out.append(_c(f"    fix: {f.remediation}", "dim", color))
            out.append("")
    if report.unevaluated:
        out.append(_c(f"\n{len(report.unevaluated)} resource(s) could not be evaluated "
                      "(review needed, not a pass):", "medium", color))
        for u in report.unevaluated:
            out.append(_c(f"    {u.rule_id or '?'}  {u.resource}: {u.reason}", "dim", color))
    return "\n".join(out)


def render_json(report: Report) -> str:
    return json.dumps({
        "tool": "entraform",
        "version": __version__,
        "resources_scanned": report.resources_scanned,
        "findings": [f.to_dict() for f in report.sorted_findings()],
        "unevaluated": [{"rule_id": u.rule_id, "resource": u.resource, "reason": u.reason}
                        for u in report.unevaluated],
    }, indent=2)


_THRESHOLDS = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "medium": Severity.MEDIUM, "low": Severity.LOW}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="entraform",
        description="Identity-aware security linter for Terraform plans (Entra ID / Azure).",
    )
    parser.add_argument("plan", help="path to `terraform show -json <plan>` output, or - for stdin")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=list(_THRESHOLDS), default="high",
                        help="minimum severity that sets a non-zero exit (default: high)")
    parser.add_argument("--strict", action="store_true",
                        help="also fail if any resource could not be evaluated")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"entraform {__version__}")
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.plan == "-" else open(args.plan, encoding="utf-8").read()
    except OSError as e:
        print(f"entraform: cannot read {args.plan}: {e}", file=sys.stderr)
        return 2
    try:
        resources = load_resources(raw)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"entraform: {e}", file=sys.stderr)
        return 2

    report = scan(resources)
    color = sys.stdout.isatty() and not args.no_color
    print(render_json(report) if args.format == "json" else render_text(report, color))

    threshold = _THRESHOLDS[args.fail_on]
    failing = [f for f in report.findings if f.severity.rank >= threshold.rank]
    if failing:
        return 1
    if args.strict and report.unevaluated:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
