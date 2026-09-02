"""Run every rule over every resource, collecting findings and the third state."""

from __future__ import annotations

from .model import Report, Resource, Unevaluable
from .rules import ALL_RULES, Rule


def scan(resources: list[Resource], rules: list[Rule] | None = None) -> Report:
    rules = rules if rules is not None else ALL_RULES
    report = Report(resources_scanned=len(resources))
    for resource in resources:
        for rule in rules:
            try:
                finding = rule(resource)
            except Unevaluable as u:
                report.unevaluated.append(u)
                continue
            if finding is not None:
                report.findings.append(finding)
    return report
