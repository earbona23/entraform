"""The shapes a finding and a scanned resource take.

Two design rules carried over from the rest of this author's tooling, because they are
what a security linter lives or dies by:

1. Three outcomes, never two. A rule returns a Finding (something is wrong), returns
   nothing (this resource is fine), or raises Unevaluable (the rule could not judge this
   resource — a field it needed was absent, a shape it did not recognise). An Unevaluable
   is surfaced, never silently folded into "fine". A linter that cannot tell "clean" from
   "could not look" is a linter that lies on the day it matters.

2. Every finding names the exact resource, the rule, why it matters, and the fix. A finding
   an engineer cannot act on is noise, and noise gets the whole tool switched off in CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


@dataclass(frozen=True)
class Resource:
    """One resource from a Terraform plan's resource_changes."""
    address: str            # e.g. azuread_application.payroll
    type: str               # e.g. azuread_application
    after: dict             # the planned attributes (change.after)
    provider: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    resource: str           # the resource address
    title: str
    detail: str             # what was observed, concretely
    remediation: str        # the specific change to make

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "resource": self.resource,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


class Unevaluable(Exception):
    """A rule could not judge a resource — a needed field was missing or the shape was
    unfamiliar. This is the third state: reported as review-needed, never as a pass."""

    def __init__(self, resource: str, rule_id: str, reason: str):
        self.resource = resource
        self.rule_id = rule_id
        self.reason = reason
        super().__init__(f"{rule_id} could not evaluate {resource}: {reason}")


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    unevaluated: list[Unevaluable] = field(default_factory=list)
    resources_scanned: int = 0

    @property
    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.rule_id, f.resource))
