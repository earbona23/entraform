"""SARIF 2.1.0 output.

SARIF is what makes a linter a first-class citizen in a repository: GitHub renders a SARIF
upload as annotations on the pull request and as entries in the Security tab, so a finding
lands next to the line that caused it instead of scrolling past in a log. That is the
difference between a tool people glance at and a tool people adopt.

We emit the minimum well-formed SARIF that GitHub's code-scanning ingester accepts: a single
run, one rule object per rule id actually seen, and one result per finding. Levels map from
our severity, and `partialFingerprints` keep a finding stable across runs so GitHub does not
re-alert on the same issue every push.
"""

from __future__ import annotations

import hashlib
import json

from . import __version__
from .model import Report, Severity

# SARIF has three levels; our four severities fold onto them. GitHub also reads the
# security-severity property (a CVSS-like number) to bucket Critical/High/Medium/Low in the
# Security tab, so we set both.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}

INFO_URI = "https://github.com/earbona23/entraform"


def to_sarif(report: Report, plan_path: str = "plan.json") -> str:
    # One rule descriptor per rule id that actually produced a finding, deduplicated.
    rules_seen: dict[str, dict] = {}
    results: list[dict] = []

    for f in report.sorted_findings():
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.detail},
                "helpUri": INFO_URI,
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {"security-severity": _SECURITY_SEVERITY[f.severity]},
            }
        fingerprint = hashlib.sha256(
            f"{f.rule_id}:{f.resource}".encode()
        ).hexdigest()[:16]
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title} — {f.detail}\nFix: {f.remediation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": plan_path},
                },
                "logicalLocations": [{
                    "fullyQualifiedName": f.resource,
                    "kind": "resource",
                }],
            }],
            "partialFingerprints": {"entraform/v1": fingerprint},
            "properties": {"resource": f.resource, "severity": f.severity.value},
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "entraform",
                    "informationUri": INFO_URI,
                    "version": __version__,
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
