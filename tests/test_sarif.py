"""SARIF output is well-formed enough for GitHub code scanning to ingest."""

from __future__ import annotations

import json
from entraform import load_resources, scan
from entraform.sarif import to_sarif


def test_sarif_is_valid_2_1_0(plan_json):
    report = scan(load_resources(plan_json))
    doc = json.loads(to_sarif(report, plan_path="infra/plan.json"))

    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "entraform"

    # One result per finding, each with a ruleId, a level, a message, and a location.
    results = run["results"]
    assert len(results) == len(report.findings)
    for r in results:
        assert r["ruleId"]
        assert r["level"] in ("error", "warning", "note")
        assert r["message"]["text"]
        assert r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
        assert r["partialFingerprints"]["entraform/v1"]

    # Every ruleId in a result has a matching rule descriptor in the driver.
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in results} <= rule_ids

    # A critical finding maps to error + a high security-severity for the Security tab.
    crit = next(r for r in results if r["ruleId"] == "ENT001")
    assert crit["level"] == "error"
    desc = next(x for x in run["tool"]["driver"]["rules"] if x["id"] == "ENT001")
    assert float(desc["properties"]["security-severity"]) >= 9.0


def test_sarif_fingerprint_is_stable(plan_json):
    # The same finding must fingerprint identically across runs, so GitHub does not
    # re-alert on every push.
    a = json.loads(to_sarif(scan(load_resources(plan_json))))
    b = json.loads(to_sarif(scan(load_resources(plan_json))))
    fa = [r["partialFingerprints"]["entraform/v1"] for r in a["runs"][0]["results"]]
    fb = [r["partialFingerprints"]["entraform/v1"] for r in b["runs"][0]["results"]]
    assert fa == fb
