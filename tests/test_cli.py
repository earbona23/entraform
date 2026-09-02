"""The exit-code contract that CI depends on."""

from __future__ import annotations

import json
from entraform.cli import main


def _write(tmp_path, plan_json):
    p = tmp_path / "plan.json"
    p.write_text(plan_json)
    return str(p)


def test_findings_fail_the_build(tmp_path, plan_json, capsys):
    code = main([_write(tmp_path, plan_json), "--no-color"])
    assert code == 1  # there are CRITICAL/HIGH findings


def test_json_output_is_parseable(tmp_path, plan_json, capsys):
    main([_write(tmp_path, plan_json), "-f", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["tool"] == "entraform"
    assert {f["rule_id"] for f in data["findings"]} >= {"ENT001", "ENT002", "ENT004"}


def test_clean_plan_exits_zero(tmp_path, capsys):
    clean = json.dumps({"resource_changes": [
        {"address": "azurerm_role_assignment.ok", "type": "azurerm_role_assignment",
         "change": {"actions": ["create"], "after": {"role_definition_name": "Reader",
          "scope": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/a"}}}]})
    assert main([_write(tmp_path, clean), "--no-color"]) == 0


def test_bad_input_exits_two(tmp_path, capsys):
    bad = tmp_path / "state.json"
    bad.write_text('{"values": {}}')  # state, not a plan
    assert main([str(bad)]) == 2


def test_missing_file_exits_two():
    assert main(["/nonexistent/plan.json"]) == 2
