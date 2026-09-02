"""Each rule fires on its target, stays silent on clean resources, and raises Unevaluable
rather than passing when it cannot judge. Every positive is paired with a negative so a rule
that fires on everything cannot pass this suite."""

from __future__ import annotations

import pytest

from entraform import load_resources, scan, Severity, Unevaluable
from entraform.model import Resource
from entraform import rules


def _findings_by_rule(plan_json):
    report = scan(load_resources(plan_json))
    return {f.rule_id: f for f in report.findings}, report


def test_every_target_rule_fires_once(plan_json):
    found, report = _findings_by_rule(plan_json)
    for rule_id in ("ENT001", "ENT002", "ENT003", "ENT004", "ENT005"):
        assert rule_id in found, f"{rule_id} did not fire on its target"
    assert found["ENT001"].severity is Severity.CRITICAL


def test_clean_resource_produces_no_finding(plan_json):
    _, report = _findings_by_rule(plan_json)
    # The scoped Reader assignment must not appear in any finding.
    assert not any(f.resource == "azurerm_role_assignment.scoped" for f in report.findings)


def test_unevaluable_is_third_state_not_a_pass(plan_json):
    _, report = _findings_by_rule(plan_json)
    # The opaque app cannot be judged by ENT001 and must be surfaced, not silently cleared.
    assert any(u.resource == "azuread_application.opaque" and u.rule_id == "ENT001"
               for u in report.unevaluated)
    # And it must NOT appear as a finding.
    assert not any(f.resource == "azuread_application.opaque" for f in report.findings)


def test_ent001_ignores_delegated_scope_permission():
    # The same Graph id requested as a delegated Scope (not an application Role) is a
    # different risk and must not trip ENT001 — otherwise the rule cries wolf.
    r = Resource("azuread_application.x", "azuread_application", {
        "required_resource_access": [{"resource_access": [
            {"id": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", "type": "Scope"}]}]})
    assert rules.entra_app_tier0_graph_permission(r) is None


def test_ent004_does_not_fire_on_unconditional_mfa():
    # An MFA policy with no risk scoping is the correct baseline and must pass clean.
    r = Resource("azuread_conditional_access_policy.baseline", "azuread_conditional_access_policy", {
        "grant_controls": [{"built_in_controls": ["mfa"]}],
        "conditions": [{"users": [{"included_users": ["All"]}]}]})
    assert rules.conditional_access_mfa_scoped_by_risk(r) is None


def test_ent002_scoped_assignment_is_clean():
    r = Resource("a", "azurerm_role_assignment", {
        "role_definition_name": "Owner",
        "scope": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/app"})
    assert rules.azure_role_assignment_privileged_broad_scope(r) is None


def test_ent003_secret_with_expiry_is_clean():
    r = Resource("a", "azuread_application_password", {"end_date_relative": "4320h"})
    assert rules.entra_app_password_no_expiry(r) is None
