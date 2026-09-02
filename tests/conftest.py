"""A synthetic Terraform plan whose resources each trip exactly one rule, plus clean and
unevaluable controls. Built inline so the tests exercise the same plan-JSON contract a real
`terraform show -json` produces."""

from __future__ import annotations

import json
import pytest


def _rc(address, rtype, after, actions=("create",)):
    return {"address": address, "type": rtype, "provider_name": "registry.terraform.io/hashicorp/azuread",
            "change": {"actions": list(actions), "after": after}}


@pytest.fixture
def plan_json() -> str:
    return json.dumps({
        "format_version": "1.2",
        "resource_changes": [
            # ENT001: tier-0 Graph app permission (RoleManagement.ReadWrite.Directory)
            _rc("azuread_application.payroll", "azuread_application", {
                "display_name": "payroll",
                "required_resource_access": [{
                    "resource_app_id": "00000003-0000-0000-c000-000000000000",
                    "resource_access": [
                        {"id": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", "type": "Role"}
                    ],
                }],
            }),
            # ENT002: Owner at subscription scope
            _rc("azurerm_role_assignment.broad", "azurerm_role_assignment", {
                "role_definition_name": "Owner",
                "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
            }),
            # ENT003: client secret with no expiry
            _rc("azuread_application_password.legacy", "azuread_application_password", {
                "application_object_id": "abc",
                "end_date": None,           # present but empty = no expiry was set
                "end_date_relative": None,
            }),
            # ENT004: MFA CA policy scoped to risk levels
            _rc("azuread_conditional_access_policy.mfa", "azuread_conditional_access_policy", {
                "display_name": "Require MFA",
                "grant_controls": [{"built_in_controls": ["mfa"]}],
                "conditions": [{"sign_in_risk_levels": ["high"], "users": [{"included_users": ["All"]}]}],
            }),
            # ENT005: custom role with wildcard action
            _rc("azurerm_role_definition.godmode", "azurerm_role_definition", {
                "name": "godmode",
                "permissions": [{"actions": ["*"], "not_actions": []}],
            }),
            # CLEAN control: a scoped, least-privilege role assignment — must produce nothing
            _rc("azurerm_role_assignment.scoped", "azurerm_role_assignment", {
                "role_definition_name": "Reader",
                "scope": "/subscriptions/x/resourceGroups/rg-app/providers/Microsoft.Web/sites/app",
            }),
            # UNEVALUABLE control: an app with no required_resource_access in the plan
            _rc("azuread_application.opaque", "azuread_application", {"display_name": "opaque"}),
        ],
    })
