"""The rules. Each is grounded in a real identity attack path, not a style preference.

Every rule is a function `resource -> Finding | None`, and may raise Unevaluable when the
resource is missing a field it needs. Rules never mutate the resource and never reach the
network — they read the planned attributes and judge them. That is the whole trust model:
this runs in someone else's CI against their infrastructure, so it must be incapable of
doing anything except reading a plan.
"""

from __future__ import annotations

from collections.abc import Callable

from .model import Finding, Resource, Severity, Unevaluable

Rule = Callable[[Resource], Finding | None]

# Microsoft Graph app-role ids that hand an application effective control of the directory.
# A service principal holding any of these can escalate to Global Administrator, so an app
# registration that requests them as *application* permissions is a standing privilege-
# escalation path — the exact shape behind the EntraGoat lab and BloodHound's AZ edges.
# id -> human name. Application permissions (Role), not delegated (Scope).
TIER0_GRAPH_APP_ROLES: dict[str, str] = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
}

# Azure RBAC roles that are effectively tenant-or-subscription takeover at a broad scope.
PRIVILEGED_AZURE_ROLES = {"Owner", "User Access Administrator", "Contributor"}
BROAD_SCOPE_MARKERS = ("/providers/Microsoft.Management/managementGroups/", "/subscriptions/")


def _require(resource: Resource, key: str):
    if key not in resource.after or resource.after.get(key) is None:
        raise Unevaluable(resource.address, "", f"planned attribute '{key}' is absent")
    return resource.after[key]


def entra_app_tier0_graph_permission(resource: Resource) -> Finding | None:
    """ENT001 — an app registration requesting a directory-takeover Graph app role."""
    if resource.type != "azuread_application":
        return None
    accesses = resource.after.get("required_resource_access")
    if accesses is None:
        raise Unevaluable(resource.address, "ENT001", "required_resource_access not in plan")
    hits: list[str] = []
    for rra in accesses:
        for access in rra.get("resource_access", []) or []:
            if access.get("type") == "Role" and access.get("id") in TIER0_GRAPH_APP_ROLES:
                hits.append(TIER0_GRAPH_APP_ROLES[access["id"]])
    if not hits:
        return None
    names = ", ".join(sorted(set(hits)))
    return Finding(
        rule_id="ENT001",
        severity=Severity.CRITICAL,
        resource=resource.address,
        title="App registration requests a directory-takeover Graph permission",
        detail=(
            f"Requests the application permission(s) {names}. A service principal holding "
            "any of these can grant itself further roles or credentials and escalate to "
            "Global Administrator — anyone who can add a credential to this app inherits that."
        ),
        remediation=(
            "Remove the tier-0 permission, or replace it with the narrowest role that does "
            "the job (e.g. Directory.Read.All instead of Directory.ReadWrite.All). If the "
            "write is genuinely required, isolate this app, gate credential issuance, and "
            "monitor its sign-ins."
        ),
    )


def azure_role_assignment_privileged_broad_scope(resource: Resource) -> Finding | None:
    """ENT002 — Owner/UAA/Contributor granted at subscription or management-group scope."""
    if resource.type != "azurerm_role_assignment":
        return None
    role = resource.after.get("role_definition_name")
    scope = resource.after.get("scope")
    if role is None or scope is None:
        # A role assignment by definition id rather than name is a different, valid shape we
        # do not resolve here — say so rather than pass it.
        raise Unevaluable(resource.address, "ENT002",
                          "role_definition_name or scope not resolvable from plan")
    if role not in PRIVILEGED_AZURE_ROLES:
        return None
    if not any(marker in scope and scope.count("/") <= 4 for marker in BROAD_SCOPE_MARKERS):
        return None  # a narrow (resource-level) grant of these roles is a different judgement
    return Finding(
        rule_id="ENT002",
        severity=Severity.HIGH,
        resource=resource.address,
        title=f"'{role}' granted at a subscription or management-group scope",
        detail=(
            f"Assigns {role} at '{scope}'. At this breadth the principal controls every "
            "resource beneath it; Owner and User Access Administrator additionally let it "
            "grant roles to anyone, which is lateral movement across the whole scope."
        ),
        remediation=(
            "Scope the assignment to the specific resource group or resource that needs it, "
            "or use a purpose-built custom role. Reserve subscription-level Owner for "
            "break-glass, and prefer PIM-eligible over permanent."
        ),
    )


def conditional_access_mfa_scoped_by_risk(resource: Resource) -> Finding | None:
    """ENT004 — an MFA Conditional Access policy narrowed so it does not cover normal sign-ins.

    This is the class behind the CISA ScubaGear MS.AAD.3.x gap: a policy that grants MFA but
    is scoped to high risk levels only does not apply to the ordinary sign-ins it is supposed
    to protect, while still looking like MFA coverage.
    """
    if resource.type != "azuread_conditional_access_policy":
        return None
    grant = resource.after.get("grant_controls")
    conditions = resource.after.get("conditions")
    if grant is None or conditions is None:
        raise Unevaluable(resource.address, "ENT004", "grant_controls or conditions absent")

    def _flatten(value) -> list:
        if isinstance(value, list):
            out = []
            for v in value:
                out.extend(_flatten(v))
            return out
        return [value]

    controls = [str(c).lower() for c in _flatten(grant)]
    requires_mfa = any("mfa" in c for c in controls)
    if not requires_mfa:
        return None

    cond = conditions[0] if isinstance(conditions, list) and conditions else conditions
    risk_scoped = bool(cond.get("sign_in_risk_levels") or cond.get("user_risk_levels"))
    if not risk_scoped:
        return None
    return Finding(
        rule_id="ENT004",
        severity=Severity.HIGH,
        resource=resource.address,
        title="MFA Conditional Access policy is scoped to risk levels only",
        detail=(
            "Requires MFA but is narrowed by sign_in_risk_levels / user_risk_levels, so it "
            "does not apply to ordinary sign-ins — the ones it is meant to protect. The "
            "tenant looks MFA-covered while most authentications are exempt. This is the "
            "same fail-open shape CISA's ScubaGear flags for MS.AAD.3.x."
        ),
        remediation=(
            "If this policy is your baseline MFA enforcement, remove the risk-level scoping "
            "so it targets all users and all sign-ins. If risk-based step-up is intended, "
            "keep it as a *separate* policy and add an unconditional MFA baseline alongside it."
        ),
    )


def entra_app_password_no_expiry(resource: Resource) -> Finding | None:
    """ENT003 — an application password (client secret) with no end date."""
    if resource.type != "azuread_application_password":
        return None
    if "end_date" in resource.after and resource.after.get("end_date"):
        return None
    if "end_date_relative" in resource.after and resource.after.get("end_date_relative"):
        return None
    # Neither an absolute nor a relative expiry is set in the plan.
    if "end_date" not in resource.after and "end_date_relative" not in resource.after:
        raise Unevaluable(resource.address, "ENT003",
                          "neither end_date nor end_date_relative present in plan")
    return Finding(
        rule_id="ENT003",
        severity=Severity.MEDIUM,
        resource=resource.address,
        title="Application client secret has no expiry",
        detail=(
            "This azuread_application_password sets neither end_date nor end_date_relative, "
            "so the credential does not expire. A long-lived secret that leaks stays valid "
            "indefinitely, and rotation never gets forced."
        ),
        remediation=(
            "Set end_date_relative (e.g. \"4320h\" for ~6 months) and rotate on a schedule. "
            "Prefer certificate credentials or workload-identity federation over passwords."
        ),
    )


def azure_custom_role_wildcard_action(resource: Resource) -> Finding | None:
    """ENT005 — a custom Azure role definition granting the wildcard action '*'."""
    if resource.type != "azurerm_role_definition":
        return None
    perms = resource.after.get("permissions")
    if perms is None:
        raise Unevaluable(resource.address, "ENT005", "permissions block not in plan")
    for block in perms:
        actions = block.get("actions") or []
        if "*" in actions:
            return Finding(
                rule_id="ENT005",
                severity=Severity.HIGH,
                resource=resource.address,
                title="Custom role definition grants the wildcard action '*'",
                detail=(
                    "The permissions block allows actions = [\"*\"], which is every "
                    "management operation in scope — functionally equivalent to Owner and "
                    "the opposite of a custom least-privilege role."
                ),
                remediation=(
                    "Enumerate the specific actions the role needs. If you truly need "
                    "everything, use the built-in Owner role so the intent is explicit and "
                    "auditable rather than hidden in a custom definition."
                ),
            )
    return None


ALL_RULES: list[Rule] = [
    entra_app_tier0_graph_permission,
    azure_role_assignment_privileged_broad_scope,
    conditional_access_mfa_scoped_by_risk,
    entra_app_password_no_expiry,
    azure_custom_role_wildcard_action,
]
