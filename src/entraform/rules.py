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


# Well-known Entra directory role template ids that are tier-0 — whoever holds one of these,
# permanently and outside PIM, is standing privilege an attacker only has to reach once.
PRIVILEGED_DIRECTORY_ROLE_TEMPLATES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}

NON_ENFORCING_CA_STATES = {"disabled", "enabledForReportingButNotEnforced"}
GITHUB_ACTIONS_ISSUER = "token.actions.githubusercontent.com"


def entra_role_assignable_group(resource: Resource) -> Finding | None:
    """ENT006 — a group created as role-assignable is a tier-0 object."""
    if resource.type != "azuread_group":
        return None
    if "assignable_to_role" not in resource.after:
        raise Unevaluable(resource.address, "ENT006", "assignable_to_role not in plan")
    if resource.after.get("assignable_to_role") is not True:
        return None
    return Finding(
        rule_id="ENT006", severity=Severity.HIGH, resource=resource.address,
        title="Group is role-assignable (tier-0)",
        detail=(
            "assignable_to_role = true. This group can be granted a directory role, so anyone "
            "who can change its membership can grant that role — a self-service path to whatever "
            "the group is later assigned. It must be governed like a privileged role."
        ),
        remediation=(
            "Only create role-assignable groups when you deliberately need one, restrict who "
            "owns and manages it, and prefer PIM for Groups over standing membership. If this "
            "group does not need to hold a role, set assignable_to_role = false."
        ),
    )


def conditional_access_enforcing_policy_disabled(resource: Resource) -> Finding | None:
    """ENT007 — a CA policy that enforces MFA / blocks legacy auth but is disabled or report-only."""
    if resource.type != "azuread_conditional_access_policy":
        return None
    state = resource.after.get("state")
    if state is None:
        raise Unevaluable(resource.address, "ENT007", "state not in plan")
    if state not in NON_ENFORCING_CA_STATES:
        return None
    grant = resource.after.get("grant_controls") or []

    def _flatten(v):
        out = []
        for x in (v if isinstance(v, list) else [v]):
            out.extend(_flatten(x) if isinstance(x, list) else [x])
        return out

    controls = " ".join(str(c).lower() for c in _flatten(grant))
    if not any(k in controls for k in ("mfa", "block", "compliantdevice", "domainjoined")):
        return None
    label = "report-only" if state != "disabled" else "disabled"
    return Finding(
        rule_id="ENT007", severity=Severity.HIGH, resource=resource.address,
        title=f"Enforcing Conditional Access policy is {label}",
        detail=(
            f'state = "{state}". This policy applies a real control (MFA / block / device '
            "compliance) but is not enforcing, so it protects nothing while appearing "
            "configured. A tenant relying on it for MFA or legacy-auth blocking is exposed."
        ),
        remediation=(
            'If this is your enforcement policy, set state = "enabled". Keep report-only for '
            "genuine staging, but never leave the control the tenant depends on in it."
        ),
    )


def federated_identity_credential_broad_subject(resource: Resource) -> Finding | None:
    """ENT008 — a workload-identity federation credential whose subject is too broad."""
    if resource.type != "azuread_application_federated_identity_credential":
        return None
    subject = resource.after.get("subject")
    issuer = str(resource.after.get("issuer") or "")
    if subject is None:
        raise Unevaluable(resource.address, "ENT008", "subject not in plan")
    if "*" in subject:
        why = "the subject contains a wildcard, so any matching external identity can assume this app"
    elif GITHUB_ACTIONS_ISSUER in issuer and not any(
        m in subject for m in (":ref:", ":environment:", ":pull_request")
    ):
        why = ("the GitHub Actions subject is not pinned to a branch (:ref:), an environment "
               "(:environment:) or a pull_request, so any workflow in the repo can assume this app")
    else:
        return None
    return Finding(
        rule_id="ENT008", severity=Severity.HIGH, resource=resource.address,
        title="Federated identity credential has an over-broad subject",
        detail=(
            f"issuer '{issuer}', subject '{subject}' — {why}. This grants a token as the app "
            "with no client secret, so an over-broad subject is a keyless path to whatever the "
            "app can do."
        ),
        remediation=(
            "Pin the subject to the exact workload: for GitHub Actions, "
            "'repo:ORG/REPO:ref:refs/heads/main' or ':environment:production'. Never use a "
            "wildcard. One credential per trusted workload, scoped to that workload only."
        ),
    )


def permanent_privileged_directory_role(resource: Resource) -> Finding | None:
    """ENT009 — a privileged directory role assigned permanently (not PIM-eligible)."""
    if resource.type != "azuread_directory_role_assignment":
        return None
    role_id = resource.after.get("role_id")
    if role_id is None:
        raise Unevaluable(resource.address, "ENT009", "role_id not in plan")
    name = PRIVILEGED_DIRECTORY_ROLE_TEMPLATES.get(str(role_id))
    if name is None:
        if len(str(role_id)) == 36 and str(role_id).count("-") == 4:
            return None
        raise Unevaluable(resource.address, "ENT009",
                          f"role_id '{role_id}' is not a recognisable role template")
    return Finding(
        rule_id="ENT009", severity=Severity.HIGH, resource=resource.address,
        title=f"'{name}' assigned as a permanent directory role",
        detail=(
            f"Assigns {name} directly via azuread_directory_role_assignment — a standing, "
            "always-on grant of a tier-0 role. An attacker who compromises the assignee has it "
            "immediately, with no activation step and no time bound."
        ),
        remediation=(
            "Make privileged roles PIM-eligible rather than permanently active, so they must be "
            "activated (with MFA and a time limit) and every use is logged. Reserve any standing "
            "Global Administrator for a monitored break-glass account."
        ),
    )

ALL_RULES: list[Rule] = [
    entra_app_tier0_graph_permission,
    azure_role_assignment_privileged_broad_scope,
    conditional_access_mfa_scoped_by_risk,
    entra_app_password_no_expiry,
    azure_custom_role_wildcard_action,
    entra_role_assignable_group,
    conditional_access_enforcing_policy_disabled,
    federated_identity_credential_broad_subject,
    permanent_privileged_directory_role,
]
