# entraform

[![CI](https://github.com/earbona23/entraform/actions/workflows/ci.yml/badge.svg)](https://github.com/earbona23/entraform/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB)](https://www.python.org/downloads/)
[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-blue.svg)](LICENSE)
[![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20deps-0-2f855a)](#zero-dependencies-is-the-point)
[![Linux · macOS · Windows](https://img.shields.io/badge/Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-CI--tested-4c1)](https://github.com/earbona23/entraform/actions/workflows/ci.yml)

**An identity-aware security linter for Terraform.** It reads your `terraform plan`, finds
the identity misconfigurations that generic IaC scanners walk past — over-privileged Entra
app permissions, dangerous Azure role assignments, fail-open Conditional Access — and fails
the build **before** any of it reaches your tenant.

```console
$ terraform show -json plan.tfplan | entraform -
```
```
entraform found 3 issue(s) in 4 resources:

 CRITICAL  ENT001  azuread_application.reporting
    App registration requests a directory-takeover Graph permission
    Requests Application.ReadWrite.All. A service principal holding it can grant itself
    further roles or credentials and escalate to Global Administrator.
    fix: Remove the tier-0 permission, or replace it with the narrowest role that does the job.

 HIGH  ENT004  azuread_conditional_access_policy.mfa
    MFA Conditional Access policy is scoped to risk levels only
    Requires MFA but is narrowed by sign_in_risk_levels, so it does not apply to ordinary
    sign-ins — the tenant looks MFA-covered while most authentications are exempt.
    fix: Remove the risk-level scoping so the baseline policy targets all users.
```

## Why this exists

`checkov`, `tfsec` and `kics` are broad cloud-security scanners, and they are good at what
they cover. But **identity is where cloud gets owned** — a phished account, an
over-permissioned app registration, a Conditional Access policy that looks like MFA and
isn't — and identity is exactly the thin spot in the generalist tools. `entraform` does one
thing: it reads the Entra ID and Azure identity resources in your plan the way an attacker
reads them, and tells you where the escalation paths are while they are still a diff you can
reject.

It runs in the same place your plan does — CI, pre-commit — so the check happens before
apply, not in an audit six months later.

## What it catches today

| Rule | Severity | What it flags |
|---|:---:|---|
| **ENT001** | critical | An `azuread_application` requesting a directory-takeover Graph **application** permission (`RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Directory.ReadWrite.All`, `Group.ReadWrite.All`). Owning such an app is a path to Global Administrator. |
| **ENT002** | high | `Owner` / `User Access Administrator` / `Contributor` granted at **subscription or management-group** scope, where it becomes tenant-wide lateral movement. |
| **ENT004** | high | An MFA Conditional Access policy **scoped to risk levels only**, so it doesn't cover ordinary sign-ins — the same fail-open shape CISA's ScubaGear flags for MS.AAD.3.x. |
| **ENT003** | medium | An `azuread_application_password` (client secret) with **no expiry** set. |
| **ENT005** | high | A custom `azurerm_role_definition` granting the wildcard action `"*"` — Owner in disguise. |
| **ENT006** | high | A group created **role-assignable** (`assignable_to_role = true`) — a tier-0 object anyone who manages its membership can weaponise. |
| **ENT007** | high | A Conditional Access policy that enforces MFA / blocks legacy auth but is **disabled or report-only** — protection that protects nothing. |
| **ENT008** | high | A **workload-identity federation** credential with an over-broad subject (a wildcard, or an unpinned GitHub Actions subject) — a keyless path into the tenant. |
| **ENT009** | high | A **privileged directory role** (Global Administrator, Privileged Role Administrator, …) assigned **permanently** rather than PIM-eligible. |

Each finding names the resource, explains the attack path in a sentence, and gives the
specific fix. Rules are grounded in real escalation paths, not style preferences.

## Three outcomes, never two

Every rule returns one of three things: a **finding**, **nothing** (the resource is fine),
or **unevaluable** — the rule needed a field the plan did not contain and says so. An
unevaluable resource is reported as *review-needed*, never folded silently into "clean":

```
1 resource(s) could not be evaluated (review needed, not a pass):
    ENT001  azuread_application.opaque: required_resource_access not in plan
```

A linter that cannot tell "clean" from "could not look" lies on the day it matters. This one
is built so it can't.

## Drop it into GitHub Actions (2 minutes)

```yaml
# .github/workflows/entraform.yml
permissions:
  contents: read
  security-events: write

# ...after terraform plan -out plan.tfplan && terraform show -json plan.tfplan > plan.json
- uses: earbona23/entraform@v1
  with:
    plan: plan.json
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: entraform.sarif
```

Because it emits **SARIF**, findings land as annotations on the pull request and in your
repository's **Security tab** — on the exact resource, before apply — not buried in a log.
Full workflow: [docs/github-action.md](docs/github-action.md).

## Install and use in CI

```console
$ pip install entraform            # (not on PyPI yet — pip install -e . from a checkout)
```

```yaml
# GitHub Actions
- run: |
    terraform plan -out plan.tfplan
    terraform show -json plan.tfplan | entraform -
```

Exit codes, because it lives in a pipeline:

| code | meaning |
|---|---|
| `0` | no findings at or above the fail threshold |
| `1` | findings that meet `--fail-on` (default: `high`) |
| `2` | could not read the plan |

Flags: `--fail-on {critical,high,medium,low}`, `--format {text,json,sarif}`, `--strict` (also fail
on unevaluable resources), `--no-color`.

## Zero dependencies is the point

`dependencies = []`. Everything is standard library. This runs inside **your** CI against
**your** infrastructure plan — the last thing it should do is pull a dependency tree into
that trust boundary. It parses the documented `terraform show -json` contract with the JSON
parser Python already ships, and nothing else. It never reaches the network and never
touches your tenant — it reads a plan file and exits.

## Limitations — read these before you trust it

This is **v0.1 (alpha)**, and it is deliberately honest about its edges:

- **It reads the plan, not the tenant.** It judges what Terraform *will* apply. Drift, or
  anything configured outside Terraform, is invisible to it — for the live tenant, use
  something like [Maester](https://github.com/maester365/maester) or
  [ScubaGear](https://github.com/cisagov/ScubaGear).
- **Nine rules today.** It covers a small set of high-value identity misconfigurations, not
  the whole Azure/Entra surface. It is not a replacement for `checkov`/`tfsec` on the broad
  cloud-security checks — run it *alongside* them.
- **Values must be known at plan time.** A permission id or scope that is a computed value
  (`(known after apply)`) cannot be judged, and is reported as unevaluable rather than
  guessed.
- **`azuread` / `azurerm` provider shapes only.** It does not read AzAPI or ARM/Bicep yet.
- **It reasons about the plan, not runtime behaviour.** It flags an over-privileged app; it
  cannot tell you whether that app is actually reachable by an attacker — that is what
  [BloodHound](https://github.com/SpecterOps/BloodHound) is for.

A linter that oversells its coverage gets switched off in CI the first time it is wrong.
This one would rather tell you what it did not check.

## Development

```console
$ pip install -e ".[dev]"
$ pytest
```

CI runs the suite on Ubuntu, Windows and macOS across Python 3.11–3.13, and dogfoods the
demo plan (`examples/demo-plan.json`) — the tool must flag its own example and exit 1, or
the build fails.

Every rule's tests are load-bearing: each was checked by breaking the rule and confirming a
specific test dies. A rule that fires on everything, or on nothing, does not pass this suite.

## Sponsor

entraform is MIT and free forever. If it catches a bad identity change before it
ships, or earns a place in your pipeline, sponsoring keeps it maintained: bug fixes,
keeping the Graph-permission and Conditional Access rules current as Entra changes,
and testing against new provider shapes.

- **[Sponsor on GitHub](https://github.com/sponsors/earbona23)** — any amount.

## More tools like this

Part of a small suite of dependency-free security tools I maintain. Each one runs
offline, ships its own tests, and maps its detections to MITRE ATT&CK.

- **[vantage](https://github.com/earbona23/vantage)** — see your domain's external attack surface the way an attacker's first recon does, scored and explained.
- **[revtriage](https://github.com/earbona23/revtriage)** — offline malware triage: an explainable score and a STIX bundle from a suspicious file.
- **[entra-tripwire](https://github.com/earbona23/entra-tripwire)** — decoy identities in Entra ID that fire the moment someone touches them.
- **[containment-cut](https://github.com/earbona23/containment-cut)** — the minimum-cost set of actions that provably severs a compromised identity, with a proof.

## Licence

[MIT](LICENSE). Runs read-only against a plan file. Point it only at infrastructure you are
authorised to review.
