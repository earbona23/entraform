# Borradores para publicar entraform — los envía Eduard, no un bot

Cada uno es para una comunidad distinta. Publicá de a uno, no todos el mismo día, y respondé
los comentarios vos mismo (ahí se gana la confianza). Nunca pegar el mismo texto en varios lados.

---

## 1) r/AzureSecurity  (o r/entra) — el más cálido para empezar

**Título:** I built an identity-focused Terraform linter — catches over-privileged Entra apps and fail-open Conditional Access before apply

**Cuerpo:**
> checkov and tfsec are great but thin on identity, which is where most Azure tenants
> actually get owned. So I wrote a small linter that reads a `terraform show -json` plan and
> flags the identity escalation paths specifically: app registrations requesting
> directory-takeover Graph permissions, Owner at subscription scope, MFA Conditional Access
> policies scoped to risk levels only (the same fail-open shape CISA's ScubaGear flags for
> MS.AAD.3.x), non-expiring client secrets, wildcard custom roles.
>
> It runs in CI, emits SARIF so findings show up on the PR and in the Security tab, and has
> zero runtime dependencies (it runs against your infra plan, so I didn't want it pulling a
> dependency tree into that trust boundary). MIT, and it's honest about what it can't do —
> it reads the plan, not the live tenant.
>
> Would genuinely like feedback on the rule set and what identity misconfigs you'd want it
> to catch next. github.com/earbona23/entraform

*(Regla de oro de Reddit: no es un anuncio, es pedir feedback. Respondé cada comentario técnico.)*

---

## 2) Comunidad de Maester (Discord) — ya te conocen ahí

> Following up on my PR the other day — I published a small side project you all might find
> useful: **entraform**, a Terraform plan linter focused purely on Entra/Azure identity
> misconfig (over-privileged app perms, fail-open CA, subscription-scope Owner). Different
> layer from Maester — Maester checks the live tenant, this catches it in the plan before it
> ever ships. Would love eyes from people who live in this stuff. github.com/earbona23/entraform

---

## 3) Show HN (Hacker News) — SOLO cuando tenga 2-3 reglas más y algún usuario real

**Título:** Show HN: entraform – an identity-focused security linter for Terraform (Entra/Azure)

**Primer comentario (vos, apenas se publique):**
> Author here. I kept seeing Azure tenants get compromised through identity —
> over-permissioned app registrations, Conditional Access policies that look like MFA and
> aren't — and the generic IaC scanners are broad and thin on exactly that. entraform reads
> the plan and flags those paths before apply. Zero deps, SARIF, MIT. It's alpha and honest
> about its limits (reads the plan, not the live tenant). Happy to answer anything.

*(HN es una sola bala: publicá cuando el repo tenga más sustancia. Un lanzamiento flojo no se repite.)*

---

## 4) LinkedIn / X — opcional, tono profesional

> Published entraform: a small open-source linter that catches Microsoft Entra ID and Azure
> identity misconfigurations in your Terraform plan — over-privileged app permissions,
> fail-open Conditional Access, subscription-scope Owner — before they reach the tenant.
> Runs in CI, SARIF output, zero dependencies, MIT. github.com/earbona23/entraform

---

## Qué NO hacer (te protege el nombre)
- No comprar estrellas ni seguidores. GitHub lo detecta y arruina la credencial.
- No pegar el mismo texto en 5 subreddits el mismo día (eso ES spam).
- No publicar y desaparecer: el valor está en responder los comentarios técnicos, ahí te ven.
