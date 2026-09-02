# Plan de promoción de entraform — arranca cuando Sponsors esté aprobado

Objetivo: conseguir **usuarios reales** (gente que lo mete en su CI), no estrellas vacías.
El patrocinio sigue a la dependencia: primero usuarios, después sponsors. Todo lo publica
Eduard, con su voz, respondiendo comentarios. Nada automatizado, nada de comprar métricas.

## Secuencia (una cosa por vez, no todo el mismo día)

**Semana 1 — el círculo cálido (ya te conocen):**
1. **Comunidad de Maester (Discord)** — borrador #2 de `LANZAMIENTO-borradores.md`. Es tu
   entrada más natural: ya contribuiste ahí. Público exacto.
2. **r/AzureSecurity** — borrador #1. Pedís feedback, no anunciás. Respondé cada comentario técnico.
3. **LinkedIn** — borrador #4, tono profesional. Etiquetá la tecnología (#EntraID #Terraform #DevSecOps).

**Semana 2 — ampliar, si la semana 1 tuvo tracción:**
4. **r/entra, r/AzureDevOps, r/Terraform** — variando el texto, nunca copiar-pegar el mismo.
5. **entra.news / newsletters de seguridad de identidad** — mandarles la herramienta a que la prueben.
6. **dev.to / un blog corto** — "Why I built an identity linter for Terraform" con un ejemplo real.

**Cuando tenga tracción (estrellas reales + issues de usuarios):**
7. **Show HN** — borrador #3. UNA sola bala. Publicá martes-jueves 14-16h UTC. Primer comentario
   listo. No se repite un lanzamiento flojo.
8. **Awesome-lists** (PR honesto, cumpliendo sus reglas): `awesome-terraform`, `awesome-azure-security`,
   `awesome-opensource-security`. Solo si la herramienta ya está pulida — un mantenedor rechaza
   proyectos flojos y eso quema.

## Qué NO hacer (protege el nombre — la credencial profesional)
- Comprar estrellas/seguidores → GitHub lo detecta, arruina la credencial.
- Mismo texto en 5 subreddits el mismo día → ES spam, te banean.
- Publicar y desaparecer → el valor está en responder. Ahí te ven los que contratan.
- Show HN antes de tener sustancia → quemás la única bala.

## Métrica honesta de éxito (para no engañarnos)
- **Real:** issues de usuarios reales, forks que se usan, alguien que lo mete en su CI y lo comenta.
- **Vanidad (ignorar):** número de estrellas por sí solo. 8 de los 10 repos más estrellados de
  GitHub son listas de links, no software.

## El puente a ingresos
Cada usuario de entraform es un cliente potencial de la **evaluación de M365** (paquete en
`~/proyectos/arrankago-consulting/`). El pitch: "usás entraform en tu CI — ¿querés que audite
tu tenant vivo con la misma metodología?" La herramienta gratis vende el servicio pago.
