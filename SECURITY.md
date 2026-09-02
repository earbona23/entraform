# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/earbona23/entraform/security/advisories/new).
Please do not open a public issue for a vulnerability. Acknowledgement within 72 hours,
assessment within seven days, and credit in the advisory unless you ask otherwise.

## The threat model, because it is unusual

entraform runs inside **your** CI, against **your** infrastructure plan. The plan file it
reads is untrusted input — it may describe a hostile or malformed tenant. So the properties
that matter are what it structurally cannot do:

| Property | Why it matters | How it holds |
|---|---|---|
| **It never executes anything** | The input is a data file, and it must stay data | No `eval`, `exec`, `subprocess`, `pickle`, or dynamic import exists in `src/` |
| **It never reaches the network** | A linter that phones home leaks your infrastructure shape | There is no HTTP client in the package; it reads a file and exits |
| **It never writes to your infrastructure** | It reviews a plan, it does not apply one | It has no Azure/Graph client and no credentials of any kind |
| **Zero runtime dependencies** | Running in your CI, it must not drag a dependency tree into that boundary | `dependencies = []`; every import is standard library |
| **Malformed input fails cleanly** | A crafted plan must not crash the build ambiguously | Bad input exits `2` with a message; it is fuzzed against null/empty/garbage plans |

In scope: any path that executes plan content, opens a socket, writes outside its own output,
hangs on a crafted plan, or reports a real misconfiguration as clean (a false negative in a
security check is a vulnerability here). Out of scope: a finding you would tune differently —
open a normal issue.
