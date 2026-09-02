# Using entraform in GitHub Actions

Add this to `.github/workflows/entraform.yml`. It plans your Terraform, lints the plan for
identity misconfigurations, and — because it uploads SARIF — shows every finding **inline on
the pull request** and in the repository's **Security tab**, not buried in a log.

```yaml
name: entraform
on:
  pull_request:
    paths: ["**.tf"]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning

jobs:
  identity-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
      - run: terraform plan -out plan.tfplan
      - run: terraform show -json plan.tfplan > plan.json

      - name: Lint identity config
        uses: earbona23/entraform@v1
        with:
          plan: plan.json
          fail-on: high        # critical | high | medium | low

      - name: Upload results to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: entraform.sarif
```

That's the whole integration. A pull request that introduces an over-privileged app
registration or a fail-open MFA policy now gets a red check and an annotation on the exact
resource, before anyone applies it.

## Without the Action (any CI, or locally)

```bash
pip install "entraform @ git+https://github.com/earbona23/entraform"
terraform show -json plan.tfplan | entraform -            # human output
terraform show -json plan.tfplan | entraform - -f sarif > entraform.sarif
```

`entraform` exits `1` when it finds an issue at or above `--fail-on`, `0` when clean, and
`2` on bad input — so it gates a pipeline in any CI system, not just GitHub.
