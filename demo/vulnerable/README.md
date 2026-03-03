# VXPwngard Demo Vulnerable Workflows

> **WARNING:** These workflows are intentionally vulnerable for demonstration purposes.
> Do NOT use these in production repositories.

## Scenarios

### ci-vulnerable.yml -- Fork Checkout Kill Chain
Replicates the CI/CD configuration pattern exploited by autonomous AI agents in
documented pipeline compromises. The workflow uses `pull_request_target` with fork
checkout, enabling arbitrary code execution in a privileged context with write
permissions and secret access.

### comment-trigger.yml -- Microsoft/Akri Pattern
Demonstrates the `issue_comment` trigger vulnerability pattern seen in Microsoft's
Akri project and similar repositories. Any user can trigger deployment by posting
a comment, with no authorization check. Branch name injection and curl-pipe-bash
patterns compound the risk.

### ai-config-attack.yml -- AI Config Injection (CLAUDE.md Attack)
Demonstrates the novel attack vector where AI configuration files (CLAUDE.md,
.mcp.json) are modified in a fork PR to hijack AI code review agents. This is
a VXPwngard-exclusive detection not found in other CI/CD scanners.

## Usage

```bash
vxpwngard demo                          # Run all demo scenarios
vxpwngard demo --scenario fork-checkout # Run specific scenario
vxpwngard scan demo/vulnerable/         # Scan demo files directly
```
