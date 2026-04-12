# Sample Reports

These HTML reports are generated from synthetic data — no real cluster is needed.

They demonstrate the auditor-ready evidence narrative layer that Varax produces, including:

- **Control implementation narratives** — grammatically correct prose per SOC2 control, built from scan data
- **Evidence integrity verification** — SHA256 hashes and capture timestamps on every evidence artifact
- **Auditor verification commands** — kubectl one-liners to independently confirm reported findings
- **Control-specific evidence** — fine-grained evidence artifacts per control (no duplication)
- **Scope & limitations declaration** — in-scope vs out-of-scope controls
- **Assessment period** — date range and scan count from historical data
- **Structured remediation** — check-level remediation with dry-run commands

## Files

| File | Description |
|------|-------------|
| `readiness-report.html` | Full SOC2 readiness assessment with narratives, evidence integrity, and verification commands |
| `executive-report.html` | Executive summary with compliance score and trend |
| `evidence-CC6.1.html` | Per-control evidence detail for CC6.1 (Logical Access Controls) |
| `readiness-report.json` | JSON export of the readiness assessment data |

## Regenerate

```bash
make examples
```

Or directly:

```bash
go run examples/generate.go
```

The generator uses synthetic data representing a realistic EKS cluster at ~78% compliance with 93 checks across CIS, NSA-CISA, PSS, RBAC, Workload Hygiene, Supply Chain, and Namespace Governance benchmarks.
