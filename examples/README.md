# Sample Reports

These HTML reports are generated from synthetic data — no real cluster is needed.

They demonstrate the readiness assessment, executive summary, and per-control evidence detail pages that Varax produces, including the shared responsibility section for managed Kubernetes.

## Files

| File | Description |
|------|-------------|
| `readiness-report.html` | Full SOC2 readiness assessment with shared responsibility section |
| `executive-report.html` | Executive summary with compliance score and trend |
| `evidence-CC6.1.html` | Per-control evidence detail for CC6.1 (Logical Access Controls) |

## Regenerate

```bash
make examples
```

Or directly:

```bash
go run examples/generate.go
```

The generator uses synthetic data representing a realistic EKS cluster at 78% compliance with a mix of passing, failing, and provider-managed checks.
