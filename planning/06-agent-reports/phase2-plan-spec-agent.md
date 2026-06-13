# Phase 2 PlanSpecAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- `pdp-mask plan <scan.json> --out mask.yml` must generate a stable v1 plan from scan JSON.
- Do not include raw samples or raw PII in `mask.yml`.
- High-confidence findings become `mask`.
- Medium-confidence findings become `review`.
- Numeric ID columns are kept by default when they are not emitted as findings.
- Multiple findings for one column should collapse to one column decision, preferring the safest decision.
- Plan output should be deterministic and diffable.

## Adopted minimal schema

```yaml
version: 1
source:
  scan: reports/customers.scan.json
  scan_sha256: <hex>
inputs:
  - path: testdata/customers_pii.csv
    format: csv
    table: customers_pii
    columns:
      email:
        action: mask
        type: email
        strategy: deterministic_email
        confidence: high
        evidence:
          - column_name:email
          - value_pattern:email
      nama_lengkap:
        action: review
        type: name
        strategy: deterministic_name
        confidence: medium
        evidence:
          - column_name:name
summary:
  inputs: 1
  findings: 7
  actions:
    mask: 6
    review: 1
```

## Deferred

- Full column coverage for non-findings.
- Policy override files.
- `drop` action.
- Multi-input merge semantics beyond preserving each input entry.
