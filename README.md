# pdp-mask

Local-first CLI for scanning SQL/CSV snapshots for likely Indonesian PII before data is used in local, staging, demo, CI, or vendor workflows.

Phase 1 currently supports CSV scanning only.

## Usage

```bash
go run ./cmd/pdp-mask scan testdata/customers_pii.csv --json reports/customers.scan.json
```

Example output:

```txt
Likely PII
  customers_pii.email  email     high  column_name:email+value_pattern:email
  customers_pii.no_hp  phone_id  high  column_name:phone+value_pattern:phone_id
```

## Current detectors

- Email
- Indonesian phone numbers
- NIK-like values
- NPWP-like values
- Indonesian name/address/date-of-birth column heuristics
- Operational numeric ID false-positive guardrails

Default reports do not include raw sampled values.
