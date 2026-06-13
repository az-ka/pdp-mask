# pdp-mask

Local-first CLI for scanning SQL/CSV snapshots for likely Indonesian PII before data is used in local, staging, demo, CI, or vendor workflows.

Current MVP supports CSV scan reports, plan generation, and deterministic CSV masking.

## Usage

```bash
go run ./cmd/pdp-mask scan testdata/customers_pii.csv --json reports/customers.scan.json
go run ./cmd/pdp-mask plan reports/customers.scan.json --out reports/mask.yml

# Resolve review entries in reports/mask.yml, then apply with a salt.
PDP_MASK_SALT=0123456789abcdef go run ./cmd/pdp-mask apply testdata/customers_pii.csv --config reports/mask.yml --out reports/customers.safe.csv
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

Default reports, generated plans, and apply summaries do not include raw sampled values.
