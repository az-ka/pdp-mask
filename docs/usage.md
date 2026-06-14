# Usage Guide

This guide walks through a complete `pdp-mask` workflow, from a raw
production CSV to a verified, masked output safe to share with developers.

## Prerequisites

- Go 1.26+ (matches `go.mod`)
- A salt, generated once per project: `openssl rand -hex 32`
- The salt stored in a vault, accessible only to operators

## Workflow overview

```
prod.csv  ──scan──▶  scan.json  ──plan──▶  mask.yml
                                                    │
                                                    ▼
prod.csv  ──apply──▶  safe.csv  ◀── mask.yml + salt
   │
   └────verify──▶  PASS / FAIL  ◀── safe.csv + mask.yml
```

Each step is a separate command. Operators can pause between steps to
review the scan and plan before applying.

## Step 1: Scan

Identify columns that may contain PII.

```bash
go run ./cmd/pdp-mask scan data/prod.csv --json reports/scan.json
```

The scan report lists each column with its likely PII type, confidence
score, and the detector rule that fired. No raw values are included.

Example output:

```text
Likely PII
  customers.email  email     high  column_name:email+value_pattern:email
  customers.no_hp  phone_id  high  column_name:phone+value_pattern:phone_id
  customers.nik    nik       high  column_name:nik+value_pattern:nik
```

## Step 2: Plan

Convert the scan report into a masking plan.

```bash
go run ./cmd/pdp-mask plan reports/scan.json --out reports/mask.yml
```

The plan is a YAML file that specifies, for each column, which masking
strategy to apply. Operators review and edit this file before applying.

## Step 3: Apply

Mask the CSV using the plan and a salt.

```bash
PDP_MASK_SALT=$(cat /path/to/salt.txt) \
  go run ./cmd/pdp-mask apply data/prod.csv \
    --config reports/mask.yml \
    --out data/safe.csv
```

The salt is read from the `PDP_MASK_SALT` environment variable, or from
a salt file with `--salt-file`. The salt **must not** appear in shell
history. Use a file or a vault-injected env var.

The output `safe.csv` is written with mode `0600` (owner read/write only).
`pdp-mask` will refuse to read salt files with group/other bits set.

## Step 4: Verify

Confirm that the masked output has no PII leakage.

```bash
go run ./cmd/pdp-mask verify data/prod.csv \
  --config reports/mask.yml \
  --out data/safe.csv
```

The verifier checks:

- Every column flagged in the plan was masked in the output.
- The masked values do not match the original PII patterns (e.g., a
  masked email does not look like a real email address).
- No column was missed or skipped.

Exit code 0 on success, non-zero on any leakage or mismatch.

## Common workflows

### Mask a new dataset for a developer

```bash
# Operator side
go run ./cmd/pdp-mask scan data/prod.csv --json /tmp/scan.json
go run ./cmd/pdp-mask plan /tmp/scan.json --out /tmp/mask.yml
# Review /tmp/mask.yml, edit if needed
PDP_MASK_SALT=$(cat /vault/salt.txt) \
  go run ./cmd/pdp-mask apply data/prod.csv \
    --config /tmp/mask.yml \
    --out /tmp/safe.csv
# Hand off /tmp/safe.csv to developer (via secure channel)
```

### Re-mask after salt rotation

```bash
# Generate new salt
NEW_SALT=$(openssl rand -hex 32)
# Re-apply plan with new salt
PDP_MASK_SALT=$NEW_SALT \
  go run ./cmd/pdp-mask apply data/prod.csv \
    --config reports/mask.yml \
    --out data/safe.csv
# Update vault with new salt; remove old salt at rotation date
```

### Verify a previously masked file

```bash
# This requires the original input file and the salt
go run ./cmd/pdp-mask verify data/prod.csv \
  --config reports/mask.yml \
  --out data/safe.csv
# Same salt used during apply must be available
```

## Custom rule packs

`pdp-mask` supports data-driven rule packs. Add a custom pack:

```bash
go run ./cmd/pdp-mask scan data/prod.csv --rules custom_rules.yml
```

The rule pack format is documented in `CONTRIBUTING.md`.

## Salt file format

A salt file is a UTF-8 text file containing the salt as a single line.
Hex format (64 characters) is conventional:

```text
a3f8c2e1d4b5...
```

File mode must be `0600` (or `0400` for read-only). `pdp-mask` will
refuse to read a salt file with group/other bits set, on POSIX systems.

## Limitations

- **CSV only.** SQL dumps, JSON, Parquet, and other formats are not
  supported. Convert input data to CSV first.
- **Deterministic, not anonymous.** A user with the salt + a guessed
  original can compute the masked output. See `SECURITY.md` for the
  full threat model.
- **No incremental re-masking.** If you add rows to a CSV after
  applying, you must re-mask the entire file.
- **No streaming.** Input is loaded into memory. The 1 GiB cap
  prevents OOM on large files; for files larger than 1 GiB, split
  them upstream.
