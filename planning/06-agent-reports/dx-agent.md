# CLI/DX Draft

## User workflow

1. Export production data to a local snapshot outside the app runtime.
   ```bash
   pg_dump --format=plain --no-owner --no-privileges "$DATABASE_URL" > prod.sql
   ```
2. Scan the snapshot for likely PII and generate machine-readable evidence.
   ```bash
   pdp-mask scan prod.sql --format postgres-dump --out reports/prod.scan.json
   ```
3. Generate a reviewable masking plan from the scan report.
   ```bash
   pdp-mask plan reports/prod.scan.json --out mask.yml
   ```
4. Review and edit `mask.yml`: classify ambiguous fields, choose masking strategies, and mark safe columns as `keep`.
5. Apply the plan with a team-controlled salt to create safe local or staging data.
   ```bash
   PDP_MASK_SALT_FILE=.secrets/pdp-mask-salt \
     pdp-mask apply prod.sql --config mask.yml --out safe.sql
   ```
6. Verify the masked artifact before loading it anywhere.
   ```bash
   pdp-mask verify safe.sql --config mask.yml --source-report reports/prod.scan.json
   ```
7. Import only the verified artifact into local or staging databases.
   ```bash
   psql "$LOCAL_DATABASE_URL" < safe.sql
   ```

## Commands

### `pdp-mask scan`

Detects likely PII in PostgreSQL SQL dumps and CSV files. It does not modify input files.

```bash
pdp-mask scan prod.sql \
  --format postgres-dump \
  --sample-rows 500 \
  --preset indonesia \
  --out reports/prod.scan.json
```

CSV example:

```bash
pdp-mask scan exports/customers.csv \
  --format csv \
  --sample-rows 1000 \
  --out reports/customers.scan.json
```

Expected terminal output:

```text
pdp-mask scan prod.sql

Input        prod.sql
Format       postgres-dump
Preset       indonesia
Tables       18
Columns      214
Sample rows  up to 500 per table

Likely PII
  public.users.email             email        high    column+value
  public.users.phone             phone_id     high    column+value
  public.users.full_name         name         medium  column
  public.profiles.nik            nik          high    column+value
  public.orders.shipping_address address      medium  column

Needs review
  public.audit_logs.actor        unknown      low     value
  public.customers.external_ref  unknown      low     column

Next step
  pdp-mask plan reports/prod.scan.json --out mask.yml
```

Core flags:

- `--format postgres-dump|csv|auto`: input parser. `auto` detects by extension and content header.
- `--preset indonesia`: enables Indonesian PII detectors such as NIK, NPWP, local phone formats, address terms, and common Indonesian name fields.
- `--sample-rows N`: caps value inspection per table/file to keep scans predictable.
- `--out PATH`: writes JSON evidence for planning, review, and CI.
- `--fail-on likely-pii|unknown|none`: optional CI behavior during scanning.

### `pdp-mask plan`

Creates or updates a reviewable `mask.yml` from a scan report. It prefers explicit actions over hidden defaults.

```bash
pdp-mask plan reports/prod.scan.json \
  --out mask.yml \
  --default-action review \
  --keep-numeric-ids
```

Expected terminal output:

```text
pdp-mask plan reports/prod.scan.json

Created mask.yml

Planned actions
  mask   5 columns
  keep   42 columns
  review 2 columns

Review required
  public.audit_logs.actor
  public.customers.external_ref

Edit mask.yml, then run:
  pdp-mask apply prod.sql --config mask.yml --out safe.sql
```

Planning rules:

- Numeric primary and foreign keys default to `keep` for relational consistency.
- Columns with high-confidence PII detections default to `mask`.
- Low-confidence or conflicting detections default to `review` and block `apply` unless explicitly resolved.
- Existing user edits in `mask.yml` are preserved when regenerating the plan.

### `pdp-mask apply`

Applies deterministic masking to a SQL dump or CSV using `mask.yml`. It writes a new artifact and never overwrites the input unless `--in-place` is explicitly provided later; MVP should omit `--in-place`.

```bash
PDP_MASK_SALT='team-local-dev-2026' \
  pdp-mask apply prod.sql \
  --config mask.yml \
  --out safe.sql
```

Recommended salt file usage:

```bash
install -m 0600 /dev/null .secrets/pdp-mask-salt
printf '%s' 'replace-with-random-team-salt' > .secrets/pdp-mask-salt

PDP_MASK_SALT_FILE=.secrets/pdp-mask-salt \
  pdp-mask apply prod.sql --config mask.yml --out safe.sql
```

Expected terminal output:

```text
pdp-mask apply prod.sql

Config       mask.yml
Output       safe.sql
Salt source  PDP_MASK_SALT_FILE
Mode         deterministic

Applied
  public.users.email              email        12450 values
  public.users.phone              phone_id     11903 values
  public.users.full_name          name         12450 values
  public.profiles.nik             nik          8910 values
  public.orders.shipping_address  address      33102 values

Kept for joins
  public.users.id
  public.orders.user_id
  public.profiles.user_id

Wrote safe.sql
Next step: pdp-mask verify safe.sql --config mask.yml --source-report reports/prod.scan.json
```

Apply behavior:

- Deterministic values are derived from `(salt, pii_type, original_value)`.
- The same source email, phone, NIK, or natural-key PII receives the same masked value across tables.
- Empty strings and `NULL` remain unchanged.
- Numeric IDs are kept unless the config explicitly marks them for masking.
- Any `review` action blocks the run.

### `pdp-mask verify`

Checks that a masked artifact matches the plan and does not contain unresolved likely PII.

```bash
pdp-mask verify safe.sql \
  --config mask.yml \
  --source-report reports/prod.scan.json
```

Expected terminal output:

```text
pdp-mask verify safe.sql

Config       mask.yml
Source scan  reports/prod.scan.json
Artifact     safe.sql

Passed
  5 masked columns checked
  3 kept relationship columns checked
  0 unresolved review actions
  0 high-confidence PII leaks found

Safe to load into local/staging workflows.
```

Failure example:

```text
pdp-mask verify safe.sql

Failed
  public.users.email matched email pattern in 3 sampled rows
  mask.yml has unresolved review action: public.audit_logs.actor

Fix mask.yml or rerun apply, then verify again.
```

CI example:

```bash
pdp-mask scan prod.sql --out reports/prod.scan.json --fail-on unknown
pdp-mask verify safe.sql --config mask.yml --source-report reports/prod.scan.json
```

## `mask.yml` example

```yaml
version: 1
preset: indonesia
source:
  format: postgres-dump
  path: prod.sql
salt:
  required: true
  env: PDP_MASK_SALT
  env_file: PDP_MASK_SALT_FILE
defaults:
  unknown_action: review
  keep_numeric_ids: true
  deterministic: true
outputs:
  report_json: reports/prod.apply.json

tables:
  public.users:
    primary_key: id
    columns:
      id:
        action: keep
        reason: numeric primary key used by foreign keys
      email:
        action: mask
        type: email
        strategy: deterministic_email
        domain: example.invalid
      phone:
        action: mask
        type: phone_id
        strategy: deterministic_phone
        country: ID
      full_name:
        action: mask
        type: name
        strategy: deterministic_name
      created_at:
        action: keep
        reason: operational timestamp, not directly identifying in this dataset

  public.profiles:
    primary_key: id
    columns:
      id:
        action: keep
      user_id:
        action: keep
        references: public.users.id
      nik:
        action: mask
        type: nik
        strategy: deterministic_digits
        preserve_length: true
      npwp:
        action: mask
        type: npwp
        strategy: deterministic_digits
        preserve_format: true
      birth_date:
        action: mask
        type: date_of_birth
        strategy: date_shift
        max_days: 45

  public.orders:
    primary_key: id
    columns:
      id:
        action: keep
      user_id:
        action: keep
        references: public.users.id
      shipping_address:
        action: mask
        type: address
        strategy: deterministic_address
      total_amount:
        action: keep
        reason: non-PII business metric

  public.audit_logs:
    columns:
      actor:
        action: review
        detected_as: unknown
        evidence: value matched name-like tokens in sampled rows
```

Config ergonomics:

- One file controls scan decisions, apply behavior, and verification expectations.
- `action` is always one of `keep`, `mask`, `drop`, or `review`.
- `review` is intentionally blocking for `apply` and `verify`.
- `reason` is optional for generated entries but recommended for manual `keep` decisions.
- Table and column paths use database names exactly as found in dumps: `schema.table.column`.
- Secrets are not stored in `mask.yml`; salt comes from an environment variable or file path.
- Regenerating with `pdp-mask plan existing.scan.json --out mask.yml` should add newly detected columns without replacing reviewed decisions.

## Exit codes

| Code | Meaning | Typical command |
| ---: | --- | --- |
| 0 | Success; requested operation completed and policy passed. | all |
| 1 | Runtime or IO error, such as unreadable input or unwritable output. | all |
| 2 | Invalid CLI arguments or invalid `mask.yml` schema. | all |
| 3 | Likely PII or unknown fields found when the selected policy requires failure. | `scan`, `verify` |
| 4 | Plan contains unresolved `review` actions. | `apply`, `verify` |
| 5 | Masking verification failed because sampled output still matches configured PII detectors. | `verify` |
| 6 | Salt missing, empty, or not readable. | `apply` |

## Production dump to safe data: concrete path

```bash
# 1. Keep the raw dump local and short-lived.
pg_dump --format=plain --no-owner --no-privileges "$PROD_DATABASE_URL" > prod.sql

# 2. Detect likely PII.
pdp-mask scan prod.sql --format postgres-dump --preset indonesia --out reports/prod.scan.json

# 3. Generate the first plan.
pdp-mask plan reports/prod.scan.json --out mask.yml --keep-numeric-ids

# 4. Human review: edit mask.yml until no action: review remains.

# 5. Apply with deterministic salt.
PDP_MASK_SALT_FILE=.secrets/pdp-mask-salt \
  pdp-mask apply prod.sql --config mask.yml --out safe.sql

# 6. Verify before import.
pdp-mask verify safe.sql --config mask.yml --source-report reports/prod.scan.json

# 7. Load only the masked dump.
createdb pdp_mask_local
psql postgres://localhost/pdp_mask_local < safe.sql

# 8. Remove the raw dump after successful import if team policy allows it.
rm prod.sql
```

The DX should make the safe path shorter than the unsafe path: scan produces evidence, plan creates a reviewable config, apply refuses unresolved decisions, and verify gives CI a stable pass/fail contract.
