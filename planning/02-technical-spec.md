# pdp-mask Technical Spec

## Principles

- File/snapshot first; no production database writes in MVP.
- Offline by default; no network calls.
- Rule-based deterministic detection; AI is non-MVP and local-only if added later.
- Keep numeric IDs by default.
- Mask PII deterministically using a user-provided salt.
- Preserve repeated natural-key PII across tables/files.
- Never print raw sensitive values in default output.

## Supported MVP inputs

### PostgreSQL-style SQL dump

Target common `pg_dump --format=plain` shapes:

- `CREATE TABLE` for schema extraction.
- `COPY schema.table (col1, col2, ...) FROM stdin;` data blocks.
- Pass through non-data SQL sections unless required for metadata.

`INSERT INTO ... VALUES ...` can come after the COPY path is stable.

### CSV

- RFC 4180-style CSV.
- Header row required by default.
- Configurable delimiter, quote, escape, null marker, and encoding.
- Stream records and track row/column diagnostics.

## Pipeline

1. Open input and detect explicit/auto format.
2. Extract structure: tables, columns, COPY blocks, CSV headers.
3. Sample bounded non-null values per column.
4. Run detector rules.
5. Produce terminal + JSON report.
6. Generate or update `mask.yml`.
7. Apply masking by streaming input to output.
8. Verify output shape and unresolved PII policy.

## Detector rules

### Column normalization

- Lowercase.
- Split snake_case, camelCase, kebab-case, spaces.
- Keep original column names for output.

### Column-name signals

- `nik`: `nik`, `no_ktp`, `nomor_ktp`, `ktp`, `identity_number`.
- `npwp`: `npwp`, `no_npwp`, `nomor_npwp`, `tax_id`.
- `name`: `nama`, `nama_lengkap`, `full_name`, `first_name`, `last_name`, `customer_name`, `pemilik`, `ibu_kandung`.
- `email`: `email`, `email_address`, `alamat_email`.
- `phone`: `phone`, `no_hp`, `nomor_hp`, `telepon`, `telp`, `wa`, `whatsapp`, `mobile`.
- `address`: `alamat`, `address`, `jalan`, `kelurahan`, `kecamatan`, `kota`, `kabupaten`, `provinsi`, `kode_pos`.
- `date_of_birth`: `tanggal_lahir`, `tgl_lahir`, `birth_date`, `dob`.
- `bank_account`: `rekening`, `no_rekening`, `nomor_rekening`, `bank_account`, `account_number` with context.

Negative signals:

- `id`, `*_id`, `count`, `total`, `amount`, `qty`, `status`, `type`, `created_at`, `updated_at` are not PII by name alone.
- Integer primary/foreign keys default to `keep`.

### Value-pattern signals

- Email: standard email shape with valid-looking domain.
- Indonesian phone: `08...`, `628...`, `+628...`, plausible length after stripping separators.
- NIK: 16 digits; reject repeated digits/counters; later add region/date plausibility.
- NPWP: punctuation-tolerant legacy/new numeric shapes; reject repeated digits.
- DOB: date-like values only strong with birth context.
- Postal code: 5 digits, weak alone, stronger with address context.
- Address: `jl`, `jalan`, `gg`, `rt`, `rw`, `kel`, `kec`, `kab`, `kota`, `provinsi`.
- Name: weak by value alone; stronger with column context.

Each rule emits category, score contribution, evidence label, sampled count, matched count, and match ratio.

## Confidence scoring

Score range: `0.0..1.0`.

Suggested weights:

- Strong column match: `+0.45..0.65`.
- Weak column match: `+0.15..0.35`.
- Strong value match with high ratio: `+0.45..0.70`.
- Medium value match: `+0.20..0.40`.
- Context boost: `+0.05..0.15`.
- Operational ID penalty: `-0.40..0.70`.
- Low sample count caps confidence unless column evidence is strong.

Bands:

- `high >= 0.80`: recommend `mask`.
- `medium >= 0.50`: recommend `review`.
- `low < 0.50`: recommend `keep` or `ignore`.

## `mask.yml` schema

```yaml
version: 1
preset: indonesia
salt_ref: env:PDP_MASK_SALT
inputs:
  - id: prod_dump
    type: postgres_dump
    path: prod.sql
    output: safe.sql
rules:
  - target:
      input: prod_dump
      table: public.users
      column: email
    category: email
    action: mask
    method: deterministic_email
    consistency_key: global:email
    confidence: high
    evidence:
      - column_name:email
      - value_pattern:email
  - target:
      input: prod_dump
      table: public.users
      column: id
    action: keep
    reason: numeric_primary_key
```

Required concepts:

- `version` for migrations.
- `salt_ref` references env/file; plaintext salt is not stored.
- `target` identifies file/table/column.
- `action` is `mask`, `keep`, `ignore`, or `review` in MVP.
- `method` required for `mask`.
- `consistency_key` shares deterministic mapping across related fields.

## Deterministic masking

Use HMAC-SHA-256, not unsalted hashes.

Input to HMAC:

```txt
version + category + consistency_key + normalized_source_value
```

HMAC key: user-provided salt.

Normalization:

- Email: lowercase domain; configurable local-part normalization.
- Phone: strip separators, preserve original display style when practical.
- NIK/NPWP: strip punctuation for mapping, re-emit similar shape.
- Names/addresses: trim; preserve null/empty.

Methods:

- `deterministic_email`: default domain `example.invalid`.
- `deterministic_phone_id`: plausible Indonesian phone shape.
- `deterministic_nik`: 16-digit placeholder; later add stronger validity rules.
- `deterministic_npwp`: valid-length numeric shape, preserving punctuation.
- `deterministic_name_id`: synthetic Indonesian-friendly names from bundled non-sensitive lists.
- `deterministic_address_id`: synthetic address-like text.
- `date_shift`: deterministic bounded shift for DOB when configured.

## Foreign keys and snapshot consistency

### Numeric IDs

Default action: `keep`.

Examples kept by default:

- `users.id`
- `orders.user_id`
- `transactions.order_id`

This preserves joins and application behavior.

### Natural-key PII

Mask consistently across tables/files when the same raw value appears under the same `consistency_key`.

Examples:

- `users.email` and `login_logs.user_email` share `global:email`.
- `customers.nik` and `kyc_records.nik` share `global:nik`.

HMAC-based masking is stateless and scales better than a full in-memory lookup. A lookup table is only needed for collision-free generators.

## Streaming and large files

- Never require loading a full dump/CSV into memory.
- Keep bounded samples and counters per column.
- Stream apply into a temp output file, then atomically rename where supported.
- Never partially overwrite source input.
- Memory scales with columns/rules/samples, not rows.

## Exit codes

- `0`: success.
- `1`: usage/config error.
- `2`: parse/input error.
- `3`: check failed due to unclassified likely PII.
- `4`: apply/verification failed.

## Testing strategy

Use fixtures, not mocks, for parser/masker correctness.

Required test areas:

- Column normalization and detector rules.
- NIK/NPWP/phone/email/address pattern detection.
- Confidence scoring and numeric ID negative signals.
- HMAC determinism: same salt/source => same output; different salt => different output.
- Null/empty preservation.
- SQL COPY parsing and output shape.
- CSV quoting, escaped delimiters, ragged row failure.
- Cross-table repeated email maps to same masked email.
- Numeric foreign keys remain unchanged.
- CI/check fails for new unclassified high-confidence PII.
