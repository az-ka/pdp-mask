# Technical Spec Draft: pdp-mask

## Scope and principles

`pdp-mask` is a local-first CLI for scanning PostgreSQL-style SQL dumps and CSV files, producing a reviewable masking plan, and applying deterministic masking without uploading data. The MVP is rule-based: detection comes from schema/column heuristics plus sampled value patterns. Any AI-assisted classification is out of the MVP path and must remain optional and local-only later.

Core defaults:

- Never write to a production database in MVP; operate on files/snapshots.
- Preserve numeric IDs by default.
- Mask likely PII deterministically with a user-provided salt.
- Keep natural-key PII consistent across tables and files when the same source value appears.
- Generate human-reviewable terminal/JSON reports and `mask.yml` before applying changes.
- Avoid claiming legal compliance certification; report detected categories and decisions only.

## Input formats

### PostgreSQL SQL dump

MVP support should target common `pg_dump` text output:

- `CREATE TABLE` statements for schema extraction.
- `COPY schema.table (col1, col2, ...) FROM stdin;` blocks for bulk data.
- `INSERT INTO ... VALUES ...` may be supported after COPY-path stability, but should not be required for the first working path unless existing sample data needs it.
- Comments, extensions, indexes, constraints, and grants are passed through unless they are needed for schema/relationship metadata.

Parser expectations:

- Treat the dump as bytes plus declared/default encoding, normally UTF-8.
- Preserve line endings when practical for pass-through sections.
- Track file offset, line number, table name, column list, and row number for diagnostics.
- Do not fully parse PostgreSQL expression grammar unless needed; COPY data path is the reliable MVP target.

### CSV

CSV support should be explicit rather than magical:

- RFC 4180-style comma-separated files with quoted fields.
- Header row required by default; allow `--no-header` only if the user supplies a column map.
- Configurable delimiter, quote, escape, null marker, and encoding.
- Optional file-level table alias so multiple CSVs can share masking rules and relationship mappings.

CSV parser expectations:

- Stream records.
- Track row number and column index/name.
- Preserve row count and column count checks.
- Fail clearly on malformed quotes, ragged rows, or undecodable input unless a future explicit repair mode is added.

### Later inputs, not MVP

- Live database connections.
- MySQL/MariaDB dumps.
- Parquet/Excel.
- SaaS storage imports.

These should not shape the first internal API beyond keeping scanner/masker boundaries file-format agnostic.

## Parser and scan pipeline

Recommended pipeline:

1. **Open input**: resolve path, input type, encoding, size, and user options.
2. **Extract structure**:
   - SQL: collect tables, columns, COPY blocks, and simple FK/unique metadata when present.
   - CSV: collect file/table alias and headers.
3. **Sample values**:
   - Read bounded samples per column for detection, e.g. first N non-null values plus optional reservoir sampling for large files.
   - Store only derived evidence in reports where possible; avoid echoing full raw PII values.
4. **Detect PII**:
   - Run column-name rules.
   - Run value-pattern rules.
   - Combine signals into confidence and category candidates.
5. **Build report**:
   - Per input, table/file, column, category, confidence, evidence summary, and recommended action.
6. **Generate plan**:
   - Emit `mask.yml` with stable rule IDs and explicit decisions.
   - Leave uncertain columns as `review_required` when confidence is not high enough for automatic masking.
7. **Apply plan**:
   - Stream input to output.
   - Mask selected fields deterministically.
   - Pass through unselected fields and SQL non-data sections.
8. **Validate output shape**:
   - Same record counts.
   - Same column counts.
   - SQL COPY terminators preserved.
   - No unclassified high-confidence PII in CI mode.

Pipeline modes:

- `scan`: input -> terminal report + JSON report.
- `plan`: input -> generated `mask.yml`.
- `apply`: input + `mask.yml` + salt -> masked output.
- `check`: input + optional baseline/plan -> non-zero exit on newly detected unclassified likely PII.

## Detector rules for Indonesian PII

Rules should be transparent, versioned, and explainable. Each rule emits category, confidence contribution, and evidence label.

### Column-name heuristics

Normalize names before matching:

- Lowercase.
- Split snake_case, camelCase, kebab-case, spaces, and common prefixes/suffixes.
- Preserve original name for reports.
- Match Indonesian and common English terms.

Suggested categories and column signals:

- `nik`: `nik`, `no_ktp`, `nomor_ktp`, `ktp`, `n_i_k`, `identity_number`.
- `npwp`: `npwp`, `no_npwp`, `nomor_npwp`, `tax_id`.
- `name`: `nama`, `nama_lengkap`, `full_name`, `first_name`, `last_name`, `customer_name`, `pemilik`, `ibu_kandung`.
- `email`: `email`, `email_address`, `alamat_email`.
- `phone`: `phone`, `no_hp`, `nomor_hp`, `telepon`, `telp`, `wa`, `whatsapp`, `mobile`.
- `address`: `alamat`, `address`, `jalan`, `kelurahan`, `kecamatan`, `kota`, `kabupaten`, `provinsi`, `kode_pos`.
- `date_of_birth`: `tanggal_lahir`, `tgl_lahir`, `birth_date`, `dob`.
- `bank_account`: `rekening`, `no_rekening`, `nomor_rekening`, `bank_account`, `account_number` when paired with bank/customer context.
- `card_or_payment`: `card_number`, `no_kartu`, `kartu_kredit`, `payment_token`.
- `passport`: `passport`, `paspor`, `no_paspor`.
- `vehicle`: `plat_nomor`, `nopol`, `vehicle_plate`.
- `location`: `latitude`, `longitude`, `lat`, `lng`, `geo`, only when identifying individuals or addresses.

Negative/weakening signals:

- `id`, `*_id`, `count`, `total`, `amount`, `qty`, `status`, `type`, `created_at`, `updated_at` should not be marked PII by name alone.
- Numeric primary keys remain `keep` unless values also match a strong natural-key rule.

### Value-pattern rules

Patterns should be conservative to avoid masking operational fields incorrectly.

- Email: standard local-part/domain pattern with a valid-looking TLD; high confidence when many non-null samples match.
- Indonesian phone: `+62`, `62`, or leading `0` mobile/area patterns after stripping spaces, dashes, and parentheses; require plausible length.
- NIK: 16 digits; validate province/regency/district/date-position plausibility where possible; reject all repeated digits and obvious counters.
- NPWP: legacy 15-digit and newer 16-digit forms, with punctuation-tolerant normalization; reject repeated digits.
- Date of birth: date-like values in columns with birth/name context; value alone should be medium at most because transaction dates are common.
- Postal code: 5 digits; weak alone, stronger with address column names.
- Bank account: long digit strings in account-context columns; weak without context because many numeric identifiers exist.
- Address: Indonesian address tokens such as `jl`, `jalan`, `gg`, `gang`, `rt`, `rw`, `kel`, `kec`, `kab`, `kota`, `provinsi`, plus mixed free text; medium unless column name supports it.
- Name: value-only name detection should be weak; Indonesian names are diverse and overlap with free text. Prefer column context plus alphabetic samples.
- Vehicle plate: regional prefix + number + suffix shape, e.g. `B 1234 XYZ`; medium unless column context supports it.

For every value rule, compute:

- `sampled`: number of non-null sampled values.
- `matches`: count matching the rule.
- `match_ratio`.
- `examples_redacted`: optional redacted examples such as `jo***@example.com`, never full raw values by default.

## Confidence scoring

Use deterministic scoring, not opaque model output. A simple weighted model is enough for MVP.

Suggested score range: `0.0` to `1.0`.

Signals:

- Strong column-name match: +0.45 to +0.65.
- Weak/contextual column-name match: +0.15 to +0.35.
- Strong value-pattern match with high ratio: +0.45 to +0.70.
- Medium value-pattern match: +0.20 to +0.40.
- Cross-field context, e.g. `nama` near `nik`/`alamat`: +0.05 to +0.15.
- Negative operational signal, e.g. `*_id` numeric primary key: -0.40 to -0.70.
- Low sample count: cap confidence to medium unless column-name match is strong.

Suggested bands:

- `high`: `>= 0.80`; recommend `mask` for PII categories unless configured otherwise.
- `medium`: `0.50` to `< 0.80`; recommend `review_required`.
- `low`: `< 0.50`; recommend `keep` or `ignore` with evidence.

Tie-breaking:

- Prefer specific categories over generic ones: `nik` over `numeric_identifier`, `email` over `contact`.
- Allow multiple category candidates in the report, but the plan should choose one action/category per column unless the user overrides.

## Masking plan schema

`mask.yml` should be stable, diffable, and reviewable.

Example shape:

```yaml
version: 1
salt_ref: env:PDP_MASK_SALT
inputs:
  - id: customers_dump
    type: postgres_dump
    path: dump.sql
    output: dump.masked.sql
rules:
  - target:
      input: customers_dump
      table: public.customers
      column: email
    category: email
    action: mask
    method: deterministic_email
    consistency_key: global:email
    confidence: high
    detector_evidence:
      - column_name:email
      - value_pattern:email
  - target:
      input: customers_dump
      table: public.customers
      column: id
    action: keep
    reason: numeric_primary_key
  - target:
      input: customers_dump
      table: public.orders
      column: shipping_address
    category: address
    action: review_required
    confidence: medium
```

Schema fields:

- `version`: required integer for migration.
- `salt_ref`: required for apply unless salt is supplied by CLI option; do not store plaintext salt by default.
- `inputs`: list of input IDs, types, paths, and outputs.
- `rules`: ordered list of column-level decisions.
- `target`: input + table/file + column; SQL may include schema.
- `category`: detector category for mask/review actions.
- `action`: `mask`, `keep`, `drop`, `null`, `review_required`, or `ignore`.
- `method`: masking method when `action: mask`.
- `consistency_key`: namespace used to keep equal source values equal after masking.
- `reason`: human-readable reason for non-mask decisions.
- `detector_evidence`: compact rule IDs, not raw values.

CI behavior should require all `high` detections to have explicit plan entries. Medium detections may warn or fail depending on CLI flag.

## Deterministic masking

Masking must be deterministic for the same salt, category, consistency namespace, and source value.

Recommended primitive:

- Derive bytes with HMAC-SHA-256 using the user salt.
- Input to HMAC: version + category + consistency namespace + normalized source value.
- Use derived bytes to select fake values, digits, or formatted components.
- Never use unsalted hashes for PII.

Normalization examples:

- Email: lowercase domain; decide whether local-part normalization is category-specific.
- Phone: strip separators; preserve leading `0`/`+62` format based on original.
- NIK/NPWP/account numbers: strip punctuation for mapping, re-emit original punctuation shape when possible.
- Names/addresses: trim surrounding whitespace; preserve empty/null as-is.

Masking methods:

- `deterministic_email`: preserve domain policy by config: fake domain default such as `example.invalid`, or preserve original domain only if user opts in.
- `deterministic_phone_id`: generate plausible Indonesian phone shape while preserving original formatting style.
- `deterministic_nik`: generate 16 digits with plausible date/region shape if feasible; otherwise clearly fake but structurally valid. Do not preserve actual birthdate unless user explicitly requests format-preserving partial retention.
- `deterministic_npwp`: generate valid-length numeric shape, preserving punctuation.
- `deterministic_name_id`: choose from bundled Indonesian-friendly given/family name lists using HMAC-derived indexes.
- `deterministic_address_id`: synthesize street/city/province-like text from bundled local lists; preserve null/empty.
- `deterministic_digits`: same length numeric replacement for bank accounts and similar natural keys.
- `fixed_null`/`drop_column`: explicit destructive methods only when configured.

Null and empty handling:

- SQL `NULL`, CSV configured null marker, and empty string are distinct and should be preserved unless the plan explicitly changes them.

## FK and snapshot consistency

Relational safety has two separate concerns: structural keys and natural-key PII.

### Numeric IDs

- Default action for integer primary keys and foreign keys is `keep`.
- Do not mask `customer_id`, `order_id`, or similar numeric relational IDs by detector name alone.
- If a numeric ID column is also detected as PII by strong value rules, require review rather than automatic masking.

### Natural-key PII consistency

Equal source PII values should map to equal masked values when the plan uses the same `consistency_key`.

Examples:

- `users.email` and `orders.customer_email` share `global:email`.
- `customers.nik` and `kyc_records.nik` share `global:nik`.
- CSV and SQL inputs in the same apply run can share consistency namespaces.

Consistency implementation:

- Stateless deterministic masking via HMAC is preferred over an in-memory lookup table for large files.
- A lookup table is only needed for generators that must avoid collisions across many generated values; if used, it must spill safely or be bounded by category.
- The plan should allow per-column overrides when the same raw value should not be shared across contexts.

### Snapshot-level consistency

- A single apply command over multiple inputs should use one salt and one plan.
- Re-running apply with the same salt, plan, and inputs should produce byte-for-byte equivalent masked data for data fields, except for pass-through formatting differences explicitly documented.
- Changing salt must remap all masked values.

## Streaming large files

The implementation should not require loading a full SQL dump or CSV into memory.

Scanning:

- Stream input records.
- Keep bounded samples and counters per column.
- Use reservoir sampling only if representative late-file samples are needed; otherwise first-N non-null samples are simpler and deterministic.
- Track maximum sample bytes per column to avoid memory blowups on free-text fields.

Applying:

- Stream input to a temp output file in the destination directory, then atomically rename on success where the platform allows.
- Never partially overwrite the source file by default.
- Flush pass-through SQL sections without materializing them.
- For COPY blocks and CSV records, transform only selected fields.

Memory targets:

- Memory should scale with number of columns/rules and bounded samples, not with input file size.
- HMAC-based deterministic masking avoids keeping a raw-value map for most categories.

Progress and cancellation:

- Report bytes/records processed for large inputs.
- On error, close files and leave the original input untouched.
- Remove incomplete temp output unless a debug flag asks to keep it.

## Outputs

### Terminal report

Human-readable summary:

- Inputs scanned.
- Tables/files and row/sample counts.
- Detected columns grouped by confidence and category.
- Recommended actions: mask, keep, review.
- CI/check result and next command suggestion.

Avoid printing full raw PII. Redacted examples are acceptable only when useful.

### JSON report

Machine-readable report for CI and review tools:

```json
{
  "version": 1,
  "inputs": [
    {"id": "customers_dump", "type": "postgres_dump", "path": "dump.sql"}
  ],
  "findings": [
    {
      "target": {"input": "customers_dump", "table": "public.customers", "column": "email"},
      "category": "email",
      "confidence": 0.97,
      "band": "high",
      "sampled": 100,
      "matches": 99,
      "evidence": ["column_name:email", "value_pattern:email"],
      "recommended_action": "mask"
    }
  ]
}
```

### Masked files

- SQL output should remain loadable by PostgreSQL for supported dump forms.
- CSV output should preserve delimiter/quote configuration and row/column counts.
- Output paths should default to suffixes such as `.masked.sql` and `.masked.csv` unless configured.

### Exit codes

Suggested:

- `0`: success, no blocking findings.
- `1`: CLI usage/config error.
- `2`: parse/input error.
- `3`: check failed due to unclassified likely PII.
- `4`: apply failed.

## Errors and diagnostics

Errors should include input ID/path, table/file, column when known, row/line when known, and a short remediation hint.

Error categories:

- `unsupported_input`: format not supported.
- `encoding_error`: invalid bytes for selected encoding.
- `parse_error`: malformed SQL COPY or CSV syntax.
- `schema_error`: duplicate/missing columns, unknown plan target.
- `plan_error`: invalid `mask.yml`, missing salt, unsupported method/category.
- `consistency_error`: conflicting rules for the same consistency namespace.
- `io_error`: read/write/temp/rename failure.
- `safety_error`: output path would overwrite input without explicit flag.

Warnings:

- Low sample count.
- Medium-confidence findings requiring review.
- Unsupported SQL statements passed through.
- Potential collision risk for format-preserving numeric generation if collision-free mode is not enabled.

## Testing strategy

Do not rely on mocks for parser/masker correctness. Use small fixture files with realistic edge cases.

### Unit tests

- Column-name normalization and rule matching.
- Indonesian PII value patterns: NIK, NPWP, phone, email, address tokens, vehicle plates.
- Confidence scoring, including negative `*_id` primary-key signals.
- HMAC deterministic mapping: same salt/source gives same output; different salt changes output.
- Null/empty handling per format.
- Format preservation for punctuation in NPWP, phone, and numeric strings.

### Parser fixture tests

- PostgreSQL dump with CREATE TABLE plus COPY blocks.
- COPY data containing tabs, escaped nulls, backslash escapes, and terminator line.
- CSV with quoted commas, quotes, multiline fields if supported, ragged row failure, and configured delimiter.
- Encoding failure fixture if non-UTF-8 support is added.

### Integration tests

- `scan` produces expected findings and bands for a fixture dump.
- `plan` generates stable `mask.yml` with explicit `keep` for numeric IDs and `mask` for high-confidence PII.
- `apply` preserves row counts, column counts, SQL COPY structure, and CSV shape.
- Same email across two tables/files maps to the same masked email under shared `consistency_key`.
- Numeric foreign keys remain unchanged and joins remain possible by ID.
- `check` exits non-zero when a new high-confidence PII column lacks a plan entry.

### Property/invariant tests

- Applying the same plan and salt twice is deterministic.
- Changing salt changes masked PII.
- Non-targeted fields are byte/field equivalent after round trip.
- No generated masked value equals the original for non-null selected PII unless collision handling explicitly reports it.
- Memory use for large generated fixtures remains bounded by samples/rules rather than row count.

### Golden outputs

Maintain compact golden fixtures for:

- JSON report shape.
- `mask.yml` generation.
- Masked SQL COPY output.
- Masked CSV output.

Golden tests should avoid asserting default fake names/domains except where the deterministic algorithm contract requires exact output. Prefer asserting logical invariants when defaults are not contractual.
