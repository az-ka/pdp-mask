# Phase 1 DX Advice: `pdp-mask scan` CSV CLI

## Scope boundary

Phase 1 should expose one user-facing command only:

```bash
pdp-mask scan <csv>
```

It scans one RFC 4180-style CSV file with a required header row, detects likely Indonesian PII, prints a safe terminal summary, and optionally writes a safe JSON report. It must not mask data, generate plans, connect to databases, parse SQL, or print raw cell values.

## Recommended default command

```bash
pdp-mask scan customers.csv
```

Default behavior:

- Treat input as CSV.
- Require a header row.
- Use Indonesian detector rules.
- Sample up to 1,000 non-empty values per column.
- Print a terminal summary to stdout.
- Print diagnostics/errors to stderr.
- Exit non-zero only for command/input failures, not merely because PII was found.
- Never print raw CSV values.

## Flags

### Phase 1 flags to implement

```text
Usage:
  pdp-mask scan <csv> [flags]

Flags:
  --out <path>              Write JSON scan report to path.
  --sample-rows <n>         Maximum data rows to inspect. Default: 1000. Use 0 to scan all rows.
  --delimiter <char>        CSV delimiter. Default: ,.
  --quote <char>            CSV quote character. Default: ".
  --has-header <bool>       Whether the first row is a header. Default: true. Phase 1 only supports true.
  --fail-on <policy>        Exit policy: none, medium, high. Default: none.
  --quiet                   Suppress finding table; keep final count and JSON path.
  --json                    Print JSON report to stdout instead of terminal text.
  -h, --help                Show help.
```

### Flag behavior

- `<csv>` is required and must be a local file path.
- `--out` writes the same schema as `--json`; it must fail rather than overwrite a directory or unreadable path.
- `--json` writes JSON to stdout. Human logs and warnings must go to stderr so stdout remains parseable.
- `--out` and `--json` may be used together: write the file and also print JSON to stdout.
- `--sample-rows 0` means scan all rows. Negative values are invalid.
- `--delimiter` and `--quote` must be exactly one character.
- `--has-header=false` should return a clear unsupported error in Phase 1 instead of guessing column names.
- `--fail-on none` means findings do not change the exit code.
- `--fail-on medium` exits 3 when any medium or high finding exists.
- `--fail-on high` exits 3 when any high finding exists.
- `--quiet` affects terminal output only and must not change JSON content.

### Flags to defer

Do not add these in Phase 1:

- `--format`: CSV is the only Phase 1 format for this implementation slice.
- `--preset`: Indonesian detectors are the only enabled preset.
- `--config`: no custom detector configuration yet.
- `--mask`, `--apply`, `--plan`, `--verify`: out of scope.
- Encoding, null-marker, and escape customization unless already trivial in the CSV library; avoid promising behavior not implemented.

## Terminal output

### Successful scan with findings

```text
pdp-mask scan customers.csv

Input        customers.csv
Format       csv
Preset       indonesia
Rows scanned 1,000 of 12,481
Columns      8

Likely PII
  column            category       confidence  evidence        matches
  email             email          high        column+value    982/1000
  no_hp             phone_id       high        column+value    876/1000
  nik               nik            high        column+value    991/1000
  nama_lengkap      name           medium      column          -
  alamat            address        medium      column+value    344/1000
  tanggal_lahir     date_of_birth  medium      column          -

Probably safe / ignored
  id                numeric_id     low         negative-id     -

Summary
  High confidence    3 columns
  Medium confidence  3 columns
  Low confidence     1 column

No raw values printed. Use --out report.json for machine-readable evidence.
```

### Successful scan with no likely PII

```text
pdp-mask scan products.csv

Input        products.csv
Format       csv
Preset       indonesia
Rows scanned 1,000 of 42,000
Columns      6

No likely PII found.

Summary
  High confidence    0 columns
  Medium confidence  0 columns
  Low confidence     0 columns
```

### Quiet output

```text
pdp-mask scan customers.csv

High: 3  Medium: 3  Low: 1
JSON report written to reports/customers.scan.json
```

### Output rules

- Terminal rows are column-level only.
- Do not print sampled values, example matches, row numbers containing PII, or unredacted parse context.
- Sort findings by confidence descending, then category, then input column order.
- Use `-` for counts that do not apply, such as column-name-only findings.
- Keep column names as provided in the CSV header; column names are metadata and are safe to display.
- Include numeric ID negative-signal rows only when useful; do not let them dominate output.

## JSON report schema

The JSON report should be stable, deterministic, and safe for CI artifacts.

```json
{
  "schema_version": 1,
  "tool": {
    "name": "pdp-mask",
    "command": "scan"
  },
  "input": {
    "path": "customers.csv",
    "format": "csv",
    "has_header": true,
    "delimiter": ",",
    "quote": "\""
  },
  "scan": {
    "preset": "indonesia",
    "sample_rows": 1000,
    "rows_scanned": 1000,
    "rows_total": 12481,
    "truncated": true,
    "columns_total": 8
  },
  "summary": {
    "high": 3,
    "medium": 3,
    "low": 1,
    "findings": 7
  },
  "findings": [
    {
      "column": "email",
      "column_index": 2,
      "category": "email",
      "confidence": "high",
      "score": 0.98,
      "recommended_action": "review",
      "evidence": [
        {
          "kind": "column_name",
          "label": "email_column",
          "score": 0.55
        },
        {
          "kind": "value_pattern",
          "label": "email",
          "score": 0.65,
          "sampled": 1000,
          "matched": 982,
          "match_ratio": 0.982
        }
      ]
    },
    {
      "column": "id",
      "column_index": 1,
      "category": "numeric_id",
      "confidence": "low",
      "score": 0.05,
      "recommended_action": "keep",
      "evidence": [
        {
          "kind": "negative_signal",
          "label": "numeric_id_column",
          "score": -0.4
        }
      ]
    }
  ],
  "diagnostics": []
}
```

### JSON field requirements

- `schema_version`: integer, start at `1`.
- `tool.name`: `pdp-mask`.
- `tool.command`: `scan`.
- `input.path`: display path as provided or normalized relative path; do not require absolute paths.
- `input.format`: always `csv` in Phase 1.
- `scan.rows_total`: total parsed data rows when known. If counting all rows would require a second pass, set it to `null` and rely on `rows_scanned` plus `truncated`.
- `scan.truncated`: true when sampling stopped before all rows were inspected.
- `summary`: counts by finding confidence.
- `findings`: one object per reported column/category decision.
- `column_index`: one-based CSV column index.
- `category`: one of `email`, `phone_id`, `nik`, `npwp`, `name`, `address`, `date_of_birth`, `numeric_id`, or `unknown`.
- `confidence`: `high`, `medium`, or `low`.
- `score`: numeric `0.0` to `1.0` after penalties/caps.
- `recommended_action`: for Phase 1 reporting only; use `review` for high/medium PII and `keep` for numeric ID negative signals.
- `evidence.kind`: one of `column_name`, `value_pattern`, `context`, or `negative_signal`.
- `evidence.label`: stable detector label, not a raw value.
- `diagnostics`: non-fatal parse or scan warnings, never raw data.

### JSON privacy rules

The JSON report must not include:

- Raw cell values.
- Example matched values.
- Row-level PII excerpts.
- Hashes of raw values.
- Full source file contents.

Allowed evidence is aggregate-only: sampled count, matched count, match ratio, detector labels, column metadata, and scores.

## Detector UX expectations

### High confidence

Use high confidence when strong value evidence exists, usually with matching column context:

- `email` column plus email-like values.
- Indonesian phone values in `no_hp`, `telepon`, `wa`, or similar columns.
- 16-digit NIK-like values in `nik`, `no_ktp`, `nomor_ktp`, or similar columns.
- NPWP-like values in `npwp`, `tax_id`, or similar columns.

### Medium confidence

Use medium confidence for likely PII that still needs human review:

- Name columns such as `nama`, `nama_lengkap`, `full_name` without strong value proof.
- Address columns or address-token values.
- DOB columns such as `tanggal_lahir`, `tgl_lahir`, `birth_date`, `dob`.
- Value-only patterns with lower match ratios.

### Low confidence / negative signal

Use low confidence for weak or mostly safe signals:

- Numeric operational IDs: `id`, `user_id`, `customer_id`, `order_id`.
- `count`, `total`, `amount`, `qty`, `status`, `type`, `created_at`, `updated_at` by name alone.
- Postal-code-like 5 digit values without address context.

Numeric IDs should be visible as safe/ignored when they explain why a column was not treated as NIK/phone/NPWP.

## Error behavior

### Exit codes

```text
0  Scan completed and fail policy did not trigger.
1  Usage error: invalid flags, missing input, unsupported option.
2  Input error: file missing, unreadable, malformed CSV, duplicate/empty headers.
3  Findings triggered --fail-on policy.
4  Output error: could not write --out report.
```

### Error output examples

Missing input:

```text
Error: missing CSV input path

Usage:
  pdp-mask scan <csv> [flags]
```

Unsupported headerless CSV:

```text
Error: Phase 1 requires a CSV header row; --has-header=false is not supported yet
```

Malformed CSV:

```text
Error: malformed CSV at row 42, column 5: unexpected quote
```

Duplicate headers:

```text
Error: duplicate CSV header "email" at columns 2 and 7
```

Fail policy triggered:

```text
pdp-mask scan customers.csv

High: 3  Medium: 3  Low: 1
Error: --fail-on=high triggered by 3 high-confidence findings
```

### Error rules

- Errors must not include raw field values.
- CSV row and column numbers are okay because they identify structure, not content.
- If `--json` is set and the scan fails before producing a valid report, stdout should be empty and the error should be on stderr.
- If `--out` fails after a successful scan, return exit code 4 and say that the report could not be written.
- Malformed CSV must fail clearly; do not silently skip bad rows.

## Help text

```text
Scan a CSV file for likely Indonesian PII without printing raw values.

Usage:
  pdp-mask scan <csv> [flags]

Examples:
  pdp-mask scan customers.csv
  pdp-mask scan customers.csv --out reports/customers.scan.json
  pdp-mask scan customers.csv --fail-on high
  pdp-mask scan customers.csv --json > report.json
```

The help text should explicitly say that Phase 1 scans CSV only and does not mask data.
