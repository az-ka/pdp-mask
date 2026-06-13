# Phase 1 Test Advice: CSV Scan

## Recommended compact fixtures

Keep fixtures small enough for golden review, but dense enough to exercise column-name signals, value-pattern signals, confidence bands, and false-positive guards.

### 1. `customers_pii.csv` — positive Indonesian PII signals

Purpose: one happy-path CSV that should produce high-confidence findings without relying on raw value output.

```csv
id,nama_lengkap,email,no_hp,nik,npwp,alamat,tgl_lahir,status,created_at
1,Siti Aminah,siti.aminah@example.test,0812-3456-7890,3173054401010001,12.345.678.9-012.000,"Jl. Melati No. 7 RT 01 RW 02, Kota Bandung",1991-01-04,active,2024-01-02T03:04:05Z
2,Budi Santoso,budi.santoso@example.test,+62 812 1111 2222,3276021502870002,98.765.432.1-091.000,"Jalan Kenanga 12, Kec Sukajadi",1987-02-15,inactive,2024-02-03T04:05:06Z
3,Dewi Lestari,dewi.lestari@example.test,6281312345678,3374015203900003,01.234.567.8-999.000,"Gang Mawar 3, Kel Cikutra",1990-03-12,pending,2024-03-04T05:06:07Z
```

Expected findings:

| Column | Expected category | Expected confidence/action | Evidence to require |
| --- | --- | --- | --- |
| `nama_lengkap` | `name` | high or medium review, depending on scoring policy | strong column-name signal, alphabetic non-null samples |
| `email` | `email` | high / mask recommendation | column-name + value-pattern match ratio 3/3 |
| `no_hp` | `phone` | high / mask recommendation | Indonesian phone normalization accepts `08`, `+62`, `62` |
| `nik` | `nik` | high / mask recommendation | column-name + 16-digit plausible values |
| `npwp` | `npwp` | high / mask recommendation | column-name + punctuation-tolerant NPWP values |
| `alamat` | `address` | high or medium review | column-name + address tokens: `Jl`, `Jalan`, `Gang`, `RT`, `RW`, `Kec`, `Kel` |
| `tgl_lahir` | `date_of_birth` | high or medium review | birth-date column context + date-like values |

Expected non-findings/keeps in the same file:

- `id`: keep; numeric operational ID must not be classified as NIK just because it is numeric.
- `status`: keep; operational status negative signal.
- `created_at`: keep; timestamp negative signal, not DOB without birth context.

### 2. `ops_false_positives.csv` — numeric and operational guardrail

Purpose: protect against over-classifying IDs, amounts, timestamps, counters, and enum-like text.

```csv
id,user_id,order_id,invoice_number,amount,total,qty,status,type,created_at,updated_at,reference_code
1,101,90001,2024010000000001,150000,175000,2,paid,retail,2024-01-01T10:00:00Z,2024-01-01T11:00:00Z,INV-2024-0001
2,102,90002,2024020000000002,250000,275000,1,failed,wholesale,2024-02-01T10:00:00Z,2024-02-01T11:00:00Z,REF-000000000002
3,103,90003,2024030000000003,350000,375000,5,refunded,retail,2024-03-01T10:00:00Z,2024-03-01T11:00:00Z,ORDER-3374015203900003
```

Expected behavior:

- `id`, `user_id`, `order_id`: no PII finding; recommended action `keep` or absent from findings.
- `invoice_number`, `reference_code`: no high-confidence NIK/NPWP finding despite 16-digit-like substrings; operational column names should lower confidence.
- `amount`, `total`, `qty`: no numeric identifier findings.
- `status`, `type`: no name/address findings from free-form enum text.
- `created_at`, `updated_at`: no DOB finding even though values are date-like.
- If implementation reports low-confidence candidates for `invoice_number` or `reference_code`, tests should require `confidence != high` and `recommended_action != mask`.

### 3. `mixed_sparse.csv` — sample ratios, nulls, and ambiguity

Purpose: verify confidence is ratio/context based and null/empty values do not create matches or errors.

```csv
customer_name,contact,identity_number,tax_id,address_note,birth_date,notes
Andi Pratama,andi.pratama@example.test,3173054401010001,123456789012000,"Jl. Sudirman 1",1980-10-01,preferred customer
,,not-a-nik,,unknown,,no contact
Rina Melati,081234567890,0000000000000000,000000000000000,"near Kota Bogor",not-a-date,manual review
```

Expected behavior:

- `customer_name`: medium/high name from column context, not value-only certainty.
- `contact`: ambiguous mixed email/phone; either category candidates are allowed, but evidence must show sampled/matched counts and no raw values.
- `identity_number`: medium/high NIK only for plausible 16-digit sample; reject `0000000000000000` repeated digits.
- `tax_id`: medium/high NPWP only for plausible sample; reject all-zero repeated digits.
- `address_note`: medium address because context/tokens are partial.
- `birth_date`: medium/high DOB only from column context; invalid date must reduce match ratio.
- Empty fields should be counted as null/empty or skipped from sampled non-null counts, not as failed matches that crash parsing.

### 4. Malformed CSV fixture

Purpose: assert clear parse failure and exit behavior.

```csv
id,email
1,"broken@example.test
2,ok@example.test
```

Expected behavior:

- `pdp-mask scan malformed.csv` exits with the configured parse/input error code for Phase 1, or at minimum a non-zero code if exit codes are not finished yet.
- Error text identifies CSV parsing and location enough to fix the file, e.g. row/line context.
- Error text must not dump raw cell contents.
- No JSON report should be written unless the CLI has an explicit partial-report contract.

## Behavior tests to add/review

### CLI invocation

- `pdp-mask scan customers_pii.csv` prints a terminal summary listing file, column, category, confidence band, recommendation, and evidence labels.
- `pdp-mask scan customers_pii.csv --json report.json` writes machine-readable JSON and keeps terminal output concise.
- Unknown flags, missing path, nonexistent file, and directory path fail with usage/input errors.
- Header row is required for Phase 1; a no-header CSV should fail clearly unless implementation adds an explicit option.

### Terminal output safety

For all positive fixtures, assert terminal output:

- Contains column names and categories: `email`, `phone`, `nik`, `npwp`, `address`, `date_of_birth`.
- Contains confidence bands or numeric scores.
- Contains evidence labels such as `column_name:email`, `value_pattern:email`, `value_pattern:phone`, `negative_signal:operational_id`.
- Does not contain full raw fixture values, especially complete emails, phone numbers, NIK, NPWP, names, addresses, or DOB strings.
- If redacted examples are supported, they must be visibly redacted and never reversible from the output.

### JSON report shape

Assert structure rather than exact scoring constants. Recommended minimum shape:

```json
{
  "version": 1,
  "input": {
    "path": "customers_pii.csv",
    "type": "csv"
  },
  "summary": {
    "columns": 10,
    "rows": 3,
    "findings": 7
  },
  "findings": [
    {
      "column": "email",
      "category": "email",
      "confidence": "high",
      "score": 0.0,
      "recommended_action": "mask",
      "evidence": [
        {
          "kind": "column_name",
          "label": "email"
        },
        {
          "kind": "value_pattern",
          "label": "email",
          "sampled": 3,
          "matched": 3,
          "match_ratio": 1.0
        }
      ]
    }
  ]
}
```

JSON assertions:

- Stable top-level `version` exists.
- Input format is `csv`.
- Summary includes row count, column count, and finding count.
- Findings are per column and include original column name, category, score or confidence band, recommended action, and evidence.
- Evidence includes sampled/matched counts for value-pattern rules.
- JSON output must not contain raw sensitive values. Test by scanning for full fixture emails, phone numbers, NIKs, NPWPs, names, addresses, and DOBs.
- Ordering should be stable: preferably file/header order, then category priority for multiple candidates.

### False-positive guard tests

Use `ops_false_positives.csv` to assert:

- No finding with `category in {"nik", "npwp", "phone", "email", "name", "address", "date_of_birth"}` has `confidence == "high"` or `recommended_action == "mask"` for `id`, `*_id`, `amount`, `total`, `qty`, `status`, `type`, `created_at`, or `updated_at`.
- Long operational numbers under `invoice_number` and `reference_code` are either absent or downgraded to low/keep/review with explicit negative evidence.
- A 16-digit substring embedded in `ORDER-...` is not enough for a high NIK finding when the column name is operational.

### Detector-specific checks

- Email accepts common local/domain forms and rejects strings without a valid-looking domain.
- Indonesian phone accepts separators and prefixes `08`, `628`, `+628` after normalization.
- NIK rejects repeated digits, obvious counters, and values in operational ID columns.
- NPWP accepts punctuated legacy shape and numeric-only shape, but rejects repeated digits.
- DOB requires birth column context; transaction timestamps are not DOB.
- Address/name value-only signals remain weak unless column context supports them.

## Review guidance

Good Phase 1 tests should avoid pinning exact floating-point scores unless scoring constants are declared stable. Prefer assertions on category, confidence band, recommendation, evidence labels, sampled/matched counts, and absence of raw PII. The most important regression tests are the false-positive guards: masking operational IDs, amounts, statuses, or timestamps would break downstream data utility and undermine trust in the scanner.
