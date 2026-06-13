# PRD Draft: pdp-mask

## 1. Summary

`pdp-mask` is a local-first open-source CLI for Indonesian software teams that need production-like SQL or CSV snapshots without exposing personal data in local, staging, demo, CI, or vendor workflows. The MVP scans PostgreSQL-style SQL dumps and CSV files, detects likely PII using deterministic rule-based heuristics, generates a reviewable masking plan, applies deterministic masking with a user-provided salt, preserves relational consistency, and supports CI checks for unclassified newly detected PII.

The product must not position itself as legal compliance certification. It should help teams reduce accidental exposure of personal data while keeping the workflow understandable, auditable, and runnable fully offline.

## 2. Problem

Development teams often need production-like data to reproduce bugs, validate migrations, test reports, prepare demos, or share fixtures with vendors. In practice, snapshots can contain names, email addresses, phone numbers, physical addresses, NIK, NPWP, dates of birth, bank identifiers, and other personal data. Raw snapshots copied into developer machines, staging systems, CI artifacts, or third-party environments expand the blast radius of a data leak.

Existing anonymization tools prove demand for database masking, but many workflows still fail for Indonesian teams because they need:

- Indonesian PII presets, not only generic email/name detection.
- Snapshot-first handling for SQL dumps and CSV files, not mandatory live database access.
- Offline execution with no SaaS upload.
- A generated plan that engineers can review before mutation.
- Deterministic masking so foreign-key-like natural keys and repeated values stay consistent.
- CI enforcement so newly introduced PII columns are classified before fixtures are published.

## 3. Target Users

### Primary users

1. **Backend engineers**
   - Need production-like fixtures for debugging, migrations, and integration tests.
   - Care about deterministic output, schema preservation, and low-friction CLI usage.

2. **QA and test engineers**
   - Need realistic but safe data in staging, test suites, and bug reproduction packages.
   - Care about repeatable datasets and simple reports that explain what was masked.

3. **DevOps / platform engineers**
   - Need CI guardrails around fixture generation and database dump handling.
   - Care about scriptability, non-interactive modes, exit codes, and artifact outputs.

4. **Engineering leads / security-minded maintainers**
   - Need visibility into what personal data exists in shared snapshots.
   - Care about reviewable plans, risk reduction, and no hidden cloud dependency.

### Secondary users

1. **Data analysts in small teams** who receive CSV exports and need safe demo/test data.
2. **Open-source maintainers** who want sanitized fixtures for reproducible issues.
3. **Vendors or implementation partners** who should receive masked snapshots instead of raw production data.

## 4. Core Use Cases

### UC1: Inspect a SQL dump for likely PII

A backend engineer runs `pdp-mask scan dump.sql` before sharing a production snapshot. The tool emits a terminal summary and JSON report listing tables, columns, confidence levels, detection reasons, and recommended masking strategies.

### UC2: Generate a reviewable masking plan

After scanning, the engineer runs a plan-generation command. The tool creates `mask.yml` with each detected field classified as mask, keep, ignore, or needs-review. The engineer reviews and edits the plan before applying masking.

### UC3: Mask a PostgreSQL-style dump deterministically

The engineer applies `mask.yml` with a salt. The output dump preserves schema and numeric IDs by default, replaces PII values with deterministic fake values, and keeps repeated natural-key PII consistent across tables.

### UC4: Mask CSV exports

A QA engineer receives CSV files containing customer records. The tool scans and masks them using the same rule presets and plan format, producing masked CSV files suitable for staging or demos.

### UC5: Enforce fixture safety in CI

A platform engineer adds a CI job that scans committed or generated SQL/CSV fixtures. The job fails when likely PII appears without an explicit plan classification, preventing accidental publication of raw personal data.

### UC6: Preserve relational consistency for natural-key references

If the same email, phone number, NIK, or NPWP appears in multiple files or tables, applying the same salt and plan maps the same input value to the same masked output value. This lets application flows keep working while hiding the original value.

## 5. MVP Scope

### Inputs

- PostgreSQL-style SQL dump files.
- CSV files with header rows.
- Local files only; no remote URLs or cloud storage connectors in MVP.

### Detection

- Rule-based column-name heuristics.
- Rule-based sample-value pattern matching.
- Indonesian PII presets, including at minimum:
  - NIK-like values.
  - NPWP-like values.
  - Indonesian phone numbers.
  - Indonesian address signals.
  - Bank/account identifier signals where detectable from column names or value shape.
- Generic PII signals, including at minimum:
  - Email.
  - Phone.
  - Person name.
  - Address.
  - Date of birth / birth date.
- Confidence labels or scores that explain why a field was flagged.
- Detection reasons must be included in JSON and terminal reports.

### Masking plan

- Generate a `mask.yml` file from scan findings.
- Each field entry should include:
  - Source location: file/table/column as applicable.
  - Detected PII category.
  - Detection reasons.
  - Recommended action.
  - Selected action.
  - Masking strategy.
- Supported actions for MVP:
  - `mask`: replace values.
  - `keep`: preserve values, intended for IDs and non-sensitive operational fields.
  - `ignore`: explicitly accept as not PII.
  - `review`: require human decision before apply/CI success.
- Numeric surrogate IDs are kept by default unless explicitly classified otherwise.

### Masking behavior

- Deterministic masking using a user-provided salt.
- Same original value + same salt + same strategy must produce the same masked value across files and tables.
- Different salt should produce different masked values.
- Empty/null values must remain empty/null.
- Output should preserve the input format enough for normal downstream loading/parsing.
- Masking should favor plausible replacement shapes where practical:
  - Emails remain email-shaped.
  - Phone numbers remain phone-shaped.
  - NIK/NPWP replacements remain category-shaped and non-original.
  - Names remain name-like.
  - Dates remain valid dates when masked.
- The tool must not write to a production database in MVP.

### Outputs

- Human-readable terminal report.
- Machine-readable JSON report.
- Generated `mask.yml`.
- Masked SQL dump output.
- Masked CSV output.
- CI-compatible exit codes.

### CLI workflow

The exact command names can be finalized during technical design, but the MVP should support these flows:

1. `scan`: inspect input and emit report.
2. `plan`: generate or update `mask.yml` from scan results.
3. `apply`: create masked output using a plan and salt.
4. `check`: fail CI when likely PII is unclassified or plan coverage is incomplete.

## 6. Non-Goals

- No SaaS upload or hosted processing.
- No legal compliance certification claim.
- No production database writes in MVP.
- No AI-first detection.
- No remote database connector in MVP.
- No web dashboard before the CLI workflow is stable.
- No attempt to perfectly identify every possible personal-data field.
- No generic data catalog or full data-governance platform.
- No automatic destructive mutation of source files; outputs should be written separately unless the user explicitly opts into overwrite behavior.
- No promise that masked data is mathematically impossible to re-identify; the tool reduces practical exposure when used correctly.

## 7. Success Metrics

### Product usefulness

- A new user can scan a SQL dump or CSV and understand likely PII findings without reading source code.
- Generated `mask.yml` is clear enough for a senior engineer to review and adjust.
- A team can produce a masked SQL/CSV artifact suitable for local/staging/demo use.

### Detection and review quality

- Reports identify common Indonesian PII categories from both column names and sample values.
- Findings include evidence reasons, not opaque labels.
- CI check fails when a likely PII field is newly detected but not classified.

### Masking correctness

- Deterministic consistency holds across repeated values in the same run and across separate runs with the same salt.
- Numeric IDs are preserved by default.
- Null/empty values are preserved.
- Masked outputs remain parseable as SQL dump or CSV.

### Adoption and maintainability

- CLI can run offline in a standard development or CI environment.
- Default workflow requires no service account and no network access.
- Rules and presets are understandable and extensible by contributors.

## 8. User Journeys

### Journey A: Backend engineer sanitizes a production bug fixture

1. Engineer exports a PostgreSQL-style dump from an approved internal process.
2. Engineer runs scan locally.
3. Tool prints a summary: number of tables, flagged columns, high-confidence categories, and fields requiring review.
4. Engineer generates `mask.yml`.
5. Engineer reviews the plan, keeps numeric IDs, masks email/phone/name/NIK/NPWP/address fields, and marks false positives as ignored.
6. Engineer runs apply with a salt from team secret storage or local secure input.
7. Tool writes a masked dump and JSON report.
8. Engineer loads the masked dump into a local/staging environment and can reproduce the bug without raw PII.

### Journey B: QA prepares masked CSV demo data

1. QA receives CSV exports from an internal system.
2. QA scans the CSV files.
3. Tool flags likely names, emails, phone numbers, DOBs, and addresses.
4. QA generates and reviews `mask.yml`.
5. QA applies masking with a stable salt for the demo environment.
6. Tool outputs masked CSV files preserving headers and row count.
7. QA uses the masked files in a demo or test environment.

### Journey C: Platform engineer adds CI guardrail

1. Platform engineer commits a reviewed `mask.yml` for test fixtures.
2. CI runs `pdp-mask check` on fixture SQL/CSV files.
3. If a new column or value pattern indicates likely PII and is not classified in the plan, the command exits non-zero and prints the unclassified findings.
4. Developer updates the plan to mask, keep, or ignore the field.
5. CI passes only after all likely PII findings are classified.

### Journey D: Maintainer publishes OSS reproduction data

1. Maintainer receives a bug report that requires realistic data.
2. Maintainer creates a minimal CSV or SQL fixture from internal data.
3. Maintainer runs scan and apply locally.
4. Maintainer verifies the masked artifact has no original email/phone/NIK/NPWP values.
5. Maintainer commits only the masked artifact and plan/report evidence.

## 9. Acceptance Criteria

### Scan

- Given a PostgreSQL-style SQL dump containing likely PII columns, when the user scans it, then the tool reports flagged fields with category, confidence, and detection reason.
- Given a CSV with headers and sample values, when the user scans it, then the tool evaluates both header names and sampled values.
- Given an input with no detected likely PII, when the user scans it, then the tool exits successfully and reports no findings.
- Given unsupported or malformed input, when the user scans it, then the tool returns a clear error without producing a misleading successful report.

### Plan generation

- Given scan findings, when the user generates a plan, then `mask.yml` contains one entry per detected field with source location, category, reason, selected action, and strategy.
- Given numeric ID columns with no PII evidence, when a plan is generated, then they default to keep rather than mask.
- Given ambiguous findings, when a plan is generated, then the entries require review instead of silently ignoring them.

### Apply masking

- Given a plan and salt, when the user applies masking to SQL or CSV input, then output is written separately from the source by default.
- Given repeated PII values across tables/files, when masking is applied with the same salt and strategy, then repeated originals map to repeated masked values.
- Given the same input, plan, and salt across two runs, when masking is applied, then masked values are stable.
- Given a different salt, when masking is applied, then PII masked values change.
- Given null or empty values, when masking is applied, then they remain null or empty.
- Given numeric IDs marked keep, when masking is applied, then the IDs are unchanged.
- Given an incomplete plan with review/unclassified PII fields, when masking is applied in strict mode, then the command fails with actionable messages.

### CI check

- Given all detected likely PII fields are classified, when CI check runs, then it exits zero.
- Given newly detected likely PII not present in `mask.yml`, when CI check runs, then it exits non-zero and lists the unclassified fields.
- Given a field explicitly marked ignore with reason, when CI check runs, then the field does not fail solely because it matched a heuristic.

### Reporting

- Terminal report must be concise enough for routine use and include counts, high-risk findings, and next-step guidance.
- JSON report must include enough structured data for CI annotations or downstream tooling.
- Reports must not print the full original sensitive values by default; short redacted examples or hashes may be used if needed for evidence.

## 10. Risks and Mitigations

### False negatives: PII is missed

Risk: Rule-based detection may miss unusual column names or data formats.

Mitigations:
- Combine column-name heuristics with sample-value pattern matching.
- Make rules easy to inspect and extend.
- Use CI check to detect newly introduced likely PII over time.
- Avoid claiming complete compliance or perfect detection.

### False positives: useful data is over-masked

Risk: The tool may classify operational columns as PII, reducing fixture usefulness.

Mitigations:
- Generate a reviewable plan instead of applying scan results blindly.
- Support explicit keep/ignore actions with reasons.
- Keep numeric IDs by default unless PII evidence exists.

### Broken relational behavior

Risk: Masking repeated natural-key values inconsistently could break application flows.

Mitigations:
- Require deterministic mapping by original value, salt, and strategy.
- Apply the same mapping across all files/tables in a run.
- Include tests in implementation for cross-table repeated values.

### Sensitive evidence in reports

Risk: Reports could leak PII if they print raw sample values.

Mitigations:
- Redact or hash examples by default.
- Include detection reason without full raw value disclosure.
- Make verbose raw-sample output opt-in only if needed, with clear warning.

### SQL dump parsing complexity

Risk: PostgreSQL dump syntax can be complex, especially COPY blocks, quoted identifiers, encodings, and large files.

Mitigations:
- Define MVP support around common PostgreSQL-style dumps.
- Preserve unsupported sections without mutation where safe, or fail clearly when unsafe.
- Stream processing where possible to avoid loading large dumps entirely into memory.

### Misuse as compliance proof

Risk: Users may treat successful masking as legal compliance certification.

Mitigations:
- Product copy and reports must state that the tool is an engineering safeguard, not a certification.
- Avoid compliance badges or guarantees.

### Salt handling

Risk: Reusing, leaking, or hardcoding salts can weaken masking.

Mitigations:
- Require explicit salt input for apply/check flows that need deterministic comparison.
- Avoid writing the salt into reports or `mask.yml` by default.
- Document expected handling in CLI help text during implementation.

## 11. Open Product Questions for Review

1. Should MVP include built-in fake Indonesian names/addresses, or start with format-preserving deterministic placeholders and add richer locale datasets later?
2. What confidence labels should be exposed: numeric score, `low/medium/high`, or both?
3. Should `mask.yml` require a human-written reason for `ignore` actions in CI mode?
4. How much SQL dump syntax is explicitly supported in MVP: INSERT statements only, COPY blocks, or both?
5. Should CI compare against a committed JSON baseline, `mask.yml` only, or both?
