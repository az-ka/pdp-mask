# pdp-mask PRD

## Summary

`pdp-mask` is a local-first open-source CLI for Indonesian teams that need production-like SQL/CSV snapshots without exposing personal data in local, staging, demo, CI, or vendor workflows.

The MVP scans PostgreSQL-style SQL dumps and CSV files, detects likely PII with deterministic rules, generates a reviewable `mask.yml`, applies deterministic masking with a user-provided salt, preserves relational consistency, and supports CI checks for unclassified likely PII.

## Problem

Developers and QA teams often need realistic data to reproduce bugs, validate migrations, test reports, and prepare demos. Raw production snapshots can contain names, email addresses, phone numbers, addresses, NIK, NPWP, dates of birth, bank identifiers, and other personal data. Copying those snapshots into laptops, staging, CI artifacts, or vendor environments expands leak risk.

## Target users

- Backend engineers debugging production-like issues.
- QA/test engineers preparing realistic staging or demo datasets.
- DevOps/platform engineers adding CI guardrails around fixtures and dump handling.
- Security-minded engineering leads reviewing data-sharing workflows.
- Secondary: data analysts, OSS maintainers, and implementation vendors receiving sanitized fixtures.

## Core use cases

1. Scan a SQL dump or CSV for likely Indonesian PII.
2. Generate a reviewable masking plan.
3. Apply deterministic masking to produce a safe local/staging artifact.
4. Preserve repeated natural-key PII consistently across files/tables.
5. Fail CI when likely PII is newly detected but not classified.

## MVP scope

### Inputs

- PostgreSQL-style plain SQL dump.
- CSV with header row.
- Local files only.

### Detection

- Column-name heuristics.
- Sample-value pattern matching.
- Indonesian presets: NIK-like values, NPWP-like values, Indonesian phone numbers, address terms, DOB fields, bank/account-like fields where context supports it.
- Generic PII: email, phone, name, address, date of birth.
- Confidence band: `low`, `medium`, `high` with evidence reasons.

### Planning

Generate `mask.yml` with explicit decisions:

- `mask`: replace values.
- `keep`: preserve values, usually numeric IDs and operational fields.
- `ignore`: reviewed false positive.
- `review`: human decision required before strict apply/CI success.

Numeric surrogate IDs default to `keep` unless strong PII evidence exists.

### Masking

- User-provided salt required for `apply`.
- Same original value + same salt + same strategy => same masked value.
- Different salt => different masked value.
- Empty string and SQL `NULL` stay unchanged.
- Output is written separately; no in-place overwrite in MVP.
- No production database writes.

### Outputs

- Terminal report.
- JSON report.
- `mask.yml`.
- Masked SQL/CSV artifact.
- CI-compatible exit codes.

## Non-goals

- No SaaS upload.
- No legal compliance certification claim.
- No AI-first detection.
- No live production database mutation.
- No web dashboard before CLI workflow is stable.
- No promise of perfect anonymization or complete PII discovery.
- No broad data-governance platform.

## Success metrics

- New user can scan a SQL/CSV snapshot and understand findings from terminal output.
- Generated `mask.yml` is reviewable in a pull request.
- Repeated PII values stay consistent after masking.
- Numeric IDs and joins still work by default.
- CI fails on newly detected unclassified high-confidence PII.
- Reports avoid raw value disclosure by default.

## Acceptance criteria

### Scan

- Reports category, confidence, and evidence for likely PII.
- Evaluates both headers/column names and sampled values.
- Handles no-finding input successfully.
- Fails clearly on unsupported or malformed input.

### Plan

- Creates one entry per detected field.
- Keeps numeric ID columns by default.
- Marks ambiguous findings as `review`.
- Preserves user edits when regenerating a plan.

### Apply

- Requires plan and salt.
- Writes output separately from source.
- Maps repeated original values to repeated masked values.
- Produces stable output for same salt/plan/input.
- Blocks unresolved `review` actions in strict mode.

### CI/check

- Exits zero when all likely PII is classified.
- Exits non-zero when high-confidence PII lacks a plan decision.
- Does not print raw sensitive values in normal CI mode.

## Key risks

- False negatives: rules miss PII. Mitigation: explainable rules, review states, extensible presets, no compliance overclaim.
- False positives: useful data over-masked. Mitigation: reviewable plan, `keep`/`ignore`, numeric IDs kept by default.
- Broken joins: natural-key PII masked inconsistently. Mitigation: deterministic mapping by category + consistency namespace + salt.
- Report leakage: raw samples appear in logs. Mitigation: redact/omit raw values by default.
- SQL parsing scope creep. Mitigation: explicitly support common PostgreSQL dump shapes first and fail closed when unsafe.
