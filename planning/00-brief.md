# pdp-mask Brief

## One-line pitch

`pdp-mask` is a local-first CLI that helps Indonesian development teams find and mask personal data in SQL/CSV snapshots before using them in local, staging, demo, or vendor workflows.

## Problem

Teams often need production-like data to debug bugs, test migrations, validate reports, or reproduce edge cases. Copying raw production snapshots into developer laptops or staging systems exposes personal data such as names, email addresses, phone numbers, addresses, NIK, NPWP, dates of birth, and bank identifiers.

## Decision

Start as a CLI developer tool, not a SaaS product and not a web app. The MVP must run offline, use deterministic rule-based detection, and produce reviewable reports and masking plans. AI is optional later and must be local-only.

## MVP defaults

- Inputs: PostgreSQL-style SQL dump and CSV.
- Detection: column-name heuristics plus sample-value pattern matching.
- Scope: Indonesian PII presets plus generic email/phone/date/address/name signals.
- Masking: deterministic fake values using a user-provided salt.
- Relational safety: keep numeric IDs by default; mask natural-key PII consistently across tables.
- Outputs: terminal report, JSON report, generated `mask.yml`, masked SQL/CSV.
- CI: fail when newly detected likely PII is unclassified.

## Non-goals

- No legal compliance certification claim.
- No cloud upload.
- No production database writes in MVP.
- No generic data platform.
- No AI-first detection.
- No web dashboard until the CLI workflow is stable.

## External context

- Indonesian privacy context: UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi.
- Existing category proof: Greenmask and PostgreSQL Anonymizer show practical demand for database anonymization, but `pdp-mask` focuses on Indonesian PII detection, SQL/CSV snapshot workflow, and small-team DX.
