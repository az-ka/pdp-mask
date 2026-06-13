# pdp-mask Roadmap

## Phase 0: Planning complete

Deliverables:

- Brief.
- PRD.
- Technical spec.
- Architecture.
- Security threat model.
- Roadmap.
- Specialist draft reports.

## Phase 1: CLI skeleton and scan report

Goal: scan SQL/CSV snapshots and produce explainable findings.

Scope:

- CLI command: `pdp-mask scan`.
- CSV adapter with header row.
- PostgreSQL dump COPY-block adapter.
- Column-name detector rules.
- Value-pattern detectors for email, Indonesian phone, NIK-like, NPWP-like, address tokens, DOB context.
- Confidence scoring.
- Terminal report.
- JSON report.

Acceptance:

- Fixture SQL/CSV produces expected high/medium/low findings.
- Default output does not print raw PII values.
- Malformed input fails clearly.

## Phase 2: Plan generation

Goal: convert findings into reviewable policy.

Scope:

- CLI command: `pdp-mask plan`.
- Generate `mask.yml` from scan JSON.
- Preserve existing reviewed decisions.
- Default high-confidence PII to `mask`.
- Default ambiguous findings to `review`.
- Default numeric IDs to `keep`.

Acceptance:

- Plan is stable/diffable.
- Existing user decisions survive regeneration.
- Unresolved review actions are visible.

## Phase 3: Deterministic masking

Goal: produce masked SQL/CSV artifacts safely.

Scope:

- CLI command: `pdp-mask apply`.
- Salt from env var or secret file.
- HMAC-SHA-256 deterministic mapping.
- Masking methods: email, phone, NIK-like, NPWP-like, name placeholder, address placeholder, deterministic digits, date shift.
- Streaming apply.
- Output separate from input.

Acceptance:

- Same salt/input/plan gives same output.
- Different salt changes masked values.
- Repeated natural-key PII maps consistently across files/tables.
- Numeric IDs stay unchanged by default.
- Null/empty values stay unchanged.

## Phase 4: Verify and CI guardrail

Goal: make the tool useful in team workflows.

Scope:

- CLI command: `pdp-mask verify`.
- CLI/CI policy: fail on unresolved review or unclassified high-confidence PII.
- Exit codes.
- Minimal CI-safe output.
- Example GitHub Actions workflow.

Acceptance:

- CI fails when a fixture adds a likely PII column without plan entry.
- CI output avoids raw values and secrets.
- Verification catches obvious missed email/phone/NIK/NPWP patterns in masked output samples.

## Phase 5: OSS hardening

Goal: make contribution and maintenance practical.

Scope:

- Detector pack format.
- Fixture contribution guide.
- Rule versioning.
- Benchmarks for large generated fixtures.
- SARIF output consideration.
- Locale data provenance review.

Acceptance:

- Contributors can add detector rules without touching parser internals.
- Rule changes have fixture tests.
- Docs clearly state limitations and non-compliance guarantees.

## Deferred features

- Local web studio for reviewing plans.
- Live read-only database adapter.
- MySQL dump adapter.
- PDF/Excel/document scanning.
- Local-only AI classifier for free text.
- Database subsetting.
- Cloud storage integrations.

These are intentionally deferred to keep MVP useful and finishable.
