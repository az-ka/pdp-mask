# pdp-mask Security and Privacy Threat Model

## Security posture

`pdp-mask` processes sensitive production-like snapshots. Raw inputs may contain regulated personal data. Masked outputs, reports, and plans can still reveal sensitive metadata. The default posture is local-first, offline, non-destructive, and conservative.

## Assets

| Asset | Risk | Protection |
| --- | --- | --- |
| Raw SQL/CSV snapshots | Direct PII exposure | Never upload; do not print raw values; avoid persistent temp copies |
| Masking salt | Correlation/re-identification risk if leaked | Require explicit user source; never log or persist plaintext |
| `mask.yml` | Reveals schema decisions | No raw samples; reviewable but treat as sensitive metadata |
| JSON/terminal reports | CI/log leak risk | Redact/omit raw values by default |
| Masked outputs | Still potentially sensitive | Label as masked, not guaranteed anonymous |
| CI artifacts | Broad retention/sharing | Minimal output; no secrets or samples |

## Threats and mitigations

### Raw input leaks through output/logging

Mitigations:

- Default terminal output shows table/column/category/confidence/counts, not values.
- JSON report contains evidence labels, not raw samples.
- Raw sample display requires explicit unsafe flag in future interactive modes.
- No telemetry, crash uploads, or automatic remote rule fetching.
- Temporary files are deleted on success/failure where possible.

### Network or AI feature regresses local-first design

Mitigations:

- MVP commands perform no network calls.
- Future network features must be opt-in and visibly named.
- AI-assisted detection, if added, must be local-only by default.
- Rule packs ship locally or are loaded from user-provided local paths.

### Salt misuse

Mitigations:

- `apply` requires explicit salt from env var, env-file reference, or secret file.
- No built-in default salt.
- Salt is never stored in `mask.yml`, reports, masked outputs, logs, or errors.
- Warn on empty or obviously weak salt.
- Document that salt rotation changes deterministic outputs.

### Reports and plans leak PII

Mitigations:

- `mask.yml` stores classification and strategy only.
- Reports store counts, categories, confidence, rule IDs, and locations.
- Redacted examples are off by default and never used in CI mode.
- CI output is non-verbose by default.

### False negatives leave PII unmasked

Mitigations:

- Product language says `likely PII`, not complete detection.
- High-risk free-text fields such as `notes`, `description`, `keterangan`, `alamat`, `comment` can default to review when weak signals exist.
- `mask.yml` supports manual classification for missed fields.
- Parse/coverage warnings are surfaced and can fail CI.

### False positives break useful data

Mitigations:

- Scan generates a plan; it does not mutate automatically.
- Numeric IDs are kept by default.
- `keep` and `ignore` require explicit review for ambiguous/high-risk cases.
- Natural-key PII is masked consistently rather than randomly.

### Relational consistency breaks

Mitigations:

- Keep integer primary/foreign keys by default.
- Use shared `consistency_key` namespaces for natural-key PII such as email/NIK/NPWP.
- Test repeated values across tables/files.

### CI leaks secrets or raw data

Mitigations:

- CI mode avoids raw samples.
- Do not print env var values, secret file contents, or command lines with salts.
- Distinct exit codes identify policy failure vs parse/config errors.
- Docs warn that CI reports are sensitive metadata.

## Unsafe defaults to avoid

- Empty/default salt.
- Printing raw samples in normal output.
- Uploading schema, data, or reports.
- Treating clean scan as proof of no PII.
- Overwriting input files.
- Masking live production databases in MVP.
- Enabling AI/network features by default.
- Failing open on parse errors.

## Legal wording boundaries

Allowed wording:

- Helps detect likely PII.
- Generates a reviewable masking plan.
- Applies deterministic masking according to user configuration.
- Supports local-first privacy engineering workflows.

Avoid wording:

- Guarantees anonymization.
- Makes data compliant with UU PDP.
- Removes all personal data.
- Certified compliant.
- Safe to share externally after masking.
- No re-identification risk.

## MVP security checklist

- [ ] Offline by default.
- [ ] No raw values in default outputs.
- [ ] Explicit salt required for masking.
- [ ] Salt never persisted.
- [ ] CI output is minimal.
- [ ] Parse/coverage failures are visible.
- [ ] Plan supports `mask`, `keep`, `ignore`, and `review`.
- [ ] Masked output never overwrites raw input by default.
- [ ] Docs avoid compliance/anonymization guarantees.
