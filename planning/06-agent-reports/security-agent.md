# Security and Privacy Threat Model Draft

## Scope and security posture

`pdp-mask` handles sensitive production-like snapshots and must be designed as a local-first privacy tool. The default threat posture is: raw input may contain regulated personal data; masked output may still be sensitive until reviewed; reports and plans can leak schema and sampled PII if not constrained.

MVP boundaries from the project brief:

- CLI-first, offline by default.
- PostgreSQL SQL dump and CSV input first.
- Rule-based detection first; AI only later and local-only.
- Deterministic masking with a user-provided salt.
- Numeric IDs are preserved by default; natural-key PII is masked consistently.
- No cloud upload, no production database writes, and no legal compliance certification claim.

## Assets to protect

| Asset | Why it matters | Required protection |
| --- | --- | --- |
| Raw SQL/CSV snapshots | Likely contain names, emails, phones, NIK, NPWP, addresses, dates of birth, bank identifiers, and business-sensitive records. | Never upload; read locally; avoid unnecessary copies; do not print raw values. |
| Masking salt / secret material | Enables deterministic remapping; if reused or leaked, masked values can be correlated across runs or environments. | Require explicit user input or environment source; never persist by default; never log; support rotation. |
| Generated `mask.yml` | Encodes classification decisions and may reveal sensitive schema semantics. | Write with conservative file permissions where possible; avoid embedding raw samples; mark as sensitive artifact. |
| Terminal and JSON reports | Useful for review and CI, but may leak examples and table/column names. | Redact samples by default; include counts, classes, confidence, and decisions rather than values. |
| Masked SQL/CSV outputs | Safer than raw inputs but not guaranteed anonymous. | Label as masked, not anonymized/compliant; preserve deterministic consistency without exposing original values. |
| CI logs and artifacts | Commonly retained and shared beyond the immediate team. | CI mode must emit minimal, non-PII summaries and avoid storing raw inputs or verbose traces. |

## Primary threat scenarios and mitigations

### 1. Raw input exposure during scan

**Threat:** The tool reads SQL/CSV snapshots that contain real personal data. Accidental terminal output, debug traces, temp files, panic dumps, or crash reports could leak raw records.

**Mitigations:**

- Default logs must never include raw cell values, SQL literals, or row payloads.
- Terminal output should show table/column names, detector names, counts, confidence, and action status; sample values must be redacted or omitted by default.
- JSON reports should use bounded metadata: column name, inferred category, confidence, evidence type, row count/sample count, and classification state.
- If examples are ever needed for interactive review, require an explicit unsafe flag such as `--show-samples`, redact by default, and document that it is inappropriate for CI.
- Avoid persistent temp files. If unavoidable, place them under a tool-owned temp directory, use restrictive permissions where supported, and delete them on success and failure.
- Do not add automatic telemetry, crash uploading, analytics, update checks, or remote rule fetching.

### 2. Local-only operation regression

**Threat:** Future convenience features introduce SaaS dependencies, remote AI calls, remote rule downloads, or online update checks that transmit schema or samples.

**Mitigations:**

- Treat offline operation as a product invariant, not only an MVP feature.
- Default network behavior must be none. Any future networked feature must be opt-in, visibly named, and disabled in CI unless explicitly configured.
- AI-assisted detection, if added later, must run against local models only and must receive redacted or bounded context unless the user explicitly chooses otherwise.
- Rule packs should ship with the binary/package or be loaded from user-provided local files; no silent remote fetching.
- Add design wording that `pdp-mask` is a CLI tool, not a hosted processor of user data.

### 3. Salt and deterministic masking misuse

**Threat:** Deterministic masking needs a salt to preserve relationships. Weak, reused, logged, committed, or default salts can make outputs linkable across datasets and teams.

**Mitigations:**

- Require a user-provided salt for masking; detection/report-only mode may run without it.
- Never provide a built-in production default salt such as `changeme`, `pdp-mask`, or an empty string.
- Accept salt through a safer channel such as environment variable or secret file path, not only CLI arguments that may appear in shell history/process lists.
- Never write the salt into `mask.yml`, reports, masked outputs, logs, or error messages.
- In CI documentation, recommend storing the salt in the CI secret manager and using separate salts per project/environment.
- Warn when a salt is obviously weak or from an unsafe example value.
- Document that rotating a salt changes deterministic outputs and may break comparisons with older masked datasets.

### 4. Reports and generated plans leaking PII

**Threat:** Reports and `mask.yml` are intended for review, PRs, and CI artifacts. They can become a secondary leak if they contain raw samples or overly specific values.

**Mitigations:**

- Generated `mask.yml` should contain classification decisions and masking strategies, not copied sample data.
- Reports should include evidence labels such as `column_name_match: email` or `sample_pattern_match: nik`, not the matching value.
- For false-positive review, provide stable row/column location references only when safe, and avoid row contents.
- Redaction should preserve debugging utility without exposing values, for example `jo***@example.test`, `08********12`, or preferably category-only in CI.
- Mark JSON report schema fields that may contain schema names as non-secret but potentially sensitive.
- Keep verbose report mode separate from CI mode.

### 5. False negatives: PII left unmasked

**Threat:** Rule-based detection can miss personal data in unexpected columns, free text, local abbreviations, mixed-language fields, or non-standard formats. Masked output may still contain real PII.

**Mitigations:**

- Use conservative language: `likely PII`, `detected`, `masked according to plan`; never claim complete anonymization.
- CI should fail when newly detected likely PII is unclassified, but should not claim that passing means the dataset is safe or legally compliant.
- Provide an explicit manual override path in `mask.yml` so teams can classify columns the rules missed.
- Include an `unknown` or `needs_review` state for suspicious columns rather than silently treating them as safe.
- Consider high-risk free-text columns (`notes`, `description`, `alamat`, `keterangan`, `comment`) as review candidates even when patterns are weak.
- Report coverage: scanned files/tables/columns, skipped columns, parse errors, unsupported statements, and rows sampled. Unknown coverage is a security risk.

### 6. False positives: useful data over-masked or broken

**Threat:** Aggressive detection can mask non-PII business values, break tests, alter analytics, or damage relational consistency.

**Mitigations:**

- Generate a reviewable plan before applying masks.
- Keep numeric IDs by default as stated in the brief; do not infer every identifier is PII.
- Separate natural-key PII from surrogate IDs so emails, phones, NIK, NPWP, and names can be masked while internal numeric keys remain stable.
- Allow explicit `ignore`/`safe` classifications with reviewer intent captured in `mask.yml`.
- Prefer deterministic format-preserving masks where useful for application validation, while still avoiding reversible transforms.
- Report potentially destructive transformations before writing output.

### 7. CI usage leaks and unsafe automation

**Threat:** CI runs can expose file paths, schema, report artifacts, or secrets to broad audiences. A failing CI check can tempt teams to commit salts or raw snapshots for debugging.

**Mitigations:**

- CI mode should default to non-verbose, no samples, no raw values, and no salt echo.
- CI should accept input paths from the repository workspace but should not require raw production snapshots to be committed.
- Recommended CI pattern: run detection against sanitized fixtures or controlled snapshots, fail on newly detected unclassified likely PII, and publish only minimal JSON summaries.
- Exit codes should distinguish: detected unclassified likely PII, parse/coverage failure, config error, and internal error.
- Do not print environment variable values, resolved secret file contents, or command invocations containing secrets.
- Document that reports may be retained by CI providers and should be treated as sensitive metadata.

### 8. Unsafe defaults to avoid

Avoid these defaults even if they simplify demos:

- Built-in salt, empty salt, or silently generated salt saved next to outputs.
- Printing sample values in normal or CI output.
- Uploading data, schema, reports, or detector telemetry.
- Treating a clean scan as proof of no PII.
- Overwriting input files in place.
- Writing masked output to the same path as raw input.
- Masking production databases directly in MVP.
- Enabling AI or network features by default.
- Committing generated reports or plans that include raw examples.
- Using reversible encryption/tokenization and calling it masking unless key management is explicitly designed.
- Failing open when parsing errors or unsupported SQL constructs are encountered.

## Legal and product wording boundaries

`pdp-mask` should help teams reduce privacy risk, but the product must avoid legal overclaiming.

Recommended wording:

- "Helps detect likely PII in SQL/CSV snapshots."
- "Generates a reviewable masking plan."
- "Applies deterministic masking according to user configuration."
- "Designed for local-first workflows and CI checks."
- "Can support privacy engineering work under Indonesian PDP-aware processes."

Avoid wording:

- "Makes data compliant with UU PDP."
- "Guarantees anonymization."
- "Removes all personal data."
- "Certified compliant."
- "Safe to share externally after masking."
- "No risk of re-identification."

Include a standing disclaimer in docs/reports: masking quality depends on input structure, configured rules, salt handling, and human review; legal compliance requires organizational controls and legal review beyond this tool.

## MVP security requirements checklist

- [ ] Offline by default; no network calls in scan, plan, mask, or CI modes.
- [ ] No raw values in default terminal output, JSON reports, logs, or generated `mask.yml`.
- [ ] Explicit salt required for masking; no built-in default salt.
- [ ] Salt accepted through environment variable or secret file path and never persisted in outputs.
- [ ] CI mode is minimal and non-verbose by default.
- [ ] Parse/coverage failures are visible and fail closed for masking/CI decisions.
- [ ] Generated plans support manual `mask`, `ignore/safe`, and `needs_review` states.
- [ ] Masked output never overwrites raw input by default.
- [ ] Reports distinguish detected likely PII from proven absence of PII.
- [ ] Product/docs avoid compliance certification or anonymization guarantees.
