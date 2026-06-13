# OSS positioning draft: pdp-mask

## Evidence snapshot

- Greenmask is an open-source database anonymization and test data management utility for logical dumping, anonymization, synthetic data generation, and restoration; its README lists PostgreSQL as production-ready, MySQL as beta/in progress, database subsetting, S3-compatible storage, deterministic transformations, dynamic parameters, conditional transformations, native database type safety, custom command transformers, and single-binary cross-platform distribution. Source: [Greenmask GitHub README](https://github.com/GreenmaskIO/greenmask) and [Greenmask website](https://www.greenmask.io/).
- PostgreSQL Anonymizer is a PostgreSQL extension for masking or replacing PII and commercially sensitive data. Its documentation emphasizes declarative rules embedded in database DDL/security labels, masking inside PostgreSQL, six masking methods (anonymous dumps, static masking, dynamic masking, replica masking, masking views, masking data wrappers), masking functions, and detection helpers. Source: [PostgreSQL Anonymizer documentation](https://postgresql-anonymizer.readthedocs.io/en/stable/).
- pdp-mask brief: local-first CLI for Indonesian teams; offline rule-based detection; PostgreSQL-style SQL dump and CSV first; Indonesian PII presets; deterministic masking with user-provided salt; keep numeric IDs by default; CI failure when newly detected likely PII is unclassified; no cloud upload and no legal compliance certification claim.

## Positioning against existing OSS

| Axis | Greenmask | PostgreSQL Anonymizer | pdp-mask wedge |
| --- | --- | --- | --- |
| Primary workflow | Dump/transform/restore test data management, especially PostgreSQL, with subsetting and storage integrations. | In-database PostgreSQL masking extension with declarative DDL/security-label policy. | Snapshot-first CLI for teams that receive SQL/CSV exports and need a reviewable masking plan before data leaves production-like custody. |
| Database coupling | PostgreSQL first; MySQL in progress; works as logical dump proxy and restore-compatible utility. | PostgreSQL-only extension installed into the database. | Starts with PostgreSQL-style SQL dumps and CSV files without requiring database extension installation or production database writes. |
| Detection emphasis | Strong transformation engine; less positioned around Indonesia-specific discovery. | Includes detection functions, but within PostgreSQL extension model. | Indonesia-specific PII heuristics out of the box: NIK, NPWP, Indonesian phone formats, addresses, names, dates of birth, bank/account identifiers, plus generic email/phone/date signals. |
| Policy artifact | Config-driven transformation rules. | Rules declared in PostgreSQL schema metadata. | Generated `mask.yml` plus terminal/JSON report designed for code review and CI classification of newly detected likely PII. |
| Trust stance | Broad TDM platform features, including storage options such as S3-compatible targets. | Minimizes exposure by masking inside PostgreSQL. | Local-only by default, no SaaS dependency, no cloud upload, no compliance-certification marketing claim. |

pdp-mask should not try to out-Greenmask Greenmask on mature database subsetting, storage backends, or high-performance dump/restore orchestration. It should not try to out-PostgreSQL-Anonymizer PostgreSQL Anonymizer on in-database masking modes. The credible OSS opening is narrower: "the practical Indonesian PII scanner and deterministic snapshot masker you can run before a dump, CSV, or vendor handoff enters dev/staging/CI."

## Unique Indonesia-focused wedge

1. **Preset value for Indonesian teams on day one.** Make NIK, NPWP, Indonesian mobile/landline formats, common address tokens, local name patterns, dates of birth, and bank/account-like fields first-class detection presets rather than examples users must write themselves.
2. **Reviewable classification before mutation.** The first product moment is not "mask everything"; it is a report and `mask.yml` plan that lets engineering, security, and data owners decide which findings are PII, safe identifiers, join keys, or false positives.
3. **Snapshot-safe adoption path.** Many small teams can run a CLI against SQL dumps and CSVs without asking DBAs to install extensions, granting masked roles, or changing production schemas.
4. **Deterministic relational safety for natural keys.** Keep numeric IDs by default, but deterministically mask emails, phone numbers, NIK/NPWP-like values, and other natural-key PII consistently across tables using a user-provided salt.
5. **CI guardrail, not governance platform.** Fail a pull request or data-refresh job when newly detected likely PII is unclassified. Avoid claiming legal compliance certification; position as an engineering control that supports safer workflows.

## Likely contributors

- **Indonesian backend and data engineers** who maintain Rails/Laravel/Node/Django services and need sanitized local/staging datasets.
- **Security/privacy champions in startups and agencies** who lack budget or appetite for enterprise data masking platforms but can adopt a CLI in CI.
- **QA and analytics engineers** who use production-like SQL/CSV snapshots and can contribute realistic masking recipes, edge cases, and regression fixtures.
- **DBA/SRE practitioners** who understand PostgreSQL dump formats, COPY statements, encodings, schema drift, and relational consistency pitfalls.
- **Civic-tech, fintech, health-tech, ed-tech, HR/payroll, and marketplace developers** because their schemas commonly contain NIK, NPWP, phone, address, account, and family/contact data.
- **Privacy/legal-adjacent technical reviewers** who can improve terminology and risk framing without turning the tool into a legal-compliance oracle.

## Extension points to design early

- **Detector packs:** versioned rule packs for `id_ID` PII categories; allow project-local custom column-name patterns and value regexes without editing core code.
- **Masking functions:** deterministic generators for email, phone, NIK-like placeholder, NPWP-like placeholder, name, address, date shifting, fixed redaction, passthrough, and token hashing.
- **Classifier overrides:** `mask.yml` entries for `mask`, `keep`, `hash`, `redact`, `date_shift`, `ignore_false_positive`, and "requires review" states.
- **Parser/input adapters:** PostgreSQL SQL dump parser first, CSV adapter first, later MySQL dump or live read-only adapters only if they do not compromise local-first behavior.
- **Report sinks:** terminal, JSON, and CI exit codes; later SARIF could help code-scanning integrations without adding SaaS dependency.
- **Salt/key management boundary:** accept salt from CLI/env/file, never persist secrets into generated reports by default, and document reproducibility tradeoffs.
- **Locale data:** names, address tokens, province/city patterns, and bank-code hints should be data files with reviewable provenance rather than hidden constants.

## Maintenance risks

- **PII rule drift.** Indonesian identifiers, phone formats, bank/payment tokens, and schema conventions will change; stale rules create false confidence. Mitigation: small versioned detector packs, changelogged rule changes, and fixture-driven examples.
- **False positive fatigue.** Aggressive heuristics can block CI too often. Mitigation: explicit classification states, stable ignore entries, confidence levels, and reports that explain which signal fired.
- **False negative risk.** A local rule-based tool will miss context-specific PII. Mitigation: be honest in docs and UX: pdp-mask finds likely PII, not all PII, and users remain responsible for review.
- **Determinism vs reversibility confusion.** Salted deterministic masking can preserve joins but may be misunderstood as cryptographic anonymization. Mitigation: avoid compliance-certification language and explain pseudonymization/re-identification risk plainly.
- **SQL dump parsing scope creep.** Full SQL dialect coverage can swallow the project. Mitigation: define supported PostgreSQL dump shapes for MVP, fail closed on unsupported constructs, and keep CSV path strong.
- **Locale data provenance.** Name/address fixture data can itself become sensitive or biased. Mitigation: use synthetic or openly licensed seed data, document source links, and allow downstream replacement.
- **Single-maintainer bus factor.** Security-sensitive tools need careful review. Mitigation: keep architecture boring, rules data-driven, fixtures small, and contribution paths clear for detector packs and adapters.

## Recommended OSS positioning statement

pdp-mask is the local-first, Indonesia-aware PII scanner and deterministic snapshot masker for teams that need safer SQL/CSV data in development, staging, demos, vendor handoffs, and CI. Greenmask proves demand for production-like anonymized test data; PostgreSQL Anonymizer proves the value of deep PostgreSQL-native masking. pdp-mask should win where teams need fast offline adoption, Indonesian PII presets, reviewable masking plans, CSV/dump workflows, and CI guardrails without installing database extensions, uploading data, or claiming legal compliance certification.
