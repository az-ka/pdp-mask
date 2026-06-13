# Contributing to pdp-mask

Thank you for your interest in contributing to `pdp-mask`! This project aims to provide local-first, privacy-safe developer tooling for Indonesian teams.

## Contribution Areas

1. **Adding/Improving Detector Rules**: Add or modify rules in a rule pack (like `indonesia`).
2. **Adding Fixtures**: Contribute anonymized/synthetic test fixtures for new scenarios.
3. **Core Scanners/Maskers**: Enhance Go CLI internals for new file formats or masking strategies.

## Dynamic Detector Rule Packs

`pdp-mask` uses data-driven rule packs to discover PII without changing the compiled Go binary. 

You can load a custom rule pack using the `--rules` flag:

```bash
pdp-mask scan data.csv --rules custom_rules.yml
```

### Rule Pack Schema

A rule pack YAML file (version 1) has the following format:

```yaml
version: 1
pack_name: my_custom_pack
rules:
  - name: "custom_identifier"
    category: "quasi_identifier"
    column_patterns: ["secret_code", "sec_id"]
    value_pattern: "^SEC-[0-9]{4}$"
    value_weight: 0.90
    column_weight: 0.70
```

- `name`: Unique name for the rule.
- `category`: Category tag associated with the finding.
- `column_patterns`: Substrings or tokens in the column name to match.
- `value_pattern`: Regular expression matched against sampled values.
- `value_weight`: Score contribution if the value regex matches.
- `column_weight`: Score contribution if the column name matches.

Rules loaded via `--rules` with the same name as built-in rules will override them.

## Adding Fixtures

When contributing test data/fixtures under `testdata/`:

- **Never use real production data**. All fixture values must be generated synthetically.
- Names, emails, phone numbers, NIKs, and NPWPs must be completely fictional.
- Document any new fixture in the corresponding test file or a `README.md` inside `testdata/`.

## Limitations and Disclaimers

`pdp-mask` is a helpful utility, but it comes with strict limitations:

- **No Compliance Guarantees**: Using this tool does not guarantee compliance with the Indonesian PDP Law (UU No. 27 Tahun 2022) or any other data protection regulation.
- **Explainable Heuristics**: The scanner uses rule-based heuristics and regexes. It can miss PII (false negatives) or flag non-PII columns (false positives). Always review the generated `mask.yml` file.
- **Not a Cryptographic Guarantee**: Masked data produced by `apply` uses HMAC-SHA-256 with a salt. While it prevents direct identification, sophisticated re-identification attacks (e.g., matching with external datasets) may still be possible.
