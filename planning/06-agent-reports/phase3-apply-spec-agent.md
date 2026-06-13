# Phase 3 ApplySpecAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- Command shape: `pdp-mask apply <input.csv> --config mask.yml --out safe.csv`.
- Salt is required and should come from environment or a salt file, not a built-in default.
- Apply must refuse unresolved review actions.
- Apply must not overwrite the source file.
- Masking should use HMAC-SHA-256 with the user salt.
- Empty values must stay empty.
- Output and errors should avoid raw PII values.

## Adopted MVP behavior

- Salt resolution:
  - `--salt-file` if provided.
  - otherwise environment variable named by `--salt-env`, default `PDP_MASK_SALT`.
- Minimum salt length: 16 bytes.
- CSV only.
- Non-targeted columns are passed through as CSV values.
- Strategies implemented:
  - `deterministic_email`
  - `deterministic_phone_id`
  - `deterministic_nik`
  - `deterministic_npwp`
  - `deterministic_name_id`
  - `deterministic_address_id`
  - `date_shift`
  - `deterministic_digits`

## Deferred

- JSON apply report.
- Salt file permission checks on Windows.
- Symlink/hardlink overwrite hardening.
- Configurable CSV delimiter/null sentinels.
- SQL apply.
