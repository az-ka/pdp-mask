# Phase 4 VerifySpecAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- Command: `pdp-mask verify <input.csv> --config mask.yml --out safe.csv`.
- Checks:
  - Plan completeness (fail if any unresolved `review` actions).
  - Input coverage (fail if any high/medium confidence PII in input is not classified in plan).
  - Output leakage (fail if any masked column still triggers high confidence PII in output).
- Artifact shape verification (headers, column count, row count).
- Zero-leak/no-raw-PII verification report.
- Exit codes:
  - `0`: success
  - `1`: usage/config error
  - `2`: parse/input error
  - `3`: policy failure
  - `4`: artifact shape/identity mismatch

## Adopted MVP check logic

- Checking unresolved reviews: returns exit code 3.
- Checking unclassified input columns: returns exit code 3.
- Verification checks for output:
  - If a column triggers high-confidence PII, verify that it was masked and its values are indeed masked placeholders (e.g., `user_...@example.invalid` or `081...`). If they are not placeholders, treat as a leak and fail with exit code 3.
  - If headers do not match: returns exit code 4.
  - If row counts do not match: returns exit code 4.
  - If a masked column's output is byte-identical to input (no-op apply): returns exit code 4.
- Output leakage checks run offline, do not require or load salt, and perform no database writes.
- Exit codes mapped correctly using the custom `CLIError` type.
