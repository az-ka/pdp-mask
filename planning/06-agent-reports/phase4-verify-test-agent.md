# Phase 4 VerifyTestAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- Test verify passes on clean round-trip.
- Test verify fails on unresolved review action.
- Test verify fails on unclassified high PII in input.
- Test verify fails on leakage (manually crafted raw value in safe CSV).
- Test verify fails on shape mismatch (row count, column headers).
- Test verify fails on high-confidence kept column.
- CI pipeline: scan -> plan -> apply -> verify.

## Implemented test cases

- `internal/verify` unit tests:
  - clean round-trip verification
  - fails on unresolved review action
  - fails on unclassified high PII
  - fails on output leakage
  - fails on header count/names mismatch
  - fails on high confidence keep override
- `cmd/pdp-mask` CLI integration tests:
  - run verify passes on valid inputs/output
  - run verify fails with code 3 on review plan
  - run verify fails with code 4 on shape mismatch
- GitHub Actions workflow (`.github/workflows/ci.yml`):
  - runs unit tests
  - runs scan, plan, apply, and verify pipeline on customers_pii fixture.
