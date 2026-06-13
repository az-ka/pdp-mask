# Phase 3 ApplyTestAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- Test deterministic output for same salt/input/plan.
- Test different salt changes masked output.
- Test duplicate original values map to duplicate masked values.
- Test empty targeted values remain empty.
- Test non-targeted columns are preserved.
- Test CLI requires salt and refuses existing output.
- Test unresolved `review` actions block apply.
- Test generated output does not contain raw PII fixture values.

## Implemented test coverage

- `internal/apply` package tests:
  - deterministic and consistent CSV masking
  - different salts change output
  - review actions block apply
  - short salt fails
- `cmd/pdp-mask` tests:
  - apply writes masked CSV
  - missing salt fails without output
  - existing output fails without `--force`

## Deferred

- Golden output fixtures.
- Large-file streaming benchmark.
- Symlink/hardlink overwrite tests.
- JSON apply report leak tests.
