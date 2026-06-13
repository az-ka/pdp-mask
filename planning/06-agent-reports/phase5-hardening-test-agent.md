# Phase 5 HardeningTestAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- Test loading of custom rule packs.
- Test custom rule matching (column signals and value pattern matching).
- Performance benchmarks on large datasets (10k+ rows).
- Ensure no raw PII in benchmark values or test logs.
- Document limitations and contribution rules.

## Implemented tests and docs

- `internal/detect/detect_test.go`:
  - Test custom rules YAML parsing.
  - Test custom rule insertion/override.
  - Test custom regex compilation and matching.
- `internal/scan/benchmark_test.go`:
  - `BenchmarkScanCSV_10k_Rows` generates a 10,000 row CSV fixture dynamically in a temp directory and scans it.
  - Performance measured at ~5.5 ms per 10k rows on test CPU.
- `CONTRIBUTING.md`:
  - Custom rules schema and format details.
  - Guidelines for synthetic test fixtures.
  - Limitations and PDP compliance disclaimers.
