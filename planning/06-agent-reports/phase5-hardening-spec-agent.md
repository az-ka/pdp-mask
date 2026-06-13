# Phase 5 HardeningSpecAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- Specify YAML detector pack format.
- Load custom rules from YAML config.
- Validation at load time (e.g. regex compilation validation).
- Standard rule overrides (allow custom rules with same name to override built-ins).
- Rule versioning schema.
- Data-driven detection loop instead of hardcoded rules.

## Adopted MVP changes

- Active rules migrated to `ActiveRules` slice.
- `internal/detect.LoadRules(path string)` added to read YAML and merge/override `ActiveRules`.
- Custom rule regexes are compiled once at load/compilation time and cached in `regexCache` to prevent performance drops.
- Column matching and value matching loops rewritten to use `ActiveRules` dynamically.
- `--rules` CLI flag added to `scan` and `verify` subcommands to allow custom rule packs.
