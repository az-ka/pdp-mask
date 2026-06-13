# Phase 2 PlanDXAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- Command: `pdp-mask plan <scan.json> --out mask.yml`.
- `--out` should be explicit for now.
- Terminal output should summarize plan actions and next command.
- Do not include raw evidence/sample values in YAML or terminal output.
- Reject non-CSV reports in Phase 2 if encountered.
- Keep output deterministic and safe for code review.

## Discarded guidance

The agent hallucinated unrelated `q-profiler`, Cobra, and POSIX Make conventions. Those do not apply to `pdp-mask` and were ignored.

## Adopted CLI UX

```bash
pdp-mask scan testdata/customers_pii.csv --json reports/customers.scan.json
pdp-mask plan reports/customers.scan.json --out mask.yml
```

Expected terminal summary:

```txt
pdp-mask plan reports/customers.scan.json

Output   mask.yml
Inputs   1
Findings 7
Actions  mask=6 review=1

Next step
  pdp-mask apply <input> --config mask.yml --out <masked-output>
```

`apply` remains future work.
