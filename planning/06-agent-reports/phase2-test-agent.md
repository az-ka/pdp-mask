# Phase 2 PlanTestAgent

Model requested: `tokenrouter/MiniMax-M3` via explicit `agent(..., model=...)`.

## Useful guidance kept

- Add unit tests for pure plan generation.
- Add CLI smoke tests through existing command parsing where practical.
- Assert behavior, not cosmetic YAML whitespace.
- Assert no raw fixture values appear in generated YAML.
- Assert deterministic output for the same scan report.
- Assert invalid JSON and missing args fail clearly.

## Phase 2 tests to implement

1. `TestGeneratePlanFromScanReport`
   - high confidence email/phone/NIK/NPWP/address/DOB => `mask`
   - medium confidence name => `review`
   - strategy is populated for masked/review PII
   - counts are correct

2. `TestGeneratePlanDoesNotLeakRawValues`
   - generated YAML must not contain fixture emails, phones, NIKs, NPWPs, names, addresses, or DOBs.

3. `TestGeneratePlanDeterministic`
   - same report generates byte-identical YAML.

4. `TestRunPlanWritesFile`
   - `pdp-mask plan scan.json --out mask.yml` writes a plan file.

5. `TestPlanRejectsInvalidJSON`
   - invalid JSON returns an error and does not write output.

## Deferred

- Golden tests for exact YAML shape.
- Overwrite/force behavior.
- Multi-input conflict policy.
- Stdin support.
