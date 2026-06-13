# pdp-mask Architecture

## System shape

`pdp-mask` is a single local CLI with modular internals:

```txt
CLI
  -> input adapter
  -> structure extractor
  -> sampler
  -> detector engine
  -> report writer
  -> plan generator
  -> masking engine
  -> verifier
```

No server is required for MVP. A local web studio can be added later only after CLI contracts are stable.

## Components

### CLI layer

Commands:

- `scan`: inspect input and write report.
- `plan`: generate/update `mask.yml`.
- `apply`: mask input into a new output file.
- `verify`: validate masked artifact and unresolved decisions.

Responsibilities:

- Parse flags.
- Resolve input/output paths.
- Load config/plan.
- Map errors to exit codes.
- Keep default output concise and non-sensitive.

### Input adapters

MVP adapters:

- `postgres_dump`
- `csv`

Each adapter provides:

- structure metadata: table/file, columns, row counts where available.
- streaming records for sampling/apply.
- diagnostics with line/row/column context.
- pass-through support for unsupported non-data sections when safe.

### Detector engine

Pure deterministic rules:

- column-name rules.
- value-pattern rules.
- confidence scoring.
- evidence labels.

Detector packs are data-driven so contributors can add Indonesian terms, identifier patterns, and project-local rules without changing core parser code.

### Plan generator

Inputs:

- scan JSON.
- optional existing `mask.yml`.

Outputs:

- stable, diffable `mask.yml`.

Rules:

- preserve user-reviewed decisions.
- add new findings.
- default numeric IDs to `keep`.
- default high-confidence PII to `mask`.
- default ambiguous findings to `review`.

### Masking engine

Inputs:

- source file(s).
- `mask.yml`.
- salt from env/file/secret input.

Behavior:

- stream records.
- apply methods only to targeted fields.
- use HMAC-derived deterministic values.
- preserve null/empty.
- keep non-targeted fields unchanged.
- write separate output.

### Verifier

Checks:

- unresolved `review` entries.
- output file exists and parses under supported adapter.
- row/column counts match where measurable.
- sampled masked output does not match high-confidence source PII rules for masked columns.
- kept relationship columns remain present.

## Data flow

### Scan

```txt
input file
  -> adapter extracts structure
  -> sampler collects bounded samples
  -> detector engine scores columns
  -> terminal report + scan.json
```

### Plan

```txt
scan.json + existing mask.yml?
  -> merge reviewed decisions
  -> add new findings
  -> write mask.yml
```

### Apply

```txt
input file + mask.yml + salt
  -> validate plan
  -> stream input records
  -> deterministic masks for selected fields
  -> temp output
  -> rename to final output
```

### Verify

```txt
masked output + mask.yml + optional source scan
  -> parse shape
  -> check unresolved decisions
  -> sample output
  -> fail/pass report
```

## Extension boundaries

Design early, implement only what MVP needs:

- detector packs: versioned PII rules.
- masking methods: deterministic generators.
- input adapters: PostgreSQL dump and CSV first.
- report sinks: terminal and JSON first; SARIF later.
- locale data: synthetic or openly licensed Indonesian-friendly lists.

## Safety invariants

- No network calls in MVP commands.
- No raw values in default logs/reports.
- No source overwrite by default.
- No built-in default salt.
- No production DB mutation.
- Parse/coverage failures are visible; CI fails closed when coverage is uncertain.

## Future architecture options

Not MVP:

- Local `pdp-mask studio` web UI for plan review.
- SARIF output for code scanning integrations.
- Live read-only database adapter.
- MySQL dump adapter.
- Local-only AI-assisted classifier for free text.
