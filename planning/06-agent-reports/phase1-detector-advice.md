# Phase 1 Detector Advice

Scope: CSV scan MVP only. Rules should be conservative, deterministic, explainable, and should report evidence without printing raw PII values.

## Normalization shared by detectors

- Normalize column names by lowercasing and splitting snake_case, kebab-case, spaces, and camelCase.
- Treat empty strings, configured null markers, and whitespace-only cells as non-samples.
- For value regexes, trim cell whitespace before matching.
- For digit identifiers, strip spaces, dashes, dots, slashes, and parentheses only for matching; report the original column name but never the raw value.
- Emit per column: `sampled`, `matched`, `match_ratio`, `category`, `confidence`, and evidence labels such as `column:email`, `value:email_ratio_high`, `negative:numeric_id`.

## Email

Column signals:

- Strong: `email`, `email_address`, `alamat_email`, `e_mail`.
- Weak/contextual: `contact`, `kontak`, `login`, `username`.

Value pattern:

```text
(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$
```

Conservative notes:

- Require at least one dot in the domain and a final alphabetic TLD of 2-24 chars in post-check logic.
- Reject values containing spaces or multiple `@` signs.
- High confidence when a strong email column has any match or when at least 60% of sampled non-empty values match.

## Indonesian phone

Column signals:

- Strong: `phone`, `mobile`, `no_hp`, `nomor_hp`, `telepon`, `telp`, `whatsapp`, `wa`, `ponsel`.
- Weak/contextual: `contact`, `kontak`.

Value handling:

1. Remove spaces, hyphens, dots, parentheses.
2. Accept an optional leading `+` before normalization.
3. Match normalized forms:

```text
^(?:\+?62|0)8[1-9][0-9]{7,10}$
^(?:\+?62|0)(?:21|22|24|31|61|71|274|361|411)[0-9]{5,9}$
```

Conservative notes:

- Mobile numbers are the safest MVP target: `08...`, `628...`, `+628...`, 10-13 national digits after leading `0`, or equivalent country-code length.
- Landlines should be medium unless column context is strong because area-code coverage is incomplete.
- Reject repeated digits and short operational codes.

## NIK-like

Column signals:

- Strong: `nik`, `no_ktp`, `nomor_ktp`, `ktp`, `n_i_k`, `identity_number`, `national_id`.
- Weak/contextual: `id_number`, `nomor_identitas`.

Value pattern:

```text
^[0-9]{16}$
```

Post-checks:

- Reject all same digit, sequential counters, and obvious placeholders such as `0000000000000000`, `1111111111111111`, `1234567890123456`.
- If feasible in Phase 1, validate positions 7-12 as date-like: day `01-31` or female-offset day `41-71`, month `01-12`, year `00-99`.
- Do not require complete province/regency/district tables for MVP; label as `nik_like`, not guaranteed-valid NIK.

Confidence:

- Strong NIK column + plausible 16-digit values: high.
- 16-digit values in generic `id`/`*_id` columns: medium at most, and low/keep if values look like numeric surrogate IDs.

## NPWP-like

Column signals:

- Strong: `npwp`, `no_npwp`, `nomor_npwp`, `tax_id`, `taxpayer_id`.
- Weak/contextual: `pajak`, `tax_number`.

Value handling:

- Strip `.`, `-`, `/`, spaces for matching.
- Accept legacy 15-digit and newer 16-digit numeric forms:

```text
^[0-9]{15,16}$
```

Optional display-shape regex for legacy formatted values:

```text
^[0-9]{2}\.?[0-9]{3}\.?[0-9]{3}\.?[0-9]-?[0-9]{3}\.?[0-9]{3}$
```

Conservative notes:

- Reject repeated digits and obvious placeholders.
- Without NPWP/tax column context, long numeric strings should be medium at most because account numbers and internal IDs overlap.

## Name

Column signals:

- Strong: `nama`, `nama_lengkap`, `full_name`, `first_name`, `last_name`, `customer_name`, `employee_name`, `pemilik`, `ibu_kandung`.
- Weak/contextual: `user`, `author`, `pic`, `kontak`.

Value heuristic:

```text
(?i)^[\p{L}][\p{L}' .-]{1,79}$
```

Post-checks:

- Require mostly letters after removing spaces, apostrophes, dots, and hyphens.
- Reject values containing `@`, URL fragments, mostly digits, JSON-like braces, or long free text.
- Value-only name detection should stay low; high requires strong column context plus a healthy ratio of alphabetic personal-name-like values.

## Address

Column signals:

- Strong: `alamat`, `address`, `street`, `jalan`, `kelurahan`, `kecamatan`, `kabupaten`, `kota`, `provinsi`, `kode_pos`.
- Weak/contextual: `location`, `lokasi`, `domisili`.

Value token regex:

```text
(?i)\b(?:jl\.?|jalan|gg\.?|gang|rt\.?|rw\.?|kel\.?|kelurahan|kec\.?|kecamatan|kab\.?|kabupaten|kota|provinsi|desa|dusun|komplek|blok|no\.?)\b
```

Conservative notes:

- A single token match in a generic text column is medium at most.
- `kode_pos` / postal code is only weak by value: `^[0-9]{5}$`; boost when the column name is address-related.
- High confidence needs strong address column context or repeated address-token matches across samples.

## Date of birth

Column signals:

- Strong: `tanggal_lahir`, `tgl_lahir`, `birth_date`, `date_of_birth`, `dob`, `lahir`.
- Weak/contextual: `birth`, `birthday`.

Value patterns:

```text
^[0-9]{4}-[0-9]{2}-[0-9]{2}$
^[0-9]{2}/[0-9]{2}/[0-9]{4}$
^[0-9]{2}-[0-9]{2}-[0-9]{4}$
```

Post-checks:

- Validate actual calendar dates.
- Prefer plausible human DOB range, e.g. 1900-01-01 through today minus a small child-age allowance, but do not overfit.
- Date values alone should not be high confidence; transaction, creation, and update dates are common non-PII operational fields.

## Numeric ID negative signal

Apply a strong negative signal for columns named exactly or ending with:

- `id`, `_id`, `-id`, `uuid`, `guid`, `count`, `total`, `amount`, `qty`, `status`, `type`, `created_at`, `updated_at`, `deleted_at`.

Keep by default when:

- Values are monotonically increasing integers or UUID-like operational keys.
- The column has no strong PII name signal.
- The only value evidence is generic numeric length.

Override the negative signal only for specific natural-key categories such as strong `nik`, `npwp`, phone, or account-context rules.

## Confidence scoring suggestion

Use a simple capped score per category:

- Strong column match: `+0.55`.
- Weak column/context match: `+0.25`.
- Strong value pattern and `match_ratio >= 0.60`: `+0.55`.
- Strong value pattern and `match_ratio >= 0.20`: `+0.35`.
- Low-but-real value signal: `+0.15`.
- Nearby/cross-column context in the same CSV, such as `nama` plus `nik` plus `alamat`: `+0.10`.
- Operational numeric ID negative signal: `-0.50`.

Caps and bands:

- `high >= 0.80`: report likely PII; recommended future plan action `mask`.
- `medium >= 0.50`: report as review-needed.
- `low < 0.50`: report weak evidence or suppress from default terminal summary unless verbose.
- If `sampled < 3`, cap at medium unless the column name is a strong exact PII match.
- For generic numeric columns, cap at medium unless the category is NIK-like or NPWP-like with strong column context.

Tie-breaking:

- Prefer specific categories over generic ones: `nik_like` over `numeric_id`, `npwp_like` over `long_number`, `email` over `contact`.
- A column may include secondary candidates in JSON, but terminal output should show one primary category plus concise evidence.
