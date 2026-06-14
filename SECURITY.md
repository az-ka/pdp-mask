# Security Policy

This document describes the threat model, operational practices, and security
boundaries of `pdp-mask`. Read this before using the tool with real data.

## What `pdp-mask` does

`pdp-mask` replaces PII (Personally Identifiable Information) values in a CSV
file with deterministic, salted placeholders. Given the same input, salt, and
plan, the output is reproducible. Given only the output, the input is not
recoverable without the salt.

## What `pdp-mask` is NOT

- **Not a database anonymizer.** It works on CSV files only.
- **Not irreversible.** Anyone with the salt + masked data + plan can recompute
  the masked values for any guessed input. This is **pseudonymization**, not
  anonymization.
- **Not compliant with regulations on its own.** Using `pdp-mask` does not, by
  itself, satisfy GDPR, UU PDP, PCI-DSS, or HIPAA. The surrounding process
  (salt handling, access control, audit) must be in place.
- **Not a substitute for access control on production data.** A developer who
  has read access to the production database does not need `pdp-mask` to
  exfiltrate data.

## Threat model

### Assumed environment

A small team (≤ 50 developers) that needs to share realistic-looking data
samples from a production database with developers, vendors, or CI systems,
without exposing PII.

### Adversary capabilities

The model assumes:

- Adversaries may obtain masked CSV outputs.
- Adversaries may attempt to **guess** some original PII values (e.g., a
  publicly known NIK belonging to a public figure, an email address from a
  public website).
- Adversaries may attempt to obtain the **salt** through vault compromise,
  insider access, or accidental exposure (e.g., committed `.env` file).
- Adversaries **do not** have direct access to production databases or
  network traffic.

### Out-of-scope threats

The following are **not** addressed by `pdp-mask`:

- Adversaries with direct access to production data.
- Side-channel attacks on the running masking process (memory dumps, etc.).
- Adversaries with the salt (the salt is the secret; if compromised, the
  masked data is effectively cleartext for guessed values).
- Adversaries who can run `pdp-mask` with arbitrary inputs against your salt
  (they would be insiders with explicit access).
- Network-level attacks on the host running `pdp-mask`.

## Salt management

The salt is the entire security boundary. **Anyone with the salt can
reconstruct the mapping for any guessed input.**

### Generation

Generate a fresh salt per environment and per project:

```bash
openssl rand -hex 32
```

This produces 32 bytes (64 hex characters) of entropy from
`/dev/urandom`. **Do not** use a human-chosen passphrase.

### Storage

- **Store in a secret manager** (HashiCorp Vault, 1Password, AWS Secrets
  Manager, GCP Secret Manager, Azure Key Vault). Do not commit salt files
  to version control. Do not put salt in `.env` files that are not
  excluded from git.
- **Restrict ACL** to the smallest set of operators who need to run the
  masking pipeline. Use audit logging on every read.
- **Never log the salt.** `pdp-mask` does not log salt values; verify
  this with `PDP_MASK_SALT=$(openssl rand -hex 32) pdp-mask apply ...` and
  inspect the output for any salt echo.

### Rotation

Rotate the salt:

- Every **90 days** as a baseline.
- Immediately on **any** suspected compromise (insider departure, lost
  laptop, vault access anomaly).
- When the project's data scope changes (e.g., a new table added that
  warrants re-masking).

Maintain a **16-day overlap window** during rotation:

1. Generate new salt at T-16d, store alongside the old.
2. Re-mask all in-use outputs by T-0d (the rotation date).
3. Destroy the old salt at T+0d.

When a salt is rotated, all previously masked CSVs **must be re-masked**
with the new salt. Old masked CSVs become incompatible with the new salt
and may fail `pdp-mask verify`; this is intentional.

### Departure

When a team member with salt access leaves:

1. Treat the salt as compromised the moment the offboarding process opens.
2. Generate a new salt within 1 hour. Store as a new vault item.
3. Revoke the departing member's vault ACL.
4. Re-mask all in-use outputs within 24 hours.
5. Maintain a 7-day observation window for any unexpected use of the old
   salt ID.
6. Destroy the old salt at T+7d.

## Output handling

Masked CSV outputs are **still sensitive**. The mapping is reversible to
anyone with the salt, and re-identification is possible by correlating
masked values with external data sources.

- **File permissions:** `pdp-mask` writes outputs with mode `0600`
  (owner read/write only). Do not loosen this. `pdp-mask` will refuse to
  read salt files with group/other bits set.
- **Transport:** Use encrypted channels (TLS, SSH) to move masked files.
  Do not email masked files as attachments without encryption.
- **Storage:** Store masked files in access-controlled locations. Do not
  put them in shared cloud drives without ACL.

## Audit trail

`pdp-mask` does not currently maintain a built-in audit log. Operators
should maintain an external record of:

- Who ran the masking pipeline.
- Which input file was masked (filename and SHA-256).
- Which plan was used (filename and SHA-256).
- Which salt version was used (salt ID, not salt bytes).
- When the run occurred (UTC timestamp).
- Where the output was written.

A future version of `pdp-mask` will write a `.meta.json` sidecar next to
the masked output containing the input SHA, plan SHA, salt ID, and
timestamp. Until then, capture this metadata externally.

## Reporting a vulnerability

If you find a security issue in `pdp-mask`, please email the maintainer
directly rather than opening a public issue. Include:

- Description of the vulnerability.
- Steps to reproduce.
- Potential impact.

Allow 90 days for a fix before public disclosure.

## Cryptographic details

- **Primitive:** HMAC-SHA-256, 32-byte (256-bit) salt.
- **Key derivation:** None. The salt is used directly as the HMAC key.
- **Domain separation:** A `0x1F` (unit-separator) byte is inserted
  between the strategy name, column name, and value in the HMAC input.
  This prevents ambiguity attacks (e.g., a value `a` in column `bc`
  under strategy `def` cannot be confused with a value `bc` in column
  `a` under strategy `def`).
- **Keyspace limits:** Some strategies (notably
  `deterministic_address_id`, `deterministic_name_id`) have output
  keyspaces smaller than the input keyspace. For `name_id` the
  effective output space is 4096 (64 first names × 64 last names);
  for `address_id` it is ~4.3 billion (65,536²). Re-identification by
  brute force is feasible for the smaller keyspaces if the
  attacker has the salt and a guess of the original. Do not rely on
  `pdp-mask` for data that must resist a determined adversary with
  the salt.

## Re-identification risk

Even with a strong salt and large keyspaces, masked data is
**pseudonymized, not anonymized**. Common re-identification vectors:

- **Direct match:** If the attacker knows the original NIK of a
  person, they can compute the masked NIK and look for it in the
  masked dataset.
- **Quasi-identifier join:** Combining masked quasi-identifiers (e.g.,
  date of birth + postal code) with external public datasets can
  re-identify individuals.
- **Auxiliary data:** If the attacker has any other dataset that
  includes the same individuals, joins can re-identify.

To mitigate, generalize values further (e.g., year of birth only,
province instead of postal code) and document the re-identification
risk for each masked column in the plan.
