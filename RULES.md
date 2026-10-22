# Discovery Classification and Masking Rules

This document records the implemented rules in `connector.py`, `classifier.py`, `masker.py`, `risk.py`, `secret_store.py`, and the API routes. It describes current behavior and deliberate trade-offs, not a guarantee of detecting all personal data. Setup and operational commands are in [README.md](README.md).

## 1. Source registration and credential storage

1. Strip surrounding whitespace from the submitted DSN.
2. Replace a leading `postgres://` or `postgresql://` with `postgresql+psycopg://`.
3. Parse the URL with SQLAlchemy and require the driver name to equal `postgresql+psycopg`.
4. Open the target using read-only transaction defaults, a connection timeout, and a statement timeout; execute `SELECT 1`.
5. Dispose of the verification connection pool.
6. Write the complete DSN to OpenBao KV v2 at `discovery/data/sources/<uuid>`.
7. Save the source name and secret path in the service database, returning only the source identity and timestamps.

OpenBao writes use `{"data": {"dsn": "..."}}`; reads retrieve `response.data.data.dsn`. The application reads its restricted token from a mounted file. Neither the token nor a raw DSN is returned in source-list responses. The database schema has no source `dsn` or `masked_dsn` column.

The secret-store and service-database writes are separate operations. If database persistence fails after a successful secret write, an orphaned OpenBao secret can remain. The target's true privilege boundary must be provided by its database role; the demo bootstrap role is not actually a least-privilege reader.

## 2. Schema discovery

- SQLAlchemy's inspector lists schemas, ordinary tables within each schema, and columns within each table.
- The explicitly excluded schema names are `pg_catalog`, `information_schema`, and `pg_toast`. There is no broader prefix exclusion rule.
- Views and materialized views are not explicitly enumerated.
- Metadata retained for each finding is `schema_name`, `table_name`, `column_name`, and SQLAlchemy's rendered `data_type`.
- A metadata query failure aborts discovery with a sanitized `SourceScanError`. Tables are not silently skipped after an inspection error.
- A successfully inspected source with no tables returns zero columns. It is different from a failed inspection.

## 3. Sampling

Group discovered columns by `(schema_name, table_name)`. For each table, quote every identifier with the PostgreSQL dialect's identifier preparer, including embedded double quotes, and run one sampling query with a bound row limit:

```sql
SELECT "column_a", "column_b", "column_c"
FROM "schema"."table"
LIMIT :limit;
```

- Default sample limit: 200 returned rows per table, including rows with nulls or blanks. Reject nonpositive limits and empty column lists before querying.
- All columns in a table use the same returned rows from one statement. No full-table null count or search for additional nonblank values is performed.
- For each column, SQL nulls and values whose Python string representation is blank after stripping whitespace increment `null_count`. Other values become Python strings for classification.
- `sample_size` is the number of nonblank values for that column within the returned rows. `null_count` counts null/blank values within those same rows. Their sum is the table's returned row count, which may be less than the configured limit.
- Empty tables produce zero samples and zero sampled nulls. An all-null sampled column has zero classification support; this is not proof that unsampled rows contain no PII.
- The sample is not randomized, ordered, or guaranteed stable. Rows in one table share a statement snapshot, but there is no consistent source snapshot across different tables.
- Returned rows are bounded. Returned bytes, physical database work, and total scan duration are not globally bounded. Per-statement timeouts remain in place, and there is no scan-wide deadline. A row limit is not a hard I/O budget.
- Default target connection timeout: 5 seconds. Default target statement timeout: 5,000 milliseconds, separately per statement.
- SQLAlchemy connection, permission, timeout, or result-read errors propagate as sanitized failures. A partially read table sample is never returned as a success; the scan rolls back its pending inventory writes.
- Older inventory stored table-wide null/blank counts. Rescan existing sources before interpreting `null_count` using the new sampled-row semantics; historical entries are not automatically rewritten.

The classifier receives the rendered datatype. Embedded scanning, standalone full-name detection, and standalone postal-address detection are enabled for `text`, `varchar`, `character varying`, `char`, and `character`, case-insensitively and ignoring a parenthesized length. Other scalar detectors are not restricted to text database types.

## 4. Standalone value detectors

Standalone means the entire cleaned value matches the detector. Formats are heuristic evidence, not identity verification.

### EMAIL

Full-match pattern:

```regex
[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+
```

This is a simple ASCII email pattern, not an RFC-complete parser. It does not check DNS, deliverability, allowed TLD lists, or internal-system ownership. Its permissive domain class can accept malformed dot sequences or a trailing dot. Unicode email local parts are not supported.

### PHONE_IN

Full-match pattern:

```regex
(?:(?:\+91|91|0)[ -]?)?[6-9](?:[ -]?[0-9]){9}
```

- Ten-digit mobile portion starts with 6, 7, 8, or 9.
- Optional prefix is `+91`, `91`, or `0`, followed by at most one space or hyphen.
- At most one space or hyphen is allowed between mobile digits.
- Reject the value if all ten mobile digits are identical.
- Reject alphabetic wrappers, extensions, decimal notation, parentheses, `0091`, and longer serial numbers that do not full-match.
- Numeric database columns are not categorically excluded, so a sufficiently phone-shaped numeric identifier can still collide.

### PAN

Full-match pattern:

```regex
[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z]
```

Five uppercase letters, four ASCII digits, one uppercase letter. The fourth character must be one of `A B C F G H J L P T`. Repeated characters inside a regex set would be harmless but are not needed. Lowercase input is not uppercased automatically. The rule checks format and entity-code membership, not government issuance, the holder's identity, or the final check character's correctness.

### AADHAAR

- Exactly 12 contiguous ASCII digits.
- First digit must be 2 through 9.
- The Verhoeff checksum must pass: process digits in reverse using the repository's multiplication/permutation tables; final accumulator must equal zero.
- Spaces and hyphens inside the number are not normalized.
- Passing Verhoeff is not proof of a real issued Aadhaar. Random numeric identifiers can occasionally pass the checksum.

### PINCODE

Pattern:

```regex
^[1-8]\d{5}$
```

Split camelCase boundaries, lowercase the column name, and extract alphabetic tokens. Reject matches only when a complete token is one of:

```text
id amount price count total invoice
```

For example, `customer_id`, `customerId`, and `invoice_number` are excluded, while `residential_pincode`, `country_pincode`, and `account_pincode` are eligible: `id` inside `residential` and `count` inside `country` or `account` are not separate tokens. Generic names such as `notes` and `field_1` also remain eligible. A pincode-related name never bypasses value validation.

This is a limited collision guard, not a postal-directory lookup. A six-digit identifier in an unrecognized column can still match; a genuine pincode under an excluded identifier/money token can be missed. Names without word or camelCase boundaries, such as `customerid`, are not recognized as `id` tokens. Unlike the other numeric patterns above, the final five digits use Python `\d`, which also accepts Unicode decimal digits.

### DOB

Parse the entire cleaned value with each format; no birth-related column name is required:

```text
%Y-%m-%d
%d-%m-%Y
%d/%m/%Y
%Y/%m/%d
```

Split camelCase boundaries and lowercase the column name. Suppress DOB matching only for these exact known transaction-date names: `order_date`, `payment_date`, `invoice_date`, `transaction_date`, `created_at`, `updated_at`, and `last_updated`. Thus `invoiceDate` is also excluded. Other names, including generic `notes`, `field_1`, and `col_x`, remain eligible. Column names alone never bypass value validation.

Accept any valid calendar date on or before `date.today()` from the application's runtime clock. There is no minimum-age rule or fixed birth-year cutoff, so children's birth dates are supported. Reject invalid dates, future dates, and values with trailing prose or time components. Timestamp-valued DOBs are not currently supported.

A standalone date cannot establish its business meaning. A valid date in `notes` is therefore a DOB candidate, while known transaction names provide limited negative context. This favors finding dates under misleading names but can classify unrelated dates under unrecognized names as DOB. A real birth date stored in an explicitly excluded transaction column can be missed. The `DOB` output is a heuristic classification, not proof of birth-date semantics or identity. DOB masking redacts the entire matched value.

### FULL_NAME

Apply only to supported text database types. Strip the value, then:

1. Require length 3-100 characters.
2. Optionally remove one leading honorific: `mr`, `mrs`, `ms`, `dr`, `shri`, or `smt`, case-insensitively with an optional final dot.
3. Require two to four remaining whitespace-separated words.
4. Reject words beginning with a lowercase letter. Title case and uppercase pass; uncased scripts are not rejected merely for lacking uppercase letters.
5. Allow alphabetic characters, Unicode combining marks, single-letter initials, dotted initials, internal hyphens, and straight/curly apostrophes. Each hyphen/apostrophe-separated segment must contain a letter. Empty segments and digits fail.
6. Require at least one non-initial word longer than one character.
7. Reject the following words after lowercasing and removing a final dot:

```text
unknown none null not available provided pending shipped delivered cancelled
processing refund support team call me tomorrow left at doorstep please order
invoice payment new delhi road nagar layout limited ltd
```

After those structural checks, require at least one supporting signal:

- A known person-column hint:

```text
name full_name fullname customer_name person_name contact_name employee_name
patient_name account_holder_name customer person buyer recipient author
applicant beneficiary
```

- Or an ASCII-tokenized column name containing the token `name`, without any of `product`, `item`, `company`, `city`, `file`, or `table`.
- Or the removed honorific.
- Or a single-letter/dotted initial.
- Or a word from the limited value vocabulary:

```text
sharma nair deshmukh chatterjee singh iyer reddy joshi kumar patel gupta
verma rao das khan hussain ali kaur shah menon pillai fernandes
```

There is no hard requirement for a known column name: `notes = "Aarav Sharma"` can match from its value token. Conversely, a name column containing junk fails structural checks. This is not a comprehensive or culturally neutral name recognizer. Lowercase names, single-token names, names with more than four words, and unfamiliar names without metadata/initial/honorific support can be missed. Non-person proper nouns can still match.

### POSTAL_ADDRESS

Apply only to supported text database types:

1. Require 20-250 characters and no more than 35 whitespace-separated words.
2. Extract lowercase ASCII word tokens.
3. Reject text containing any of `please`, `refund`, `call`, `email`, `verify`, `uploading`, `support`, or `update`, to reduce support-ticket prose matches.
4. Require at least two distinct tokens from:

```text
road rd street st marg nagar layout sector cross main flat floor block dist
district near house plot tower lane avenue colony
```

5. If the lowercased column name contains `address`, accept after the value checks. Otherwise require an address-like beginning with a number, optionally preceded by `flat`, `house`, `plot`, `no`, `block`, or `floor` and optional `no`.

The address-start pattern is:

```regex
(?i)^(?:(?:flat|house|plot|no|block|floor)\.?\s*(?:no\.?\s*)?)?[a-z]?-?[0-9]
```

Examples detected include `Flat 18, Maple Road, Sector 7, Pune` in a generic `notes` column and the seed's residential addresses. A column-name hint alone cannot turn a city or `N/A` into an address. There is no geocoding, delivery verification, or non-English address vocabulary. Very short, unusual, or embedded addresses may be missed.

## 5. Choosing a column's primary classification

Each sample can match more than one detector. Count matches independently for every supported type and divide by the number of returned nonblank samples.

- Select the type with the greatest match ratio, provided it reaches 0.25.
- Ties keep the first type in this order: `EMAIL`, `PHONE_IN`, `PAN`, `AADHAAR`, `PINCODE`, `DOB`, `FULL_NAME`, `POSTAL_ADDRESS`.
- When the largest ratio is below `PRIMARY_MATCH_THRESHOLD` (0.25), report `NONE` and reset the reported primary `match_ratio` and `confidence` to zero. The justification records the highest candidate's type, actual match count/ratio, and cutoff. Minority matches still affect risk and evidence; there is no separate structured per-type count field.
- Empty input reports `NONE`, zero scores/ratios, empty evidence, and a no-samples justification.
- No numeric 85/15 metadata weighting is implemented. Column metadata provides the specific guards and supporting signals documented above.

The 0.25 threshold permits a recurring minority (one in four nonblank samples) to set the primary label, rather than requiring a majority. It is not learned from labelled data. For 24/100 email matches, primary is `NONE` and the justification states 24/100 and the 25% cutoff; for 25/100, primary is `EMAIL`. Risk and evidence consider both cases. `NONE` does not prove the column contains no PII.

## 6. Embedded detection

Only supported text database types are scanned for embedded `EMAIL`, `PHONE_IN`, `PAN`, and `AADHAAR`. Column names do not gate this scan.

Use the standalone email pattern for searching. PAN and phone searches add token guards:

```regex
PAN:   (?<!\w)[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z](?!\w)
PHONE: (?<![\w+])(?:(?:\+91|91|0)[ -]?)?[6-9](?:[ -]?[0-9]){9}(?!\w)
UID:   (?<!\w)[2-9][0-9]{11}(?!\w)
```

Each matched substring must pass its type validator, including phone repeated-digit rejection and the Aadhaar checksum. A match covering the entire cleaned value is excluded from embedded counting: a standalone phone belongs to primary detection. A match with any additional surrounding characters is considered embedded; this includes punctuation around an otherwise standalone token, not only natural-language prose.

- Record the sorted union of types found in `embedded_pii_types`.
- Count a sample once when it contains one or more embedded matches, even if it contains multiple occurrences/types.
- Report any validated embedded hit; the primary 0.25 threshold does not apply to embedded reporting.
- Do not detect embedded full names, postal addresses, DOBs, or pincodes.

A mixed column containing two standalone phones and one sentence containing a phone can be both a primary-PII column and an embedded-PII column. The response counters count columns, not values.

## 7. Ratios and sample-weighted scores

Let `n` be returned nonblank sample count, `p` be the selected primary match fraction after thresholding, and `e` be the fraction of sampled values with any validated embedded hit.

```text
sample_weight = min(1.0, n / 20.0)
match_ratio = round(p, 4)
confidence = round(p * sample_weight, 2)
embedded_match_ratio = round(e, 4)
embedded_confidence = round(e * sample_weight, 2)
```

All four values are zero for empty samples. Confidence is not confidence in the absence of PII. `CONFIDENCE_SAMPLE_TARGET` (20) is the point where the linear small-sample discount saturates, not a minimum scientifically sufficient sample size. One matching value can classify a column with score 0.05. Samples are not random, duplicate values count as separate rows, and a 1.0 score is not proof of independent evidence, detector accuracy, or population coverage. Boundary regression tests verify the rules, not calibration or real-world precision/recall. Evaluate separate labelled data before changing these constants.

| Example | Match ratio | Weight | Score |
| --- | --- | --- | --- |
| 8/8 standalone addresses | 1.0 | 0.4 | Primary 0.4 |
| 20/20 standalone emails | 1.0 | 1.0 | Primary 1.0 |
| 5/6 texts with embedded PII | 0.8333 | 0.3 | Embedded 0.25 |
| No primary matches, but embedded PII | Primary 0 | Depends on n | Primary 0; separate embedded score |

Scores use unrounded ratios before final rounding. The new metric fields are nullable for historical inventory rows until a rescan populates them.

## 8. Risk assignment

Apply this priority to the union of every standalone type with at least one validated sample match and all validated embedded types. Do not restrict risk to the winning primary type or apply the primary 0.25 threshold:

1. `CRITICAL`: PAN or Aadhaar.
2. `HIGH`: email, Indian phone, postal address, DOB, or the reserved `FREE_TEXT` label.
3. `MEDIUM`: full name.
4. `LOW`: pincode.
5. `NONE`: none of the above.

The classifier does not currently emit `FREE_TEXT` as a primary type; prose normally has primary `NONE` plus embedded findings. Risk is not multiplied by confidence and does not consider combinations across separate columns, business purpose, consent, or actual exposure. Each scanned column increments exactly one risk bucket.

Two standalone emails and one PAN produce primary `EMAIL` but risk `CRITICAL`. One standalone PAN among five samples produces primary `NONE`, primary confidence zero, and risk `CRITICAL`. The justification lists all validated types used for risk, including minority and subthreshold matches. Risk is the highest observed sensitivity, not a frequency estimate or a confidence score.

## 9. Evidence selection and masking

Persist up to three masked examples selected from all returned nonblank samples, not merely the first three:

1. Consider validated types in descending risk order. Within one tier, prefer the primary type, then use alphabetical type order for deterministic ties.
2. For each type not yet covered, select a matching sample that covers the most additional uncovered standalone/embedded types. Ties use the earliest sampled value. A single sample may cover multiple types.
3. Stop at three selected samples. Fill any remaining slots with other matching samples first, then nonmatching samples, preserving sample order within each group.
4. Return selected examples in their original sample order, applying the privacy rules below. Selection does not change classifications, ratios, confidence, or risk.

This can show a PAN found after the first three sampled values, even when emails dominate the column. Three slots cannot guarantee evidence for every detected type, and fully redacted mixed-content markers do not expose their underlying values. The detector results and justification remain the complete reported type summary. Selection covers only the bounded sample, not unsampled source rows.

For each evidence value independently:

1. If it matched one or more standalone detectors, select its own type. Prefer the column's primary type only when that individual value matched it; otherwise use the first matched type in detector priority order.
2. Apply that type's standalone mask. Scan the retained result again for phone, PAN, and Aadhaar patterns, preventing identifiers in retained email-domain text from leaking.
3. If the value matched no standalone type but the column has a primary PII type, return `[MIXED_CONTENT_REDACTED]` for the entire value.
4. Otherwise, if this sample contains validated embedded matches, return `[FREE_TEXT_REDACTED: TYPE, TYPE]`, using its sorted distinct embedded types. Include only types found in that individual sample, not every type found elsewhere in the column. Retain no source text or identifier fragments.
5. Otherwise return `[UNCLASSIFIED_REDACTED]`. Empty sample sets produce an empty evidence array.

This prevents a column-level `EMAIL` decision from treating a prose value's trailing PAN as an email domain. It also masks a minority standalone PAN using the PAN mask, even in an email-dominated column. Full-value matches below the reporting threshold are still masked by their own type.

### Standalone masks

| Type | Rule | Example output |
| --- | --- | --- |
| EMAIL | Validate the whole email first. Retain the first two local-part characters only when its length is greater than two; mask the rest. For one/two-character local parts, mask every character. Retain the domain, subject to the secondary identifier scrub. Invalid input returns `[EMAIL_REDACTED]`. | `aa***@example.com`, `*@example.com` |
| PHONE_IN | Keep only the last four digits; normalize the displayed prefix | `+91-******3210` |
| PAN | Retain first three and last one characters; insert six stars | `ABC******F` |
| AADHAAR | Keep last four characters | `XXXX-XXXX-0124` |
| FULL_NAME | For each whitespace word, retain its first character and replace the remainder with stars; a one-character word becomes `*` | `A**** S*****` |
| PINCODE | Retain the first two characters | `56****` |
| DOB | Redact the whole date | `****-**-**` |
| POSTAL_ADDRESS | Redact the whole address | `[ADDRESS_REDACTED]` |
| Unknown helper type | Generic redaction | `******` |

The low-level helpers have defensive fallbacks for malformed short inputs. Normal inventory evidence calls them only after recording each sample's standalone type matches. Partial masks deliberately retain some format/identifying fragments; they are not anonymization guarantees.

### Inline masking helper (not prose evidence)

Replace matched spans with:

```text
EMAIL    -> [EMAIL_REDACTED]
PHONE_IN -> [PHONE_REDACTED]
PAN      -> [PAN_REDACTED]
AADHAAR  -> [AADHAAR_REDACTED]
```

The helper replaces only the types passed to it. Replacement order is email, phone, PAN, Aadhaar. PAN/phone use the guarded patterns above. Aadhaar masking uses `\b[2-9]\d{11}\b`; unlike classification, the masking substitution itself does not recheck Verhoeff, and can conservatively redact additional numeric lookalikes once Aadhaar masking is requested. Phone masking likewise does not recheck the repeated-digit guard.

For example:

```text
Call +91 9876543210 about PAN ABCPK1234F.
    -> Call [PHONE_REDACTED] about PAN [PAN_REDACTED].
```

This example describes the low-level `mask_free_text` helper. Inventory evidence never retains this prose excerpt: an embedded-only sample becomes `[FREE_TEXT_REDACTED: PAN, PHONE_IN]`; ambiguous mixed prose in a primary-PII column becomes `[MIXED_CONTENT_REDACTED]`.

Inline masking is limited by supported formats and detected types. It does not identify arbitrary names/addresses/DOBs in prose or every way a secret could be written, so it is not a general privacy sanitizer. Inventory generation uses this helper only to scrub supported identifiers from already-masked standalone evidence. Free-text evidence instead fully replaces prose, including samples without supported embedded matches, preventing unsupported personal data in surrounding text from leaking. This changes evidence generation, not detector coverage. Previously stored evidence requires a rescan to be replaced; historical logs and backups remain unchanged.

## 10. Persistence, transactions, and response counts

- Each finding is unique by `(source_id, schema_name, table_name, column_name)`.
- PostgreSQL `ON CONFLICT DO UPDATE` updates classifications, scores, risk, evidence, sampling statistics, justification, and `updated_at` without changing the existing row ID.
- All findings from one scan and the source's `last_scanned_at` commit together. Exceptions during connection, discovery, sampling, classification, or persistence roll back the pending service-database transaction. This is not a source-data snapshot transaction.
- Previous inventory remains available after a failed scan. Columns removed from the target are not automatically removed from old inventory.
- `total_columns_scanned` counts columns discovered on that run.
- `pii_columns_detected` counts columns whose primary type is not `NONE`.
- `embedded_pii_columns_detected` counts columns with a nonempty embedded type list. It can overlap with the primary count.
- `risk_breakdown` assigns every scanned column exactly one tier. Its sum equals `total_columns_scanned`.
- The API does not currently return a separate distinct-sensitive-column total. Summing non-`NONE` tiers counts distinct scanned columns with any validated standalone or embedded match, including subthreshold standalone hits. Primary and embedded counts can both be zero for a column with non-`NONE` risk. Undetected or unsampled PII is not counted.

## 11. Errors and logging

- Request validation failures return HTTP 422 with only error types, field locations, and fixed safe messages. Submitted input, validation context, and original validator messages are omitted so malformed registration requests cannot echo DSN credentials.
- Connection errors become sanitized `ConnectionError` messages.
- Metadata and sampling SQLAlchemy failures become sanitized `SourceScanError` messages; partially collected metadata or sample values are not returned as successful results.
- The scan API returns 502 for target connection/discovery/sampling failures, 503 for credential-store HTTP failures, and 500 for unexpected classification/persistence failures. Error responses omit underlying SQL, DSNs, and driver messages.
- On failure, roll back the service session. Dispose of the target engine in `finally` after successful or failed scans.
- Classification logs use column name and sample count. They do not print sample contents.
- The application has no general redaction middleware for arbitrary future log statements or HTTP request bodies. Keep raw DSNs, tokens, and sample values out of any added logging.

## 12. Validation and change discipline

Run `docker compose exec app pytest -q` for the default suite. Enable `TEST_DATABASE_URL` as shown in the README for real PostgreSQL transaction tests. Tests cover the seeded detectors, false positives, generic-name columns, Unicode names, standalone/embedded separation, short emails, mixed-content masking, permission/timeouts, identifier quoting, and transactional rollback.

When modifying a detector, update its positive, negative, masking, and overlap tests and revise this document. Do not increase scores merely to make small seed data look more convincing. Rebuild the image and rescan to replace current stored findings; old backups or logs are not retroactively sanitized.
