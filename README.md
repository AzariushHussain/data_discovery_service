# IngeniaAI Data Discovery Service

A FastAPI service that registers PostgreSQL sources, discovers their tables and columns, samples values, and reports personal-data types, risk levels, and masked evidence. Source connection strings are stored in OpenBao. The service database stores only their secret references.

The service implements all five assignment endpoints and two bonuses: separate embedded-PII detection and rescans that update existing findings without duplicating them. It runs scans synchronously. There is no frontend, application authentication, multi-tenancy, or background worker framework.

See [RULES.md](RULES.md) for the exact discovery, classification, confidence, risk, and masking rules. That file describes the implementation, including its limitations; it is not a claim of complete PII coverage.

## Completed bonus tasks

The assignment allows at most two bonus tasks. Both selected tasks are implemented:

| Assignment bonus | Implementation | How to verify |
| --- | --- | --- |
| Detect personal data hiding in free-text columns and report it separately from the column's main classification | Detects embedded email addresses, Indian phone numbers, PAN, and Aadhaar. Inventory reports `embedded_pii_types`, `embedded_match_ratio`, and `embedded_confidence` separately from the primary classification. Free-text evidence replaces the entire prose value with the detected types, preserving no surrounding text. | Scan the seeded source and inspect `support_tickets.ticket_body` in the inventory. Its primary type can be `NONE` while embedded types are reported. See [RULES.md](RULES.md) for format and masking limits. |
| Re-scan behaviour that updates existing findings instead of duplicating them | A unique key on `(source_id, schema_name, table_name, column_name)` and PostgreSQL upserts update existing findings. Row IDs remain stable while classifications, risk, masked evidence, and timestamps refresh. | Scan the same unchanged source twice, then compare stored and unique column counts using the commands under **Verify rescans and inspect storage**. Both remain 26 for the supplied seed. |

Embedded and primary PII column counts can overlap; they are not separate counts of distinct sensitive columns. Rescans update discovered columns but do not automatically delete findings for columns removed from the source.

## Requirements

| Requirement | Details |
| --- | --- |
| Docker Engine or Docker Desktop | Must be running; image downloads require network access on the first build |
| Docker Compose v2 | Commands use `docker compose`, not `docker-compose` |
| Bash and curl | Run the examples from Linux, macOS, or a WSL Bash terminal on Windows |
| Host ports | API: `8000`; service PostgreSQL: `5433`; sample PostgreSQL: `5434`; OpenBao: loopback `8200` |
| Host Python | Python 3.9+ for the setup helper (standard library only); optional when using the manual setup reference. Docker supplies Python 3.12 for the API |
| Local Python development | Requires Python 3.12 or newer, matching `pyproject.toml` |

Run commands from the repository root. PowerShell users should run the Bash examples in WSL, particularly heredocs, input redirection, and hidden token prompts.

```bash
docker version
docker compose version
```

The assignment permits Python 3.11+, but this implementation selects Python 3.12. Dependencies are declared in `pyproject.toml`; versions are currently lower-bounded rather than locked. PostgreSQL uses `postgres:16-alpine`. OpenBao currently uses `latest`; version 2.7.1 was used during development. Pinning images and dependency versions is a remaining reproducibility improvement.

## Architecture

```text
Client -> FastAPI
            |-- service_db: sources, column_inventory, alembic_version
            |-- OpenBao: complete source DSNs
            `-- registered source: read-only inspection and sampling

sample_source_db: demo source with customers, orders, support_tickets
```

| Component | Purpose |
| --- | --- |
| `app/api/` | Pydantic request/response schemas, HTTP endpoints, scan orchestration |
| `app/db/` | SQLAlchemy base, models, sessions |
| `app/services/connector.py` | Target connections, metadata discovery, bounded returned samples |
| `app/services/classifier.py` | Custom deterministic detectors, match counts, evidence selection |
| `app/services/masker.py` | Standalone masking and supported inline redaction |
| `app/services/risk.py` | Risk priority and sample-weighted scores |
| `app/services/secret_store.py` | OpenBao KV v2 HTTP client |
| `alembic/` | Committed migrations for the service database |
| `seed/01_init_source.sql` | Demo source schema and synthetic test records |
| `openbao/` | Persistent Raft configuration and application access policy |
| `tests/` | Classifier, masker, connector, and optional PostgreSQL transaction tests |

SQLAlchemy, FastAPI, Pydantic, psycopg, and httpx provide database, transport, validation, and HTTP support. PII classification is implemented in this repository; it does not wrap an external detection library or use a pretrained NLP model.

## First run from a clean checkout

From a WSL/Linux/macOS Bash terminal, run:

```bash
bash scripts/setup-openbao.sh
```

Requires Docker Compose v2 and host `python3` (3.9+); no host Python packages or `jq` are needed. The helper prepares the data-volume permissions, starts OpenBao, waits for its active node, initializes only a new vault, configures the `discovery` KV v2 mount and restricted policy, writes a 24-hour application token directly to `.secrets/openbao-token.txt`, then builds/recreates the API and starts its database dependencies. Migrations run during app startup.

For an existing vault, enter your saved unseal key when prompted (only if sealed), then your administrator/root token. Input is hidden; the helper refuses to fall back to echoed input without a private terminal. Multiple required unseal shares can be entered in sequence. Credentials are sent to the local published OpenBao port without proxying or redirects; they are not placed in command arguments or printed.

For a new vault, generated initialization credentials are saved once to `.secrets/openbao-init.json` with private file permissions, and used in memory to finish that first setup. Back them up in a password manager outside the repository, then remove that local recovery copy. It contains the root token and unseal keys in plaintext. Both secret files are excluded from Git and Docker's build context; Git ignore does not prevent cloud-folder synchronization. Linux permissions on Windows-mounted files depend on the mount/NTFS configuration, so restrict host access as well. On later runs the helper prompts for administrative credentials instead of reading this recovery file automatically.

Existing vaults and source secrets are preserved. An existing mount must already be KV v2; the helper stops rather than replacing an incompatible mount. It also refuses to overwrite a saved recovery file when the selected vault is uninitialized. This script is operator-triggered setup, not automatic unsealing or background token rotation. Each successful run creates a new restricted application token; older tokens remain valid until they expire or are administratively revoked.

```bash
docker compose ps
curl --retry 20 --retry-connrefused --retry-delay 1 -fsS http://localhost:8000/health
```

Expected: `{"status":"ok"}`. The API health endpoint is a liveness check; it does not verify OpenBao readiness or source connectivity. OpenBao uses persistent Raft storage, with local HTTP and one unseal share for this demonstration. The helper does not reset storage, enable development mode, or cache administrator login in the container. See the official [initialization](https://openbao.org/docs/commands/operator/init/), [unsealing](https://openbao.org/docs/commands/operator/unseal/), and [token creation](https://openbao.org/docs/commands/token/create/) documentation.

<details>
<summary>Manual setup commands (optional reference)</summary>

### 1. Prepare the local secret file

The Compose project references a token file, so create an empty placeholder before starting services. The file is populated after OpenBao initialization. These commands do not truncate an existing token file.

```bash
mkdir -p .secrets
touch .secrets/openbao-token.txt
chmod 700 .secrets
chmod 600 .secrets/openbao-token.txt
docker compose config --quiet
```

`.secrets/` is excluded from Git and Docker's build context. Linux permissions on Windows-mounted WSL paths may depend on the mount configuration. Treat the host file as a plaintext application credential and restrict access to it.

### 2. Start the databases

```bash
docker compose up -d service_db sample_source_db
docker compose ps
```

The sample database runs `seed/01_init_source.sql` on first initialization. Verify it contains three tables:

```bash
docker compose exec sample_source_db \
  psql -U customer_ro -d ecommerce_prod -c '\dt'
```

Expected: `customers`, `orders`, and `support_tickets`. The seed contains eight customers, eight orders, and six tickets, with 26 columns in total. Values are illustrative test data; checksum-valid synthetic identifiers do not establish that an identifier has ever been issued.

### 3. Prepare OpenBao volume ownership and start it

The server runs as the image's `openbao` user. The configured `/bao/data` directory needs to be writable by that user. Run this before starting a fresh OpenBao volume:

```bash
docker compose run --rm --no-deps --user root \
  --entrypoint sh openbao \
  -c 'chown -R openbao:openbao /bao/data && chmod 700 /bao/data'

docker compose up -d openbao
docker compose exec openbao bao status
```

Allow a few seconds for startup if the initial status request is refused. A new server reports `Initialized: false`, `Sealed: true`. `bao status` returns exit code 2 while sealed; this is expected, not a failed server startup.

OpenBao uses persistent Raft storage, not development mode. Its local UI is available at `http://localhost:8200/ui/`. HTTP and a single-node configuration are deliberate local-development choices, not a production deployment configuration.

### 4. Initialize once and save the administrative credentials

Only run initialization when status reports `Initialized: false`:

```bash
docker compose exec openbao bao operator init \
  -key-shares=1 \
  -key-threshold=1
```

Save the generated **Unseal Key 1** and **Initial Root Token** in a password manager outside the repository. Do not place them in the app's token file, screenshots, logs, or Git. One share with a threshold of one simplifies this local demonstration.

- The unseal key unlocks encrypted storage after a restart.
- The root token administers OpenBao during setup.
- The separate application token created below accesses source credentials.

Unseal using the hidden prompt, then log in for administrator setup:

```bash
docker compose exec openbao bao operator unseal
docker compose exec openbao bao status
docker compose exec openbao bao login -no-print
```

Enter the unseal key for `unseal` and the root token for `login`. Status should now report `Initialized: true`, `Sealed: false`. Initialization is once per stored dataset; unsealing is required after each OpenBao restart with this manual Shamir setup.

### 5. Enable the secret store and apply the application policy

Enable the mount once:

```bash
docker compose exec openbao bao secrets enable -path=discovery kv-v2

docker compose exec -T openbao \
  bao policy write discovery-service - \
  < openbao/discovery-policy.hcl

docker compose exec openbao bao policy read discovery-service
```

The policy allows create, read, update, and soft-delete operations under `discovery/data/sources/*`. It does not grant root privileges or access to other mounts. It does not grant KV metadata destruction permissions.

If the mount already exists, do not enable it again; the policy can be uploaded again when edited.

### 6. Create the restricted application token

```bash
docker compose exec openbao bao token create \
  -display-name=discovery-api \
  -policy=discovery-service \
  -no-default-policy \
  -ttl=24h \
  -explicit-max-ttl=24h
```

Copy the value beside **`token`**, not `token_accessor`. Enter it into the local file without putting its literal value in shell history:

```bash
read -rsp 'Application token: ' OPENBAO_APP_TOKEN
printf '\n'
printf '%s' "$OPENBAO_APP_TOKEN" > .secrets/openbao-token.txt
unset OPENBAO_APP_TOKEN
chmod 600 .secrets/openbao-token.txt
```

Compose mounts this as `/run/secrets/openbao_token` in the app. The application reads the file when making each secret-store request. It does not use the cached administrator login from the OpenBao container.

This token has an explicit maximum lifetime of 24 hours. Automatic rotation and renewal are not implemented. Because it excludes the default policy, `bao login` with this application token may fail its `lookup-self` check even though permitted KV operations work. Use the root token for CLI setup and the application token for the app.

### 7. Build and start the API

```bash
docker compose up -d --build app
docker compose ps
curl --retry 10 --retry-connrefused --retry-delay 1 -fsS \
  http://localhost:8000/health
```

Expected health response:

```json
{"status":"ok"}
```

Startup runs `alembic upgrade head` before Uvicorn. The health endpoint is a liveness check; it does not verify OpenBao readiness or every source connection.

- Swagger UI: `http://localhost:8000/docs`
- OpenAPI schema: `http://localhost:8000/openapi.json`

</details>

## Use all five endpoints

The example password below is the committed local demo credential. Use the Docker service hostname and internal port when registering a source: the API runs inside Docker, so `localhost` would refer to the API container itself.

### Register and verify a source

```bash
curl -fsS -X POST http://localhost:8000/sources \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Sample Customer DB",
    "dsn": "postgresql+psycopg://customer_ro:customer_password@sample_source_db:5432/ecommerce_prod"
  }'
```

Successful registration returns HTTP 201 with `id`, `name`, `created_at`, and `last_scanned_at`. It returns neither a DSN nor a secret path. Set the following variable to the returned ID; `1` is typical on a new database:

```bash
SOURCE_ID=1
```

`postgres://` and `postgresql://` prefixes are normalized to `postgresql+psycopg://`. Only that normalized PostgreSQL/psycopg driver is accepted. Connection verification occurs before the credential is written to OpenBao and the source is saved.

### List sources

```bash
curl -fsS http://localhost:8000/sources
```

### Scan a source

```bash
curl -fsS -X POST "http://localhost:8000/sources/$SOURCE_ID/scan"
```

For the supplied seed, the expected summary is:

```json
{
  "source_id": 1,
  "scanned_at": "<UTC timestamp>",
  "total_columns_scanned": 26,
  "pii_columns_detected": 10,
  "embedded_pii_columns_detected": 1,
  "risk_breakdown": {
    "CRITICAL": 3,
    "HIGH": 5,
    "MEDIUM": 1,
    "LOW": 2,
    "NONE": 15
  }
}
```

These are column counts, not numbers of people, PII occurrences, or affected rows. Primary and embedded categories can overlap when different rows in one column contain standalone PII and prose. Each column receives one risk rating, so risk counts sum to columns scanned. The current response has no `total_sensitive_columns` field. For this seed, there are 11 distinct columns with reported PII.

### Read the inventory and apply filters

```bash
curl -fsS "http://localhost:8000/sources/$SOURCE_ID/inventory"

curl -fsS "http://localhost:8000/sources/$SOURCE_ID/inventory?risk_level=CRITICAL"

curl -fsS "http://localhost:8000/sources/$SOURCE_ID/inventory?pii_type=PHONE_IN"

curl -fsS "http://localhost:8000/sources/$SOURCE_ID/inventory?risk_level=HIGH&pii_type=EMAIL"
```

Filters are case-normalized to uppercase. `pii_type` filters the primary inferred type, not `embedded_pii_types`. Unsupported filter strings currently produce no matching results rather than an enum validation error. `total_columns` is the number returned after filtering. Results are ordered by table name and inventory ID, without pagination.

Each column includes its location and database type, primary and embedded classifications, scores, risk, sample size, null count, up to three masked evidence samples, justification, and update timestamp.

Evidence is selected across all sampled values. Higher-risk types are represented first; within the same risk tier, the primary type wins ties before alphabetical type order. Samples covering multiple detected types are preferred, and remaining slots use other matches before junk. The selected examples are displayed in their original sample order. This lets a rare PAN later in an email-dominated sample appear in evidence. Three examples may not cover every type, and detection outside the bounded sample is not implied. See [RULES.md](RULES.md) for the exact selection and masking rules.

### Inspect one finding

Set `COLUMN_ID` to an inventory row's `id`:

```bash
COLUMN_ID=1
curl -fsS "http://localhost:8000/columns/$COLUMN_ID"
```

### Expected error behavior

| Status | Meaning |
| --- | --- |
| 400 | Invalid source DSN or failed registration connection check |
| 404 | Source or finding does not exist |
| 422 | Request validation fails; returns error types, field locations, and safe messages without submitted values or validation context |
| 502 | Registered source connection, metadata discovery, or sampling failed |
| 503 | OpenBao credentials are unavailable, rejected, or unreadable |
| 500 | Internal classification or persistence failure |

Discovery/sampling failures are not reported as empty successful samples. The scan rolls back its pending inventory writes and leaves the previous completed inventory and `last_scanned_at` intact. Target connection pools are disposed after scans and registration checks. A genuinely empty source can successfully return zero columns.

## Classification, confidence, and risk

The custom classifier combines format validation and contextual rules. A misleading `notes` column containing standalone mobile numbers is detected from its values. A `phone` column containing nulls and junk does not become PII just because of its name. Names, addresses, and DOB use additional contextual signals; a column hint alone is insufficient.

DOB candidates are detected from complete, valid, non-future date values, including in generic columns such as `notes` or `field_1`; a birth-related column name is not required. Children's birth dates are accepted; the former minimum-age cutoff is removed. Trailing prose and timestamp values are rejected. Known transaction-date names (`order_date`, `payment_date`, `invoice_date`, `transaction_date`, `created_at`, `updated_at`, and `last_updated`, including camelCase equivalents) suppress DOB matching to reduce false positives. A name alone never establishes PII. Date values cannot prove their business meaning: an unrelated date in an unrecognized column can still be labelled as a DOB candidate. This is a documented heuristic, not verified birth-date recognition.

Pincode candidates must match the six-digit value pattern. Complete name tokens such as `id`, `invoice`, or `amount` suppress likely identifier/financial collisions; partial words do not. Thus `residential_pincode` and generic `notes` can match from their values, while `customer_id` and `invoiceNumber` are excluded. This is a format heuristic, not verification against a postal directory.

The highest whole-value match ratio wins if it is at least 0.25. This is an explicit sensitivity trade-off, not a statistically calibrated cutoff. Rare standalone PII below that threshold does not become the primary classification, but still contributes to risk and is named in the justification. All eight types, exact regexes, tie priority, name vocabulary, address signals, and exclusions are documented in [RULES.md](RULES.md).

```text
match_ratio = selected primary matches / sampled nonblank values
sample_weight = min(1, sample_size / 20)
confidence = round(match_ratio * sample_weight, 2)

embedded_match_ratio = sampled values with embedded PII / sampled nonblank values
embedded_confidence = round(embedded_match_ratio * sample_weight, 2)
```

The ratios returned in inventory are rounded to four decimal places. Scores are heuristic support signals, not probabilities that a detector is correct. Eight matching addresses yield `match_ratio=1.0` and `confidence=0.4`. Five of six ticket bodies with embedded PII yield `embedded_match_ratio=0.8333` and `embedded_confidence=0.25`. A ticket body can have primary type `NONE`, primary score zero, and critical embedded findings.

No samples means zero detection support, not certainty that a column is safe. Rows predating the score-field migration have null new metrics until rescanned.

### Why 25% and 20 samples?

`PRIMARY_MATCH_THRESHOLD = 0.25` permits a recurring minority (one in four sampled nonblank values) to determine the primary label. It is a deliberate sensitivity choice, not a learned optimum or a claim that most rows match. At 24 matching values out of 100, primary remains `NONE` with primary ratio/score zero, but the justification reports the actual 24/100 candidate matches and the 25% cutoff. Risk and evidence still consider those validated matches. At 25/100 the primary label is assigned. Embedded detection reports any validated hit and does not use this cutoff.

`CONFIDENCE_SAMPLE_TARGET = 20` linearly discounts small samples and caps that discount at 20 values. It is not a minimum sample requirement: one matching phone can produce primary `PHONE_IN` with ratio 1.0 and score 0.05; eight matching values score 0.4. The target is a transparent heuristic, not a statistically justified sample size. Repeated identical values still count as separate sampled rows, so duplicates can inflate apparent support. Neither a score of 1.0 nor 20 matches proves correctness, independence, or coverage of unsampled data.

Tests cover the 24%/25%/26% boundary, score weighting below/at/above 20 samples, deterministic type ties, and embedded hits below 25%. These tests verify the chosen rules; they do not measure real-world precision/recall. Before tuning either constant, evaluate separate labelled positive and negative examples, report mistakes by PII type, and measure the effect of alternative cutoffs on column labels. Detector accuracy and score calibration require independent evaluation data; they are not established by the seed or this regression suite.

| Risk | Types | Rationale |
| --- | --- | --- |
| CRITICAL | PAN, Aadhaar | Government/financial identity exposure |
| HIGH | Email, Indian phone, postal address, DOB | Contactability, location, or identity-verification information |
| MEDIUM | Full name | Direct identifier with limited specificity on its own |
| LOW | Pincode | Geographic quasi-identifier |
| NONE | No validated matching type | No supported detector matched any sampled value |

The highest applicable tier across all validated standalone and embedded types wins, including minority standalone types and matches below the primary 25% threshold. Two standalone emails plus one PAN therefore produce primary `EMAIL` and risk `CRITICAL`. One PAN among five values produces primary `NONE`, primary confidence zero, and risk `CRITICAL`; its justification names PAN. Primary and embedded column counts retain their classification-based meanings, so they can both be zero for a column with non-`NONE` risk. Risk indicates the highest observed sensitivity, not its prevalence or confidence. These are application-defined priorities, not a legal determination or a calibrated loss estimate. `NONE` does not establish the absence of personal data.

## Data hygiene and credentials

- New source DSNs are written to OpenBao KV v2 under `sources/<uuid>`. PostgreSQL stores the path, source name, ID, and timestamps; the final schema contains no `dsn` or `masked_dsn` column.
- Connection strings exist transiently in application memory for connecting. Secret management does not prevent a compromised application with read access from retrieving them.
- Raw sampled values are not persisted in inventory. Standalone samples are masked by their own matched type, rather than blindly using the column's primary type.
- Ambiguous prose in a primary-PII column becomes `[MIXED_CONTENT_REDACTED]`. In embedded-only columns, each sample becomes a summary such as `[FREE_TEXT_REDACTED: EMAIL, PHONE_IN]`, listing only that sample's validated embedded types. Samples without a validated standalone or embedded match become `[UNCLASSIFIED_REDACTED]`. No surrounding prose is retained, so unsupported names, addresses, DOBs, or other secrets in that prose cannot leak through new evidence. The scanner still detects only four embedded types; redaction does not add detection coverage. Rebuild and rescan to replace old inventory evidence; existing logs and backups are not rewritten.
- Application classification logs contain column names and sample counts, not raw samples. Target exception details are suppressed in scan/connection responses. HTTP access logs and metadata remain visible; this is not a general-purpose log scrubber.
- Test passwords in Compose are public local-demo values. `customer_ro` is created as `POSTGRES_USER`, which makes it a bootstrap superuser despite the name. The connector requests read-only transactions, but this is not equivalent to database-enforced least privilege. Use a separately provisioned SELECT-only account for a real target.
- If OpenBao accepts a secret write and source persistence subsequently fails, an unreferenced secret can remain. Automatic orphan cleanup and distributed atomicity are not implemented.

The setup helper keeps entered administrator credentials in memory for its run; initial recovery credentials are saved once as described above. The optional manual CLI login caches credentials inside the OpenBao container. Keep administrative credentials secure and separate from the app token. No application auth was added: the OpenBao token authenticates the app to its credential store, not clients to FastAPI.

## Tests

Run all default tests with one command after starting the app:

```bash
docker compose exec app pytest -q
```

The default suite includes classification, masking, logs without raw samples, misleading metadata, supported Unicode names, embedded ratios, permission/timeouts, and sanitized connector failures. PostgreSQL integration tests skip unless `TEST_DATABASE_URL` is provided.

Run the complete suite including rollback/commit integration tests:

```bash
docker compose exec -T app sh -c \
  'TEST_DATABASE_URL="$DATABASE_URL" pytest -q'
```

Integration tests create uniquely named temporary schemas in the selected PostgreSQL database and remove them afterward. They require schema-creation privileges and verify that partial upserts and timestamps roll back on connection, discovery, sampling, classification, secret retrieval, and commit failures. They do not modify existing source rows. The selected database must be PostgreSQL, not SQLite.

To run tests before the app server is started, after building its image:

```bash
docker compose build app
docker compose run --rm --no-deps app pytest -q
```

Local Python alternative:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
```

Actual source scanning and local Alembic commands additionally require reachable PostgreSQL/OpenBao services and suitable environment variables. The optional test database URL is independent of the app's default database URL.

### Verification performed

The setup helper was verified against disposable OpenBao 2.7.1 and PostgreSQL containers on 2026-10-22. Checks covered fresh initialization, private credential files, restricted-token KV operations, restart/unseal with operator prompts, token-file replacement, preservation of existing secrets, and rejection of an invalid administrator token without replacing the working app token. The default suite passed **245 tests**; eight PostgreSQL integration tests were skipped in that run. Existing development vault data was not used or reset.

On 2026-10-21, the setup was exercised in a separately named Compose project with fresh PostgreSQL and OpenBao volumes. Verification covered volume ownership, OpenBao initialization/unsealing, policy and restricted-token provisioning, image build, the complete migration chain, all five API endpoints, inventory filters, expected seed classifications, and duplicate-free rescans. The complete suite passed: **148 tests**, including all seven PostgreSQL transaction tests.

The verification project used separate container names and no published host ports; HTTP checks ran inside its API container. Its containers, volumes, network, temporary token, and image tag were removed afterward. Existing development resources were not reset. The test run emitted a Starlette/httpx deprecation warning but no test failures; dependency-version pinning and migration to the future test-client interface remain maintenance work.

## Verify rescans and inspect storage

```bash
curl -fsS -X POST "http://localhost:8000/sources/$SOURCE_ID/scan"
curl -fsS -X POST "http://localhost:8000/sources/$SOURCE_ID/scan"

docker compose exec service_db \
  psql -U discovery_user -d discovery_metadata \
  -c "SELECT COUNT(*) AS stored_columns,
             COUNT(DISTINCT (schema_name, table_name, column_name)) AS unique_columns
      FROM column_inventory WHERE source_id = $SOURCE_ID;"
```

For the unchanged seed, both counts remain 26. The unique constraint on `(source_id, schema_name, table_name, column_name)` supports PostgreSQL upserts. Row IDs stay stable; update timestamps advance. Previously recorded columns that have since been dropped or renamed in the target are not automatically deleted, so the stored inventory is not a fully reconciled current snapshot after schema changes.

```bash
docker compose exec service_db \
  psql -U discovery_user -d discovery_metadata -c '\d sources'

docker compose exec service_db \
  psql -U discovery_user -d discovery_metadata \
  -c 'SELECT id, name, secret_path, last_scanned_at FROM sources ORDER BY id;'
```

For pgAdmin running on the host:

| Database | Host | Port | Database name | Username | Demo password |
| --- | --- | --- | --- | --- | --- |
| Service | `127.0.0.1` | 5433 | `discovery_metadata` | `discovery_user` | `discovery_password` |
| Sample | `127.0.0.1` | 5434 | `ecommerce_prod` | `customer_ro` | `customer_password` |

These host ports differ from the internal `5432` used between containers. If Windows has a separate PostgreSQL instance on the same host port, use a free published port or, where reachable, the WSL address from `wsl hostname -I`. WSL addresses can change after restart. For pgAdmin on the same Docker network, use service hostnames and port 5432 instead.

## Configuration

| Setting | Default in `Settings` | Compose value or behavior |
| --- | --- | --- |
| `DATABASE_URL` | Localhost service DB on 5433 | Host `service_db`, port 5432 |
| `SAMPLE_LIMIT` | 200 | Up to 200 returned rows per table, including nulls/blanks; columns share those rows |
| `CONNECT_TIMEOUT_SEC` | 5 | psycopg connection timeout |
| `STATEMENT_TIMEOUT_MS` | 5000 | Target statement timeout, including null-count queries |
| `OPENBAO_ADDR` | `http://127.0.0.1:8200` | `http://openbao:8200` inside Docker |
| `OPENBAO_MOUNT` | `discovery` | KV v2 mount name |
| `OPENBAO_TOKEN_FILE` | `/run/secrets/openbao_token` | Mounted application token |

Pydantic Settings also reads a local `.env`; it is gitignored and not copied into the image. Compose's `app.environment` values override the host application's localhost defaults. A host `.env` setting alone does not override an explicitly hardcoded Compose environment value. Edit Compose or use an explicit override for container settings, then recreate the app.

## Migrations and development edits

Application code does not call `create_all`. Alembic imports `Base` and model definitions, and uses their registered metadata. `alembic/env.py` is executable migration configuration; it is different from the optional `.env` variable file.

Use the committed migrations for initial setup; do not generate another initial migration. After an intentional model change:

```bash
docker compose up -d --build app
docker compose exec app alembic revision --autogenerate -m 'describe the schema change'
docker compose cp app:/code/alembic/versions/. ./alembic/versions/
```

Review the new local migration, including its downgrade. An empty `upgrade()` means no differences were found; a message alone does not change the schema. If you edit the copied migration, copy that exact file back before applying it, replacing the example filename:

```bash
docker compose cp ./alembic/versions/REVISION_description.py \
  app:/code/alembic/versions/REVISION_description.py

docker compose exec app alembic upgrade head
docker compose exec app alembic current
docker compose up -d --build app
```

The last build includes the migration in future images. There is no application source-code bind mount: code edits require a rebuild, and generated files inside containers must be copied out before recreation. Model changes that remove columns must be coordinated with their migration; retain an appropriate previous image if the application cannot start while preparing the change. Avoid rewriting migrations already applied to shared environments.

## Restart and manual token replacement

Run the same helper after OpenBao restarts, or before the application token's 24-hour lifetime expires:

```bash
bash scripts/setup-openbao.sh
```

If the vault is sealed, it prompts privately for the saved unseal key. It always requests an administrator token for provisioning the replacement app token. Persistent Raft data is reused; an initialized vault is never initialized again. The helper atomically replaces the app token file and recreates the API so its Compose secret mount follows the new file. Application code is rebuilt as part of startup.

The existing app token is left untouched if authentication/provisioning fails before the new token is written. If the later app build/start fails, fix that Docker error and rerun the helper; the newly written token remains available. Previously issued tokens are not revoked automatically and can remain valid until expiry. There is no background renewal, Agent, AppRole, or unattended unsealing. The manual commands above remain available for recovery or environments without host Python.

## Troubleshooting

| Symptom | Check or remedy |
| --- | --- |
| Compose reports an undefined volume | Declare it in the top-level `volumes` block |
| Compose says `services.app` has an unexpected property | `openbao` belongs alongside `app`; service `secrets` belongs alongside `depends_on`, not inside it |
| OpenBao cannot write `/bao/data/vault.db` | Run the setup helper; it prepares ownership before starting OpenBao |
| OpenBao connection refused | Check `docker compose ps -a openbao` and `docker compose logs --tail 50 openbao`; allow startup time |
| OpenBao is sealed | Use `bao operator unseal`, not `operator init` |
| Secret write/read returns 403 | Check token expiry, token-file contents, and `discovery-service` policy using the administrator login |
| App token fails `bao login` | It lacks default `lookup-self` permission; use it directly for permitted KV requests, not CLI administrator setup |
| Source scan has zero columns | Verify the registered target and `\dt` in the sample database; an empty database can be reachable and healthy |
| Inventory still shows old values | Rebuild code, perform a successful scan, and refresh the query; failed scans preserve previous findings |
| A score is 0.4 despite perfect matches | Eight samples receive weight `8/20`; inspect `match_ratio`, not the score alone |
| An edited print/log statement is missing | Rebuild the image and trigger the code path; never print raw samples or DSNs |
| `POST /sources` succeeds but a scan returns 503 later | OpenBao may have restarted sealed, or the application token may have expired |

Useful diagnostic commands:

```bash
docker compose ps -a
docker compose logs --tail 100 app
docker compose logs --tail 100 sample_source_db
docker compose logs --tail 100 openbao
docker compose exec app alembic current
```

If the sample DB was initialized while the seed file was empty, merely editing that file does not rerun initialization. Only after confirming the three target tables are absent, load the seed into that empty demo database:

```bash
docker compose exec -T sample_source_db \
  psql -U customer_ro -d ecommerce_prod \
  -v ON_ERROR_STOP=1 --single-transaction < seed/01_init_source.sql
```

Do not rerun this against populated tables; the seed uses plain `CREATE TABLE` and is not an idempotent reset script.

## Sampling trade-offs and scaling

Sampling runs one `SELECT ... LIMIT :limit` query per table for all discovered columns together. It no longer runs per-column full-table null counts or searches beyond the selected rows for nonblank values. With the three-table, 26-column seed, sampling uses three queries rather than 52. Metadata discovery and connection checks use additional queries. All columns in a table share one returned row set; each column is still classified independently.

`sample_size` counts nonblank values and `null_count` counts null/blank values within those same sampled rows. Their sum is the returned table-row count, at most `SAMPLE_LIMIT` (default 200). Sparse columns may therefore yield few or zero usable values even when later rows contain PII. Previously stored `null_count` values were table-wide: rebuild and rescan existing sources to update their meaning.

Sampling remains an unordered, nonrandom limited sample. It can be biased and can miss PII outside the returned rows; the sampled null fraction is not necessarily representative of the whole table. A table uses one statement snapshot, but different tables do not share a source snapshot. Each statement has its own timeout. Returned row counts are bounded; returned bytes, physical database work, and total scan duration are not globally bounded. There is no scan-wide deadline.

For this assignment's small seed, synchronous table-level sampling keeps the implementation inspectable. For millions of rows and a hundred sources, I would bound sampled bytes as well as row counts, use PostgreSQL statistics and explicitly designed random/block sampling, introduce a scan-wide deadline, and add a small job queue with per-source concurrency limits. I would measure detector precision/recall on a labeled dataset before calibrating scores, rather than increasing scores by lowering the sample threshold.

## Deliberate exclusions and remaining limitations

- No UI, application authentication/RBAC, multi-tenancy, second database type, or background job framework. The two selected bonuses are embedded PII and idempotent rescans.
- No verification against government registries, postal databases, email deliverability, or phone ownership. Format matches and checksums are evidence, not proof of issuance or identity.
- No exhaustive multilingual name/address recognition. The vocabulary and heuristics can produce false positives and false negatives, especially generic columns, lowercase names, unfamiliar names, or non-English address text.
- No grouped/spaced Aadhaar support, unrestricted phone-format normalization, or embedded name/address/DOB recognition. See exact supported formats in `RULES.md`.
- No calibrated confidence model, complete row counts of PII, full-table PII sweep, inventory pagination, scan history, or automatic removal of stale inventory columns.
- The setup helper combines initialization, operator-prompted unsealing, policy configuration, and app-token replacement into one command. There is no automatic AppRole/Agent lifecycle, unattended unsealing, secret orphan cleanup, or distributed transaction between OpenBao and PostgreSQL.
- Historical database files, WAL, logs, and backups may retain data written before a masking or credential-storage fix. A rescan replaces current findings but does not erase historical copies.
- Compose is a local demonstration, with plaintext demo passwords, HTTP OpenBao, exposed database ports, and unpinned dependencies. It is not ready to expose to untrusted networks.

## Stop and preserve data

```bash
docker compose stop
```

`service_db_data` and `openbao_data` are named persistent volumes. The sample PostgreSQL image uses an anonymous data volume because Compose does not declare one for it; this is adequate for disposable seed data but not a persistence guarantee across removal/recreation. Back up the service DB, OpenBao data, and separately held unseal credentials according to their sensitivity.

`docker compose down -v` deletes this project's named and attached anonymous volumes, including source registrations, scan findings, and OpenBao secrets. It is a destructive reset, not a troubleshooting or routine restart command.
