# Database migrations

Schema changes are versioned with [Alembic](https://alembic.sqlalchemy.org/).
Migrations run against the same async engine (asyncpg) and the same
`DATABASE_URL` the application uses — `alembic/env.py` reads it from
`core.config.settings`, so there is no second copy of the credentials and no
way to migrate a different database than the one the API opens.

All commands are run from `backend/`.

```bash
alembic current              # revision this database is on
alembic history --verbose    # what exists
alembic upgrade head         # apply everything outstanding
alembic downgrade -1         # step back one revision
alembic upgrade head --sql   # print the SQL instead of running it (for review)
```

## Adopting Alembic on an existing deployment

Anything that has booted the app before Alembic landed already has the full
schema: it was built by `create_all()` plus the idempotent `ALTER` list that
used to live in `core.database.init_db`. Revision `0001_baseline` describes
exactly that schema, so those databases must **not** run it.

**This happens by itself.** `core.database.init_db` checks, on every boot,
whether the database has the application's tables but no `alembic_version`
row; that combination can only mean "predates Alembic", so it stamps the
baseline and then upgrades. Nothing below is required for an ordinary
upgrade — start the app and it adopts the database.

The automation exists because the failure it prevents is silent and total:
`upgrade head` on such a database starts at the baseline and dies on
`CREATE TABLE users`, which on Postgres aborts the transaction and so fails
identically on every restart. The app never serves a request, and the only
clue is a log line. Making the operator run `alembic stamp` first is a
footgun — nothing warns you until you are already down. An empty database
is *not* stamped: it has no `users` table, so it is a fresh install and
runs the migrations normally.

The manual procedure below is still worth following when you want to
**inspect** the schema before adopting it — the automatic stamp asserts the
schema is complete, it does not verify it, and `init_db`'s old ALTERs
swallowed their own failures. Run through it once for a database you are
not sure about, ideally before the first boot on the new code.

1. Confirm the live schema really is complete. `init_db`'s ALTERs swallowed
   their own failures, so a half-migrated database is possible:

   ```sql
   \d audit_logs      -- previous_hash, seq, index ix_audit_logs_seq
   \d users           -- name, default_permission_tier, rate_limit,
                      -- llm_provider, llm_model, memory_enabled, token_epoch
   \d memories        -- source, source_conversation_id
   \d pending_actions -- risk_note
   SELECT unnest(enum_range(NULL::connector_type));  -- must include 'mcp'
   ```

   Add anything missing by hand first (the exact definitions are in
   `versions/0001_baseline_schema.py`). Stamping asserts the schema is
   already correct; it does not verify it.

2. Record the baseline as applied — this writes one row to
   `alembic_version` and changes nothing else:

   ```bash
   alembic stamp 0001_baseline
   ```

3. From then on, deploys run `alembic upgrade head`, which applies only the
   revisions after the baseline.

A brand-new/empty database skips all of this: `alembic upgrade head` builds
the schema from scratch.

`tests/test_migration_adoption.py` covers both routes — the manual stamp
and the automatic one `init_db` performs.

### Known drift

`memories.source` is created by the baseline as the `memory_source` enum.
A database that instead gained the column from `init_db`'s
`ADD COLUMN ... VARCHAR(16) NOT NULL DEFAULT 'user'` holds a varchar. The
values are identical and the application does not care, but the two
deployments differ. A follow-up revision can converge them:

```sql
ALTER TABLE memories ALTER COLUMN source TYPE memory_source USING source::memory_source;
```

The same applied to the `connector_type` enum: a stamped database had `mcp`
appended last (from `ALTER TYPE ... ADD VALUE`), a fresh one had it in
declaration order. Revision `0011_connector_type_string` removes that
difference: it turns the column into `VARCHAR(64)` and drops the type on
both kinds of database.

## Connector revisions (0011 to 0014)

These four came with the connectors work. `0010` is deliberately skipped
(another branch owns that id), so the chain runs
`0009_user_llm_nullable` -> `0011` -> `0012` -> `0013` -> `0014`. Each one
checks the live schema before changing it (like 0004 to 0009), because an
adopted pre-Alembic database is built from the current models before it is
stamped and upgraded, so the change may already be there.

| Revision | What it does | Downgrade |
|---|---|---|
| `0011_connector_type_string` | `connector_configs.connector_type` goes from the `connector_type` ENUM to `VARCHAR(64)`. Postgres converts in place (`USING connector_type::text`) and then runs `DROP TYPE IF EXISTS connector_type`; SQLite rebuilds the table in a batch operation. | Recreates the enum with its original five labels (`canvas`, `google_workspace`, `robinhood`, `mcp`, `custom`), and refuses, changing nothing, while any row holds another type. Delete those connectors first. |
| `0012_oauth_states` | Creates `oauth_states`, one row per connector sign-in (only the HMAC of `state` is stored, plus the encrypted PKCE verifier or device code), with indexes on `user_id` and `expires_at` and a unique one on `state_hash`. | Drops the table and its indexes. |
| `0013_conversation_loaded_tools` | Adds the nullable JSON column `conversations.loaded_tools`: the tools `tools.find` loaded for that conversation. NULL means none, so no backfill. | Drops the column. |
| `0014_slack_channel_links` | Creates `slack_channel_links`, one row per Slack connector with a DM link or a pending one-time code (only the code's HMAC is stored), with an index on `user_id` and a unique (`team_id`, `slack_user_id`) pair. | Drops the table and its index. |

**Why the enum became a string.** Connectors are now declared in
`services/connectors/registry.py`, and adding one must not need a schema
change. The API validates `connector_type` against the registry instead.
The Python `ConnectorType` enum stays for existing imports and
comparisons: it is a `str` enum, and the model stores a member as its plain
value. A row whose type is no longer registered is listed as unavailable
rather than breaking a reader.

## Writing a new migration

```bash
alembic revision --autogenerate -m "add widget table"
```

Autogenerate diffs `Base.metadata` against the live database, so it needs a
reachable `DATABASE_URL` and it only sees models that `alembic/env.py`
imports (it imports the `models` package, which re-exports every model —
new models must be exported there too, or they will be invisible).

**Always read the generated file before committing it.** Autogenerate does
not detect table/column renames (it emits a drop plus an add, which loses
data), and it needs help with server defaults and enum value changes. Write
a working `downgrade()` — an un-revertable migration is an outage with no
exit.

`tests/test_migrations.py` builds one database with `alembic upgrade head`
and another with `Base.metadata.create_all()` and asserts the tables,
columns, types, indexes, and foreign keys match. A model change without a
matching migration fails there rather than in production.
