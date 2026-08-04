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

### Known drift

`memories.source` is created by the baseline as the `memory_source` enum.
A database that instead gained the column from `init_db`'s
`ADD COLUMN ... VARCHAR(16) NOT NULL DEFAULT 'user'` holds a varchar. The
values are identical and the application does not care, but the two
deployments differ. A follow-up revision can converge them:

```sql
ALTER TABLE memories ALTER COLUMN source TYPE memory_source USING source::memory_source;
```

The same applies to the `connector_type` enum: a stamped database has `mcp`
appended last (from `ALTER TYPE ... ADD VALUE`), a fresh one has it in
declaration order. Only the type's sort order differs; nothing reads it.

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
