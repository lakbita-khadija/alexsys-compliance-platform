# Local PostgreSQL

Development database for ComplianceIQ. Needed to run the Phase 4
persistence tests for real — without it they skip, and a skipped
persistence test proves nothing.

## Start it

```bash
docker compose -f docker/postgres/compose.yaml up -d
```

The image creates `complianceiq` plus the two throwaway test databases
(`initdb/01-create-test-databases.sql`) the first time the volume is
created.

## Point the application at it

```bash
export COMPLIANCEIQ_DB_HOST=localhost
export COMPLIANCEIQ_DB_PORT=5432
export COMPLIANCEIQ_DB_NAME=complianceiq
export COMPLIANCEIQ_DB_USER=complianceiq
export COMPLIANCEIQ_DB_PASSWORD=complianceiq-local-dev
```

These are the only knobs; see
`infrastructure/persistence/postgres/session/engine.py` for the full set,
including `COMPLIANCEIQ_DB_SOCKET` for a Unix-socket server.

## Create the schema

```bash
alembic upgrade head
```

## Run the tests

```bash
pytest tests/integration/persistence/          # 47 tests against real PostgreSQL
```

They auto-detect the database: reachable means they run, unreachable
means they skip with a message telling you this file exists. They never
fall back to SQLite — JSONB, `ON CONFLICT`, CHECK constraints and
transactional DDL are exactly what is under test.

## Reset everything

```bash
docker compose -f docker/postgres/compose.yaml down -v   # -v drops the data volume
```

Dropping the volume is also how you re-run `initdb/`, which only executes
on a fresh volume.

## About the password

`complianceiq-local-dev` is committed deliberately. It grants access to
an empty database in a container bound to `127.0.0.1`, and having one
documented value beats every developer inventing their own. Production
credentials come from the environment or a secret manager and appear
nowhere in this repository — there is a test
(`tests/unit/infrastructure/test_persistence_security.py`) that fails if
a connection string or password is ever added to `alembic.ini`.
