"""Fixtures for the PostgreSQL persistence integration suite (Phase 4).

Unlike the AWS/Azure integration suites — which need real cloud
credentials and are therefore skipped by default — this suite needs only
a PostgreSQL server, which a developer can start locally in seconds
(`docker/postgres/`, or the commands in
docs/architecture/phase-4-persistence.md).

So it AUTO-DETECTS: if a database is reachable it runs for real; if not
it skips with an actionable message. It never silently passes by
substituting SQLite or an in-memory fake — the whole point of these
tests is to exercise real PostgreSQL semantics (JSONB, ON CONFLICT,
CHECK constraints, transactional rollback), none of which another engine
reproduces faithfully.

Connection settings come from the standard ``COMPLIANCEIQ_DB_*``
environment variables (see
infrastructure/persistence/postgres/session/engine.py).
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text

from infrastructure.persistence.postgres.models.tables import Base
from infrastructure.persistence.postgres.session.engine import (
    DatabaseConfig,
    create_database_engine,
    create_session_factory,
)
from infrastructure.persistence.postgres.session.unit_of_work import PostgresUnitOfWork


def _test_config() -> DatabaseConfig:
    """Config for the throwaway test database.

    Defaults target the local socket-based server the Phase 4 docs
    describe; every value is overridable by environment.
    """

    return DatabaseConfig(
        host=os.environ.get("COMPLIANCEIQ_DB_HOST", "localhost"),
        port=int(os.environ.get("COMPLIANCEIQ_DB_PORT", "5432")),
        database=os.environ.get("COMPLIANCEIQ_DB_NAME", "complianceiq_test"),
        user=os.environ.get("COMPLIANCEIQ_DB_USER", "postgres"),
        password=os.environ.get("COMPLIANCEIQ_DB_PASSWORD", ""),
        unix_socket=os.environ.get("COMPLIANCEIQ_DB_SOCKET", "/tmp"),
    )


@pytest.fixture(scope="session")
def db_engine():
    config = _test_config()
    try:
        engine = create_database_engine(config)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - any connection failure means "no database"
        pytest.skip(
            "PostgreSQL is not reachable, so the persistence integration suite cannot run.\n"
            f"  tried: {config.safe_url}\n"
            f"  error: {type(exc).__name__}: {str(exc)[:200]}\n"
            "  start one with `docker compose -f docker/postgres/compose.yaml up -d`, "
            "or set COMPLIANCEIQ_DB_* to point at an existing server."
        )

    # Fresh schema for the session, so a stale table from an earlier run
    # cannot make a test pass or fail for the wrong reason.
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def clean_db(db_engine):
    """Truncate every table before each test.

    TRUNCATE ... CASCADE rather than DROP/CREATE: it is far faster, and
    it keeps the schema (and therefore the constraints under test)
    exactly as the migration built it.
    """

    with db_engine.begin() as conn:
        tables = ", ".join(f'"{t}"' for t in Base.metadata.tables)
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    return db_engine


@pytest.fixture()
def session_factory(clean_db):
    return create_session_factory(clean_db)


@pytest.fixture()
def uow(session_factory):
    return PostgresUnitOfWork(session_factory)
