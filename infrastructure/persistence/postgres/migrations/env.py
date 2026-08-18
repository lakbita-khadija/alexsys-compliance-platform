"""Alembic runtime environment (Phase 4).

Two things here differ from the stock template, both deliberately.

1. **The connection URL comes from ``DatabaseConfig.from_env()``**, not
   from ``alembic.ini``. Migrations run against production databases; a
   URL in a committed ini file is a committed credential. Reusing the
   application's own config object also guarantees that `alembic upgrade
   head` and the running service can never disagree about which database
   they mean.

2. **``compare_type`` and ``compare_server_default`` are on.** Without
   them autogenerate silently misses a column whose type changed, which
   is precisely the drift a migration system exists to catch. The
   migration-parity test in tests/integration/persistence/ relies on this
   to assert that the migration and the ORM models describe the same
   schema.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from infrastructure.persistence.postgres.models.tables import Base
from infrastructure.persistence.postgres.session.engine import DatabaseConfig

config = context.config

# `configure_logger` is the documented escape hatch for callers that run
# migrations in-process (the migration tests do). `fileConfig` reconfigures
# the ROOT logger globally, which would silently take pytest's own log
# capture down with it.
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

# The single source of truth for "what should the schema look like".
target_metadata = Base.metadata


def _database_url() -> str:
    """Resolve the target database.

    An explicit ``-x url=...`` wins (used by the migration tests to point
    at a throwaway database); otherwise the environment is read. Note
    that this returns a URL WITH the password in it — it is passed
    straight to SQLAlchemy and must never be logged. Use
    ``DatabaseConfig.safe_url`` for anything human-visible.
    """

    override = context.get_x_argument(as_dictionary=True).get("url")
    if override:
        return override
    return DatabaseConfig.from_env().url


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (`alembic upgrade --sql`).

    Kept working because a regulated deployment often requires a DBA to
    review the exact DDL before it touches a production database — a
    reasonable demand for a compliance product.
    """

    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Execute migrations against a live connection.

    The whole run is wrapped in ONE transaction. PostgreSQL supports
    transactional DDL, so a migration that fails halfway rolls back
    completely rather than leaving a database in a state that is neither
    the old schema nor the new one.
    """

    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
