"""Migration tests against a real PostgreSQL server (Phase 4).

A migration that has never been executed is a guess. These tests run the
real ``alembic upgrade head`` against a throwaway database and assert the
result, because every interesting failure mode here is invisible to
static inspection: a foreign key created before its parent table, a CHECK
constraint PostgreSQL rejects, a downgrade that leaves an orphan index.

The single most valuable test in this file is
``test_migration_and_orm_models_describe_the_same_schema``. Two
descriptions of the schema exist — the ORM models (which the repositories
compile queries against) and the migration (which builds the actual
database) — and nothing but a test keeps them in step. When they drift,
the symptom is not a clear error at deploy time; it is a query that works
in the test suite, where the schema came from ``create_all``, and fails
in production, where it came from the migration.

Like the rest of this package the suite auto-detects PostgreSQL and skips
with an actionable message when none is reachable. It never substitutes
another engine: SQLite cannot express half of what these migrations do.
"""

from __future__ import annotations

import os
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from application.scanning.persist_scan import PersistScanResult
from domain.scans.models import ScanStatus, ScanTarget
from domain.shared.enums import CloudProvider
from infrastructure.persistence.postgres.models.tables import Base
from infrastructure.persistence.postgres.session.engine import (
    DatabaseConfig,
    create_session_factory,
)
from infrastructure.persistence.postgres.session.unit_of_work import PostgresUnitOfWork
from tests.integration.persistence.test_persistence import TENANT_A, a_scan_result

REPO_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"

#: A database of its own, so a migration test can DROP the whole schema
#: without destroying the fixtures the rest of the suite depends on.
MIGRATION_DB = "complianceiq_migration_test"

EXPECTED_TABLES = {
    # Phase 4
    "scans",
    "scan_errors",
    "resource_snapshots",
    "finding_snapshots",
    "logical_findings",
    "rule_versions",
    # Phase 5
    "compliance_scores",
    "audit_events",
    # STEP 4
    "attack_paths",
}


def _admin_config() -> DatabaseConfig:
    """Connection settings for the maintenance database.

    ``CREATE DATABASE`` cannot run inside a transaction and cannot run
    from within the database being created, so this points at the
    always-present ``postgres`` database.
    """

    return DatabaseConfig(
        host=os.environ.get("COMPLIANCEIQ_DB_HOST", "localhost"),
        port=int(os.environ.get("COMPLIANCEIQ_DB_PORT", "5432")),
        database="postgres",
        user=os.environ.get("COMPLIANCEIQ_DB_USER", "postgres"),
        password=os.environ.get("COMPLIANCEIQ_DB_PASSWORD", ""),
        unix_socket=os.environ.get("COMPLIANCEIQ_DB_SOCKET", "/tmp"),
    )


def _migration_config() -> DatabaseConfig:
    admin = _admin_config()
    return DatabaseConfig(
        host=admin.host,
        port=admin.port,
        database=MIGRATION_DB,
        user=admin.user,
        password=admin.password,
        unix_socket=admin.unix_socket,
    )


@pytest.fixture(scope="module")
def migration_url() -> str:
    """Create a throwaway database for this module; drop it afterwards."""

    admin = _admin_config()
    try:
        admin_engine = create_engine(admin.url, isolation_level="AUTOCOMMIT")
        with admin_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - any failure means "no database"
        pytest.skip(
            "PostgreSQL is not reachable, so the migration suite cannot run.\n"
            f"  tried: {admin.safe_url}\n"
            f"  error: {type(exc).__name__}: {str(exc)[:200]}\n"
            "  start one with `docker compose -f docker/postgres/compose.yaml up -d`, "
            "or set COMPLIANCEIQ_DB_* to point at an existing server."
        )

    with admin_engine.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{MIGRATION_DB}"'))
        conn.execute(text(f'CREATE DATABASE "{MIGRATION_DB}"'))

    yield _migration_config().url

    with admin_engine.connect() as conn:
        # Terminate stragglers first: PostgreSQL refuses to drop a
        # database that still has a session attached, and a pooled
        # connection can outlive the test that opened it.
        conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = :db AND pid <> pg_backend_pid()"
            ),
            {"db": MIGRATION_DB},
        )
        conn.execute(text(f'DROP DATABASE IF EXISTS "{MIGRATION_DB}"'))
    admin_engine.dispose()


@pytest.fixture()
def alembic_config(migration_url: str) -> Config:
    config = Config(str(ALEMBIC_INI))
    config.set_main_option(
        "script_location",
        str(REPO_ROOT / "infrastructure" / "persistence" / "postgres" / "migrations"),
    )
    # Exercises the same `-x url=...` override a CI pipeline would use,
    # rather than a test-only code path.
    config.cmd_opts = Namespace(x=[f"url={migration_url}"])
    config.attributes["configure_logger"] = False
    return config


@pytest.fixture()
def empty_database(alembic_config: Config, migration_url: str) -> str:
    """Guarantee each test starts from a database with no schema at all."""

    command.downgrade(alembic_config, "base")
    engine = create_engine(migration_url)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    engine.dispose()
    return migration_url


def _table_names(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


class TestUpgrade:
    def test_upgrade_head_creates_every_table(self, alembic_config, empty_database) -> None:
        assert _table_names(empty_database) == set(), "precondition: schema starts empty"

        command.upgrade(alembic_config, "head")

        assert EXPECTED_TABLES <= _table_names(empty_database)

    def test_upgrade_head_stamps_the_revision(self, alembic_config, empty_database) -> None:
        # Compared against the script directory's actual head rather than
        # a hardcoded id: pinning the literal here means every future
        # migration breaks this test for no reason, which trains people
        # to edit it without reading it.
        from alembic.script import ScriptDirectory

        expected = ScriptDirectory.from_config(alembic_config).get_current_head()

        command.upgrade(alembic_config, "head")

        engine = create_engine(empty_database)
        with engine.connect() as conn:
            revision = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        engine.dispose()
        assert revision == expected

    def test_upgrade_head_is_safe_to_run_repeatedly(self, alembic_config, empty_database) -> None:
        # Deployment pipelines run `alembic upgrade head` on every boot,
        # including the boots where nothing changed.
        command.upgrade(alembic_config, "head")
        before = _table_names(empty_database)

        command.upgrade(alembic_config, "head")
        command.upgrade(alembic_config, "head")

        assert _table_names(empty_database) == before

    def test_foreign_keys_point_at_scans(self, alembic_config, empty_database) -> None:
        # The child tables are created after `scans` for a reason; if the
        # ordering were wrong the migration would not have run at all,
        # but this pins the relationships themselves.
        command.upgrade(alembic_config, "head")

        engine = create_engine(empty_database)
        inspector = inspect(engine)
        for table in ("scan_errors", "resource_snapshots", "finding_snapshots"):
            fks = inspector.get_foreign_keys(table)
            assert any(fk["referred_table"] == "scans" for fk in fks), table
            assert all(fk["options"].get("ondelete") == "CASCADE" for fk in fks), table
        engine.dispose()

    def test_check_constraints_are_enforced_by_the_migrated_schema(
        self, alembic_config, empty_database
    ) -> None:
        # Constraints that exist in the models but were dropped from the
        # migration would leave production unprotected while every test
        # still passed, because the test schema comes from `create_all`.
        command.upgrade(alembic_config, "head")

        engine = create_engine(empty_database)
        with engine.begin() as conn:
            names = {
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT conname FROM pg_constraint "
                        "WHERE contype = 'c' AND connamespace = 'public'::regnamespace"
                    )
                )
            }
        engine.dispose()

        assert "ck_scans_status" in names
        assert "ck_scans_terminal_has_completed_at" in names
        assert "ck_findings_severity" in names
        assert "ck_logical_findings_resolved_has_time" in names

    def test_the_cross_account_uniqueness_constraint_survives_the_migration(
        self, alembic_config, empty_database
    ) -> None:
        # `uq_logical_finding_identity` is the constraint that keeps two
        # accounts' identically-named resources from sharing one lifecycle
        # row. It has to exist in the real database, not just the models.
        command.upgrade(alembic_config, "head")

        engine = create_engine(empty_database)
        constraints = inspect(engine).get_unique_constraints("logical_findings")
        engine.dispose()

        identity = next(c for c in constraints if c["name"] == "uq_logical_finding_identity")
        assert identity["column_names"] == [
            "tenant_id",
            "provider",
            "account_id",
            "resource_id",
            "rule_id",
        ]

    def test_every_query_index_leads_with_tenant_id(self, alembic_config, empty_database) -> None:
        """Tenant isolation is only cheap if the indexes support it.

        A composite index cannot serve a tenant-scoped query unless
        ``tenant_id`` is its leading column (Part 18), and every query
        this system issues is tenant-scoped. An index added later that
        forgets this would not break a test — it would just quietly make
        the dashboard scan the whole table — so it is asserted here.

        Indexes that merely BACK a uniqueness constraint are excluded:
        they exist to enforce an invariant, not to serve a query.
        ``uq_resource_snapshot_scan_resource`` is the case in point — it
        leads with ``scan_key``, which already belongs to exactly one
        tenant, so prefixing it with ``tenant_id`` would widen the key
        for no benefit.
        """

        command.upgrade(alembic_config, "head")

        engine = create_engine(empty_database)
        inspector = inspect(engine)
        offenders = []
        for table in EXPECTED_TABLES - {"rule_versions"}:  # rule metadata is not tenant-scoped
            for index in inspector.get_indexes(table):
                if index.get("unique") or index.get("duplicates_constraint"):
                    continue
                if index["column_names"] and index["column_names"][0] != "tenant_id":
                    offenders.append(f"{table}.{index['name']}")
        engine.dispose()

        assert offenders == []


class TestDowngrade:
    def test_downgrade_base_removes_every_table(self, alembic_config, empty_database) -> None:
        command.upgrade(alembic_config, "head")
        assert EXPECTED_TABLES <= _table_names(empty_database)

        command.downgrade(alembic_config, "base")

        assert _table_names(empty_database) & EXPECTED_TABLES == set()

    def test_migration_is_reversible_and_replayable(self, alembic_config, empty_database) -> None:
        # The property that makes a migration rehearsable: you can run it,
        # back it out, and run it again without hand-repairing anything.
        command.upgrade(alembic_config, "head")
        first = _table_names(empty_database)

        command.downgrade(alembic_config, "base")
        command.upgrade(alembic_config, "head")

        assert _table_names(empty_database) == first


class TestSchemaParity:
    def test_migration_and_orm_models_describe_the_same_schema(
        self, alembic_config, empty_database
    ) -> None:
        """The test that keeps the two schema descriptions honest.

        Builds the database from the MIGRATION, then asks Alembic what it
        would autogenerate to reach the ORM models. Anything other than
        an empty diff means the models and the migration disagree — which
        in production means a query compiled against a column that is not
        there.
        """

        command.upgrade(alembic_config, "head")

        engine = create_engine(empty_database)
        with engine.connect() as conn:
            context = MigrationContext.configure(
                conn,
                opts={
                    "compare_type": True,
                    "compare_server_default": True,
                    # `alembic_version` is Alembic's own bookkeeping table
                    # and is deliberately absent from `Base.metadata`.
                    "include_name": lambda name, type_, parent: not (
                        type_ == "table" and name == "alembic_version"
                    ),
                },
            )
            diff = compare_metadata(context, Base.metadata)
        engine.dispose()

        assert diff == [], f"migration has drifted from the ORM models: {diff}"


class TestMigratedSchemaIsUsable:
    def test_a_scan_persists_end_to_end_against_the_migrated_schema(
        self, alembic_config, empty_database
    ) -> None:
        """Proof that the migration produces a schema the app can use.

        Every other test in this package runs against a schema built by
        ``Base.metadata.create_all``. This one runs the real persistence
        use case against a schema built by the real migration — the only
        test that covers what actually happens on a deployed system.
        """

        command.upgrade(alembic_config, "head")

        engine = create_engine(empty_database)
        uow = PostgresUnitOfWork(create_session_factory(engine))
        scanned_at = datetime(2026, 3, 1, tzinfo=timezone.utc)

        outcome = PersistScanResult(uow).execute(
            scan_result=a_scan_result(at=scanned_at),
            target=ScanTarget(provider=CloudProvider.AWS, account_id="111111111111"),
            completed_at=scanned_at,
        )

        assert outcome.status is ScanStatus.COMPLETED
        assert outcome.findings_written >= 1

        with uow as u:
            stored = u.scans.get(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert stored is not None
        assert stored.status is ScanStatus.COMPLETED
        engine.dispose()
