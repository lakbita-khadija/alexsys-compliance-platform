"""Part 20 security guarantees, tested without a database.

Part 20 is the one Phase 4 requirement that must never regress quietly:
credentials, access keys, tokens, passwords and private keys must NEVER
reach the database, and the database's OWN credentials must come from the
environment rather than from a file in this repository.

These tests deliberately need no PostgreSQL server. The integration suite
also covers redaction end to end, but it SKIPS when no database is
reachable — which is exactly the situation (a CI job without a service
container, a laptop with Docker stopped) where a security regression
would otherwise sail through unnoticed.
"""

from __future__ import annotations

import ast
import configparser
import inspect as inspect_module
from pathlib import Path

import pytest

from infrastructure.persistence.postgres.mappers.redaction import REDACTED, is_secret_key, redact
from infrastructure.persistence.postgres.models import tables
from infrastructure.persistence.postgres.session.engine import DatabaseConfig

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestSecretKeyDetection:
    @pytest.mark.parametrize(
        "key",
        [
            "secret_access_key",
            "SecretAccessKey",
            "aws_secret_key",
            "password",
            "db_passwd",
            "session_token",
            "refresh_token",
            "client_secret",
            "private_key",
            "privateKeyPem",
            "api_key",
            "apiKey",
            "storage_connection_string",
            "sas_token",
            "shared_key",
            "credentials",
        ],
    )
    def test_credential_shaped_keys_are_detected(self, key: str) -> None:
        assert is_secret_key(key) is True

    @pytest.mark.parametrize(
        "key",
        [
            # These NAME a credential without carrying one — redacting
            # them would destroy the very signal a CSPM rule evaluates.
            "access_key_count",
            "active_access_key_count",
            "key_manager",
            "key_state",
            "kms_key_id",
            "key_policy_allows_public_access",
            "ssh_public_key",
            "public_key",
            # Ordinary attributes.
            "resource_id",
            "encryption_enabled",
            "public_access_block",
            "mfa_enabled",
        ],
    )
    def test_safe_keys_are_not_redacted(self, key: str) -> None:
        assert is_secret_key(key) is False

    def test_detection_is_case_insensitive(self) -> None:
        assert is_secret_key("SECRET_ACCESS_KEY") is True
        assert is_secret_key("secret_access_key") is True


class TestRedaction:
    def test_a_secret_value_is_replaced(self) -> None:
        assert redact({"secret_access_key": "AKIA-not-a-real-key"}) == {
            "secret_access_key": REDACTED
        }

    def test_ordinary_values_pass_through_untouched(self) -> None:
        data = {"encryption_enabled": False, "region": "us-east-1", "versions": 3}
        assert redact(data) == data

    def test_nested_mappings_are_redacted(self) -> None:
        # An IAM policy document or an Azure diagnostic setting nests.
        data = {"config": {"inner": {"api_key": "xyz"}, "enabled": True}}
        assert redact(data) == {"config": {"inner": {"api_key": REDACTED}, "enabled": True}}

    def test_mappings_inside_lists_are_redacted(self) -> None:
        data = {"rules": [{"name": "r1", "client_secret": "s"}, {"name": "r2"}]}
        assert redact(data) == {
            "rules": [{"name": "r1", "client_secret": REDACTED}, {"name": "r2"}]
        }

    def test_redaction_does_not_mutate_the_input(self) -> None:
        # The caller's resource attributes are shared with the rule
        # engine; mutating them would corrupt evaluation.
        original = {"password": "hunter2"}
        redact(original)
        assert original == {"password": "hunter2"}

    def test_a_secret_key_is_redacted_even_when_its_value_is_a_mapping(self) -> None:
        # Key name wins over structure — otherwise a secret hidden one
        # level down inside a `credentials` block would survive.
        assert redact({"credentials": {"user": "u", "pass": "p"}}) == {"credentials": REDACTED}

    def test_non_string_keys_do_not_crash(self) -> None:
        assert redact({1: "a", "secret": "b"}) == {1: "a", "secret": REDACTED}


class TestDatabaseCredentialsNeverLeak:
    def test_repr_does_not_contain_the_password(self) -> None:
        config = DatabaseConfig(password="super-secret-password")
        assert "super-secret-password" not in repr(config)
        assert "<redacted>" in repr(config)

    def test_safe_url_does_not_contain_the_password(self) -> None:
        config = DatabaseConfig(password="super-secret-password")
        assert "super-secret-password" not in config.safe_url

    def test_the_real_url_does_carry_it(self) -> None:
        # Stated explicitly so nobody logs `url` thinking it is safe.
        config = DatabaseConfig(password="super-secret-password")
        assert "super-secret-password" in config.url

    def test_no_password_is_hardcoded_as_a_default(self) -> None:
        assert DatabaseConfig().password == ""


class TestAlembicConfigurationCarriesNoCredentials:
    def test_alembic_ini_defines_no_connection_url(self) -> None:
        """The stock Alembic template commits a full connection string.

        This asserts we removed it and did not let it creep back —
        `env.py` builds the URL from the environment instead.
        """

        parser = configparser.ConfigParser()
        parser.read(REPO_ROOT / "alembic.ini")
        assert not parser.has_option("alembic", "sqlalchemy.url")

    def test_no_setting_in_alembic_ini_holds_a_connection_string_or_password(self) -> None:
        """No SETTING may carry a credential.

        Checked per-setting rather than by scanning the raw text: the
        file documents the environment variables to export, so the
        literal string ``PASSWORD=`` legitimately appears in a comment. A
        blunt substring match would fail on the documentation and teach
        the next person to delete the comment rather than the credential.
        """

        parser = configparser.ConfigParser(interpolation=None)
        parser.read(REPO_ROOT / "alembic.ini")

        offenders = []
        for section in parser.sections():
            for option, value in parser.items(section):
                lowered = value.lower()
                if "postgresql" in lowered and "://" in lowered:
                    offenders.append(f"[{section}] {option} holds a connection string")
                if "password" in option.lower() and value.strip():
                    offenders.append(f"[{section}] {option} holds a password")
        assert offenders == []

    def test_env_py_reads_the_url_from_the_application_config(self) -> None:
        # Read from disk rather than imported: importing env.py RUNS the
        # migrations, because that is how Alembic invokes it.
        source = (
            REPO_ROOT / "infrastructure" / "persistence" / "postgres" / "migrations" / "env.py"
        ).read_text()
        assert "DatabaseConfig" in source, "env.py must reuse the application's config object"
        assert "from_env()" in source, "the URL must come from the environment"


class TestSchemaHasNoPlaceToStoreASecret:
    def test_no_table_declares_a_credential_shaped_column(self) -> None:
        """Structural version of Part 20.

        Redaction protects the VALUES that flow in. This protects the
        schema itself: if no column is named for a credential, a future
        change that tries to persist one has to add a column, which is
        visible in a migration review rather than buried in a collector.
        """

        offenders = []
        for table in tables.Base.metadata.tables.values():
            for column in table.columns:
                if is_secret_key(column.name):
                    offenders.append(f"{table.name}.{column.name}")
        assert offenders == []


class TestPersistenceDoesNotWeakenDomainPurity:
    def test_domain_modules_import_no_persistence_technology(self) -> None:
        """Phase 4's central constraint: persistence must not leak into Domain.

        Parsed from the AST rather than grepped, so a docstring that
        merely MENTIONS SQLAlchemy (several do, explaining why the domain
        avoids it) cannot fail the test, and an import hidden inside a
        function cannot pass it.
        """

        forbidden = ("sqlalchemy", "psycopg", "alembic")
        offenders = []

        for path in sorted((REPO_ROOT / "domain").rglob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    root = name.split(".")[0].lower()
                    if root in forbidden or root == "infrastructure":
                        offenders.append(f"{path.relative_to(REPO_ROOT)} imports {name}")

        assert offenders == []

    def test_the_unit_of_work_port_is_technology_free(self) -> None:
        from application.ports.persistence import unit_of_work  # noqa: PLC0415

        source = inspect_module.getsource(unit_of_work)
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0].lower())
            elif isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0].lower() for alias in node.names)

        assert "sqlalchemy" not in imported
        assert "infrastructure" not in imported
