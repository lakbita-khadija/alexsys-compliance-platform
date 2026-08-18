"""Engine and session construction (Phase 4).

The one place a database connection is created — the direct analogue of
``infrastructure/cloud/aws/session.py``, and it exists for the same
reason: isolating construction here is what lets every repository be
tested against a throwaway database without any global state.

SECURITY (Part 20): the database password is read from the environment
and never appears in a config file, a default argument, a log line, or
this repository. ``DatabaseConfig`` has a ``password`` field because a
connection genuinely needs one, but ``__repr__`` is overridden so it
cannot be printed accidentally — a config object that leaks its own
password into a traceback or a debug log is a real and common way
credentials escape.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    """How to reach PostgreSQL. Never committed, never logged."""

    host: str = "localhost"
    port: int = 5432
    database: str = "complianceiq"
    user: str = "complianceiq"
    password: str = field(default="", repr=False)
    #: Unix socket directory. When set, `host` is ignored — used by the
    #: test harness, which runs a socket-only local server.
    unix_socket: str | None = None
    pool_size: int = 5
    max_overflow: int = 10
    echo: bool = False

    def __repr__(self) -> str:  # pragma: no cover - trivial, but security-relevant
        return (
            f"DatabaseConfig(host={self.host!r}, port={self.port}, "
            f"database={self.database!r}, user={self.user!r}, password=<redacted>)"
        )

    @classmethod
    def from_env(cls, prefix: str = "COMPLIANCEIQ_DB_") -> "DatabaseConfig":
        """Build from environment variables.

        Recognized: ``{prefix}HOST``, ``PORT``, ``NAME``, ``USER``,
        ``PASSWORD``, ``SOCKET``, ``POOL_SIZE``, ``ECHO``.
        """

        return cls(
            host=os.environ.get(f"{prefix}HOST", "localhost"),
            port=int(os.environ.get(f"{prefix}PORT", "5432")),
            database=os.environ.get(f"{prefix}NAME", "complianceiq"),
            user=os.environ.get(f"{prefix}USER", "complianceiq"),
            password=os.environ.get(f"{prefix}PASSWORD", ""),
            unix_socket=os.environ.get(f"{prefix}SOCKET") or None,
            pool_size=int(os.environ.get(f"{prefix}POOL_SIZE", "5")),
            echo=os.environ.get(f"{prefix}ECHO", "").lower() in ("1", "true", "yes"),
        )

    @property
    def url(self) -> str:
        """A psycopg3 SQLAlchemy URL.

        The password is interpolated here and nowhere else. Callers that
        need to LOG a connection target should use ``safe_url``.
        """

        if self.unix_socket:
            return f"postgresql+psycopg://{self.user}@/{self.database}?host={self.unix_socket}"
        credentials = f"{self.user}:{self.password}" if self.password else self.user
        return f"postgresql+psycopg://{credentials}@{self.host}:{self.port}/{self.database}"

    @property
    def safe_url(self) -> str:
        """The connection target with the password removed — safe to log."""

        if self.unix_socket:
            return f"postgresql+psycopg://{self.user}@{self.unix_socket}/{self.database}"
        return f"postgresql+psycopg://{self.user}:<redacted>@{self.host}:{self.port}/{self.database}"


def create_database_engine(config: DatabaseConfig | None = None) -> Engine:
    """Build a connection-pooled engine.

    ``pool_pre_ping`` is on because a CSPM scanner is bursty: it can sit
    idle for hours between scheduled scans, by which time a pooled
    connection may have been closed by the server or an intervening
    firewall. Without pre-ping the first query of each scan would fail
    on a stale connection.
    """

    config = config or DatabaseConfig.from_env()
    return create_engine(
        config.url,
        pool_size=config.pool_size,
        max_overflow=config.max_overflow,
        pool_pre_ping=True,
        echo=config.echo,
        future=True,
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Sessions that do NOT expire objects on commit.

    ``expire_on_commit=False`` matters here: repositories map rows to
    frozen domain objects and return them, and the caller may read those
    after the transaction closes. With the default, attribute access
    after commit triggers a refresh against a closed transaction.
    """

    return sessionmaker(bind=engine, expire_on_commit=False, future=True)
