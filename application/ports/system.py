"""Ambient-capability ports: clock and identifier generation (Phase 5).

Phases 1–4 kept the domain deterministic by *passing* every timestamp in
and deriving every identifier from meaning. Phase 5 introduces the first
components that genuinely need "now" and "a fresh id": an HTTP request
has no caller-supplied timestamp, and an audit event needs an identity
that is not derived from anything.

Rather than sprinkle ``datetime.now()`` and ``uuid4()` through the
application layer — which would make use cases untestable without
freezing time globally — both are ports. Tests inject a fixed clock and
a counting generator and assert on exact values; production injects the
real thing at composition.

This is the same reasoning Phase 4 applied when it confined its one
clock read to a single mapper function, extended to the layer above.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime


class Clock(ABC):
    """Port: the current time.

    Always timezone-aware UTC. A naive datetime anywhere in this system
    is a bug — every domain constructor rejects one.
    """

    @abstractmethod
    def now(self) -> datetime:
        """The current instant, timezone-aware, in UTC."""


class IdGenerator(ABC):
    """Port: fresh opaque identifiers.

    Used for audit event ids and correlation ids — values whose only
    requirement is uniqueness. Deliberately NOT used for scan keys or
    finding ids: those are derived from meaning so that retries are
    idempotent (Phase 4, §4), and replacing them with random ids would
    silently break that guarantee.
    """

    @abstractmethod
    def new_id(self) -> str:
        """A fresh, unique, URL-safe identifier."""
