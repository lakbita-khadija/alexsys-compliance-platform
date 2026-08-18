"""The audit recording port (Phase 5, §27).

Callers should not have to generate an event id, read a clock, or build
an ``AuditEvent`` by hand every time something auditable happens — that
is boilerplate at each call site, and boilerplate is where the one
forgotten field lives. ``AuditRecorder`` takes the facts and assembles
the event.

It is a port rather than a concrete helper because *where* audit events
go is a deployment decision: a database table (what Phase 5 ships), a
SIEM, an append-only log shipper. §27 asks for the trail; it does not
mandate the sink.

Recording must never break the operation being audited. An audit sink
that is briefly unavailable should not fail a scan that already ran —
implementations are expected to degrade rather than raise, and to make
that degradation visible in logs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping

from domain.audit.models import AuditAction
from domain.shared.identifiers import TenantId


class AuditRecorder(ABC):
    """Port: append a security-relevant event to the audit trail."""

    @abstractmethod
    def record(
        self,
        *,
        tenant_id: TenantId,
        actor_subject: str,
        action: AuditAction,
        resource: str | None = None,
        resource_type: str | None = None,
        correlation_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        actor_kind: str = "client",
    ) -> None:
        """Record one event.

        The implementation supplies ``event_id`` and ``occurred_at`` from
        its injected ``IdGenerator`` and ``Clock``, so no call site has
        to — and so tests can assert on exact values.

        ``metadata`` must not contain credential-shaped keys; the
        ``AuditEvent`` constructor rejects them outright rather than
        redacting, because unlike collected cloud evidence this data is
        written by code we control.
        """
