"""The audit trail (Phase 5, §27).

A compliance platform that cannot say who did what, when, and under
which request is not auditable — which is an awkward property for a
product whose entire purpose is auditing other systems.

Three decisions shape this module:

**The action vocabulary is closed.** ``AuditAction`` is an enum, not a
free string. A free string produces a table where ``scan_started``,
``scan.started`` and ``ScanStarted`` all coexist and no query can find
them all. Adding an action is a deliberate, reviewable change.

**Audit events are immutable and append-only.** There is no ``update``
and no ``delete``. An audit trail that can be edited is not evidence.
This is enforced by the type (frozen) and by the repository port, which
exposes no mutation.

**Nothing sensitive goes in ``metadata``.** Free-form context is genuinely
useful — which filter was applied, which provider was scanned — and it is
also exactly where a credential would eventually land. The constructor
therefore refuses credential-shaped keys outright rather than trusting
callers, and the persistence layer redacts again on the way in
(defense in depth, same posture as Phase 4's evidence redaction).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from domain.shared.errors import DomainError
from domain.shared.identifiers import TenantId
from domain.shared.temporal import is_timezone_aware


class InvalidAuditEvent(DomainError):
    """An ``AuditEvent`` was constructed with invalid data."""


class AuditAction(str, Enum):
    """Security-relevant actions worth recording.

    Every value here is an event a security reviewer would actually ask
    about. Read operations are deliberately absent: recording every
    ``GET /findings`` would bury the events that matter under
    high-volume noise, and the request log already covers traffic.
    """

    # Scan lifecycle
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"

    # Finding lifecycle
    FINDING_CREATED = "finding_created"
    FINDING_RESOLVED = "finding_resolved"
    FINDING_REOPENED = "finding_reopened"
    FINDING_SUPPRESSED = "finding_suppressed"

    # Access control — the failures, which are the security signal
    AUTHENTICATION_FAILED = "authentication_failed"
    AUTHORIZATION_FAILED = "authorization_failed"
    TENANT_ISOLATION_VIOLATION = "tenant_isolation_violation"

    # Configuration
    CLOUD_ACCOUNT_CONNECTED = "cloud_account_connected"
    TOKEN_ISSUED = "token_issued"


#: Substrings that disqualify a metadata key. Mirrors the persistence
#: layer's redaction markers deliberately: two independent guards that
#: agree are the point, and a single shared list imported across the
#: domain/infrastructure boundary would violate the dependency rule.
_FORBIDDEN_METADATA_MARKERS = (
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "access_key",
    "apikey",
    "api_key",
    "authorization",
    "bearer",
)

#: Keys that contain a marker but carry no credential material.
_METADATA_ALLOWLIST = ("token_id", "access_key_count", "token_expires_at")


def _is_forbidden_metadata_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _METADATA_ALLOWLIST:
        return False
    return any(marker in lowered for marker in _FORBIDDEN_METADATA_MARKERS)


@dataclass(frozen=True, slots=True)
class AuditActor:
    """Who performed the action.

    ``subject`` is the JWT ``sub`` claim. It is NOT the tenant — a single
    subject can in principle act on behalf of one tenant only, but the
    two are different facts and conflating them makes "which client did
    this?" unanswerable.

    ``system`` covers actions with no human or client behind them: a
    scheduled scan, a background job completing. Modelled explicitly
    rather than by leaving ``subject`` blank, so an empty actor is
    always a bug rather than possibly meaning "the system".
    """

    subject: str
    kind: str = "client"  # "client" | "system"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject.strip():
            raise InvalidAuditEvent("AuditActor.subject must be a non-blank string")
        if self.kind not in ("client", "system"):
            raise InvalidAuditEvent(f"AuditActor.kind must be 'client' or 'system', got {self.kind!r}")

    @classmethod
    def system(cls, name: str = "complianceiq-core") -> "AuditActor":
        return cls(subject=name, kind="system")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One immutable, tenant-scoped audit record."""

    event_id: str
    tenant_id: TenantId
    actor: AuditActor
    action: AuditAction
    occurred_at: datetime
    #: What was acted upon — a scan key, a finding id, a cloud account.
    #: Optional because some actions (a failed authentication) have no
    #: target beyond the tenant itself.
    resource: str | None = None
    resource_type: str | None = None
    correlation_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise InvalidAuditEvent("event_id must be a non-blank string")
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidAuditEvent("tenant_id must be a TenantId")
        if not isinstance(self.actor, AuditActor):
            raise InvalidAuditEvent("actor must be an AuditActor")
        if not isinstance(self.action, AuditAction):
            raise InvalidAuditEvent("action must be an AuditAction")
        if not isinstance(self.occurred_at, datetime) or not is_timezone_aware(self.occurred_at):
            raise InvalidAuditEvent("occurred_at must be a timezone-aware datetime")

        for name in ("resource", "resource_type", "correlation_id"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise InvalidAuditEvent(f"{name} must be None or a non-blank string")

        if not isinstance(self.metadata, Mapping):
            raise InvalidAuditEvent("metadata must be a mapping")

        # Refuse rather than redact. Unlike collected cloud evidence —
        # where dropping a whole scan over one suspicious key would turn
        # a hygiene problem into an outage — audit metadata is written by
        # THIS codebase, so a credential-shaped key here is a bug in code
        # we control and should fail loudly at the call site.
        offenders = [k for k in self.metadata if isinstance(k, str) and _is_forbidden_metadata_key(k)]
        if offenders:
            raise InvalidAuditEvent(
                f"audit metadata must never carry credential-shaped keys: {sorted(offenders)}"
            )

        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
