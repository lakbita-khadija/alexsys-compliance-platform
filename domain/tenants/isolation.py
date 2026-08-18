"""The canonical tenant-isolation check.

Tenant isolation is a security invariant (see project instructions and
blueprint ADR-010): it must be enforced inside the Domain itself, not
delegated to a future API layer. ``ResourceGraph.add_node`` and
``AttackPath`` construction both need the identical check — it lives here
once so the rule is not duplicated (and cannot silently drift) across
modules.
"""

from __future__ import annotations

from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import TenantId


def ensure_same_tenant(expected: TenantId, actual: TenantId, *, context: str = "") -> None:
    """Raise ``TenantIsolationViolation`` if ``actual`` does not match
    ``expected``. ``context`` is an optional short label identifying what
    was being checked, included in the error message for diagnosability.
    """

    if expected != actual:
        location = f" ({context})" if context else ""
        raise TenantIsolationViolation(
            f"tenant isolation violated{location}: expected {expected!s}, got {actual!s}"
        )
