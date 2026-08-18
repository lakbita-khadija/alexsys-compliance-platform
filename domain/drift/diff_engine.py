"""Compares two in-memory resource-fleet snapshots (blueprint §12).

A pure, deterministic comparison: no persistence, no wall-clock reads —
``detected_at`` is supplied by the caller rather than read from
``datetime.now()`` inside the engine, so the same two snapshots always
produce the exact same events.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from domain.drift.canonicalization import canonicalize
from domain.drift.models import DriftEvent, DriftType
from domain.shared.identifiers import ResourceId, TenantId


class DiffEngine:
    """Stateless comparison engine — a namespace for ``compare``, not an
    object with lifecycle of its own.
    """

    @staticmethod
    def compare(
        *,
        tenant_id: TenantId,
        previous: Mapping[str, Mapping[str, Any]],
        current: Mapping[str, Mapping[str, Any]],
        detected_at: datetime,
    ) -> tuple[DriftEvent, ...]:
        """Compare two snapshots keyed by raw resource id string, each
        mapping to that resource's raw attribute dict. Returns one
        ``DriftEvent`` per resource that was added, removed, or modified
        (after canonicalization) — none for resources that are unchanged.
        """

        events: list[DriftEvent] = []

        for resource_id in sorted(set(previous) - set(current)):
            events.append(
                DriftEvent(
                    resource_id=ResourceId(resource_id),
                    tenant_id=tenant_id,
                    drift_type=DriftType.REMOVED,
                    changed_fields={},
                    detected_at=detected_at,
                )
            )

        for resource_id in sorted(set(current) - set(previous)):
            events.append(
                DriftEvent(
                    resource_id=ResourceId(resource_id),
                    tenant_id=tenant_id,
                    drift_type=DriftType.ADDED,
                    changed_fields={},
                    detected_at=detected_at,
                )
            )

        for resource_id in sorted(set(previous) & set(current)):
            previous_canonical = canonicalize(previous[resource_id])
            current_canonical = canonicalize(current[resource_id])
            if previous_canonical == current_canonical:
                continue

            changed_fields = {
                key: (previous_canonical.get(key), current_canonical.get(key))
                for key in set(previous_canonical) | set(current_canonical)
                if previous_canonical.get(key) != current_canonical.get(key)
            }
            events.append(
                DriftEvent(
                    resource_id=ResourceId(resource_id),
                    tenant_id=tenant_id,
                    drift_type=DriftType.MODIFIED,
                    changed_fields=changed_fields,
                    detected_at=detected_at,
                )
            )

        return tuple(events)
