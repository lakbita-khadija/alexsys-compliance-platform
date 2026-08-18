"""``DetectDrift`` (blueprint §4).

Pure orchestration around ``domain.drift.diff_engine.DiffEngine`` — the
comparison logic itself is never duplicated here (blueprint §12: the
Domain's ``DiffEngine`` already handles this, persistence-independent).
This class's only job is what §12 assigns to the caller: "provide the
correct snapshots and context" — there is no snapshot-retrieval port,
since persisting/retrieving prior snapshots is explicitly
``infrastructure/persistence/ [FUTURE]`` (blueprint §5). Whoever calls
``DetectDrift`` is responsible for sourcing ``previous``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from domain.drift.diff_engine import DiffEngine
from domain.drift.models import DriftEvent
from domain.shared.identifiers import TenantId


class DetectDrift:
    """Orchestration entry point for drift detection."""

    def detect(
        self,
        *,
        tenant_id: TenantId,
        previous: Mapping[str, Mapping[str, Any]],
        current: Mapping[str, Mapping[str, Any]],
        detected_at: datetime,
    ) -> tuple[DriftEvent, ...]:
        return DiffEngine.compare(
            tenant_id=tenant_id,
            previous=previous,
            current=current,
            detected_at=detected_at,
        )
