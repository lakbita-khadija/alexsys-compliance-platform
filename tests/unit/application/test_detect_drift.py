from datetime import datetime, timezone

from application.drift.detect_drift import DetectDrift
from domain.drift.models import DriftType
from domain.shared.identifiers import TenantId

DETECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
TENANT_A = TenantId("acme")


class TestDetectDrift:
    def test_delegates_to_diff_engine_for_modified_resource(self) -> None:
        previous = {"bucket-1": {"encrypted": False}}
        current = {"bucket-1": {"encrypted": True}}
        events = DetectDrift().detect(
            tenant_id=TENANT_A, previous=previous, current=current, detected_at=DETECTED_AT
        )
        assert len(events) == 1
        assert events[0].drift_type is DriftType.MODIFIED

    def test_identical_snapshots_produce_no_events(self) -> None:
        snapshot = {"bucket-1": {"encrypted": True}}
        events = DetectDrift().detect(
            tenant_id=TENANT_A, previous=snapshot, current=snapshot, detected_at=DETECTED_AT
        )
        assert events == ()

    def test_is_deterministic(self) -> None:
        previous = {"bucket-1": {"encrypted": False}}
        current = {"bucket-1": {"encrypted": True}}
        first = DetectDrift().detect(tenant_id=TENANT_A, previous=previous, current=current, detected_at=DETECTED_AT)
        second = DetectDrift().detect(tenant_id=TENANT_A, previous=previous, current=current, detected_at=DETECTED_AT)
        assert first == second
