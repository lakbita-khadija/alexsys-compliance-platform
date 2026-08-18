from datetime import datetime, timezone

import pytest

from domain.drift.canonicalization import canonicalize
from domain.drift.diff_engine import DiffEngine
from domain.drift.models import DriftEvent, DriftType
from domain.shared.errors import InvalidDriftEvent
from domain.shared.identifiers import ResourceId, TenantId

TENANT = TenantId("acme")
DETECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


class TestCanonicalization:
    def test_strips_collected_at(self) -> None:
        data = {"encrypted": True, "collected_at": "2026-01-01T00:00:00Z"}
        assert canonicalize(data) == {"encrypted": True}

    def test_leaves_other_fields_untouched(self) -> None:
        data = {"encrypted": True, "versioning": {"enabled": True}}
        assert canonicalize(data) == data

    def test_is_pure_and_does_not_mutate_input(self) -> None:
        data = {"encrypted": True, "collected_at": "now"}
        canonicalize(data)
        assert "collected_at" in data


class TestDriftEvent:
    def test_valid_event(self) -> None:
        event = DriftEvent(
            resource_id=ResourceId("bucket-1"),
            tenant_id=TENANT,
            drift_type=DriftType.MODIFIED,
            changed_fields={"encrypted": (False, True)},
            detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert event.drift_type is DriftType.MODIFIED
        assert event.changed_fields["encrypted"] == (False, True)

    def test_added_and_removed_events_require_no_changed_fields(self) -> None:
        event = DriftEvent(
            resource_id=ResourceId("bucket-1"),
            tenant_id=TENANT,
            drift_type=DriftType.ADDED,
            changed_fields={},
            detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert event.changed_fields == {}

    def test_detected_at_must_be_timezone_aware(self) -> None:
        with pytest.raises(InvalidDriftEvent):
            DriftEvent(
                resource_id=ResourceId("bucket-1"),
                tenant_id=TENANT,
                drift_type=DriftType.ADDED,
                changed_fields={},
                detected_at=datetime(2026, 1, 1),
            )

    def test_modified_event_requires_at_least_one_changed_field(self) -> None:
        with pytest.raises(InvalidDriftEvent):
            DriftEvent(
                resource_id=ResourceId("bucket-1"),
                tenant_id=TENANT,
                drift_type=DriftType.MODIFIED,
                changed_fields={},
                detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )


class TestDiffEngine:
    def test_identical_snapshots_produce_no_drift(self) -> None:
        snapshot = {"bucket-1": {"encrypted": True}}
        events = DiffEngine.compare(tenant_id=TENANT, previous=snapshot, current=snapshot, detected_at=DETECTED_AT)
        assert events == ()

    def test_modified_resource_produces_modified_event(self) -> None:
        previous = {"bucket-1": {"encrypted": False}}
        current = {"bucket-1": {"encrypted": True}}
        events = DiffEngine.compare(tenant_id=TENANT, previous=previous, current=current, detected_at=DETECTED_AT)
        assert len(events) == 1
        assert events[0].drift_type is DriftType.MODIFIED
        assert events[0].resource_id == ResourceId("bucket-1")
        assert events[0].changed_fields == {"encrypted": (False, True)}

    def test_added_resource_produces_added_event(self) -> None:
        previous: dict = {}
        current = {"bucket-1": {"encrypted": True}}
        events = DiffEngine.compare(tenant_id=TENANT, previous=previous, current=current, detected_at=DETECTED_AT)
        assert len(events) == 1
        assert events[0].drift_type is DriftType.ADDED
        assert events[0].changed_fields == {}

    def test_removed_resource_produces_removed_event(self) -> None:
        previous = {"bucket-1": {"encrypted": True}}
        current: dict = {}
        events = DiffEngine.compare(tenant_id=TENANT, previous=previous, current=current, detected_at=DETECTED_AT)
        assert len(events) == 1
        assert events[0].drift_type is DriftType.REMOVED
        assert events[0].changed_fields == {}

    def test_volatile_collected_at_change_alone_is_not_drift(self) -> None:
        previous = {"bucket-1": {"encrypted": True, "collected_at": "t0"}}
        current = {"bucket-1": {"encrypted": True, "collected_at": "t1"}}
        events = DiffEngine.compare(tenant_id=TENANT, previous=previous, current=current, detected_at=DETECTED_AT)
        assert events == ()

    def test_multiple_resources_are_diffed_independently(self) -> None:
        previous = {
            "bucket-1": {"encrypted": True},
            "bucket-2": {"encrypted": True},
            "bucket-3": {"encrypted": True},
        }
        current = {
            "bucket-1": {"encrypted": True},  # unchanged
            "bucket-2": {"encrypted": False},  # modified
            # bucket-3 removed
            "bucket-4": {"encrypted": True},  # added
        }
        events = DiffEngine.compare(tenant_id=TENANT, previous=previous, current=current, detected_at=DETECTED_AT)
        by_resource = {e.resource_id: e.drift_type for e in events}
        assert by_resource == {
            ResourceId("bucket-2"): DriftType.MODIFIED,
            ResourceId("bucket-3"): DriftType.REMOVED,
            ResourceId("bucket-4"): DriftType.ADDED,
        }

    def test_compare_is_deterministic(self) -> None:
        previous = {"bucket-1": {"encrypted": False}}
        current = {"bucket-1": {"encrypted": True}}
        first = DiffEngine.compare(tenant_id=TENANT, previous=previous, current=current, detected_at=DETECTED_AT)
        second = DiffEngine.compare(tenant_id=TENANT, previous=previous, current=current, detected_at=DETECTED_AT)
        assert first == second
