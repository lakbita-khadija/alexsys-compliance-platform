from datetime import datetime, timedelta, timezone

import pytest

from domain.findings.models import Evidence, Finding, FindingStatus
from domain.scans.lifecycle import LifecycleState, LogicalFinding
from domain.shared.enums import CloudProvider, Severity
from domain.shared.errors import InvalidFindingLifecycle
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId

TENANT = TenantId("acme")
SCAN1_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCAN2_AT = SCAN1_AT + timedelta(days=1)
SCAN3_AT = SCAN1_AT + timedelta(days=2)
SCAN4_AT = SCAN1_AT + timedelta(days=3)

LOGICAL_ID = "acme:111111111111:bucket-1:s3-bucket-public"


def a_finding(detected_at=SCAN1_AT, severity=Severity.CRITICAL) -> Finding:
    return Finding(
        id=FindingId(f"{LOGICAL_ID}:scan-{detected_at.isoformat()}"),
        tenant_id=TENANT,
        resource_id=ResourceId("bucket-1"),
        rule_id=RuleId("s3-bucket-public"),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        status=FindingStatus.FAIL,
        severity=severity,
        evidence=Evidence(data={"public": True}),
        detected_at=detected_at,
        account_id="111111111111",
        logical_finding_id=LOGICAL_ID,
    )


def first_seen() -> LogicalFinding:
    return LogicalFinding.first_observation(
        finding=a_finding(), provider=CloudProvider.AWS, seen_at=SCAN1_AT, scan_key="scan-1"
    )


class TestFirstObservation:
    def test_new_finding_is_open(self) -> None:
        lf = first_seen()
        assert lf.state is LifecycleState.OPEN
        assert lf.first_seen_at == SCAN1_AT
        assert lf.last_seen_at == SCAN1_AT
        assert lf.occurrence_count == 1
        assert lf.reopen_count == 0

    def test_identity_components_are_stored_separately(self) -> None:
        # Never parsed out of the opaque string — audit §3.
        lf = first_seen()
        assert lf.tenant_id == TENANT
        assert lf.account_id == "111111111111"
        assert lf.resource_id == ResourceId("bucket-1")
        assert lf.rule_id == RuleId("s3-bucket-public")

    def test_finding_without_logical_id_is_rejected(self) -> None:
        finding = Finding(
            id=FindingId("f1"),
            tenant_id=TENANT,
            resource_id=ResourceId("bucket-1"),
            rule_id=RuleId("r"),
            framework="f",
            control_id="c",
            domain="d",
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            evidence=Evidence(data={}),
            detected_at=SCAN1_AT,
        )
        with pytest.raises(InvalidFindingLifecycle, match="no logical_finding_id"):
            LogicalFinding.first_observation(
                finding=finding, provider=CloudProvider.AWS, seen_at=SCAN1_AT, scan_key="scan-1"
            )


class TestPartSevenScenario:
    """The exact four-scan sequence from Part 7 of the brief."""

    def test_scan1_detected_scan2_still_present_scan3_fixed_scan4_regressed(self) -> None:
        # Scan 1: bucket public -> detected
        lf = first_seen()
        assert lf.state is LifecycleState.OPEN
        assert lf.first_seen_scan_key == "scan-1"

        # Scan 2: still public -> same logical finding, last_seen advances
        lf = lf.observed_again(seen_at=SCAN2_AT, scan_key="scan-2")
        assert lf.state is LifecycleState.OPEN
        assert lf.first_seen_at == SCAN1_AT, "first_seen must never move"
        assert lf.last_seen_at == SCAN2_AT
        assert lf.occurrence_count == 2

        # Scan 3: bucket fixed -> absent -> RESOLVED (never deleted)
        lf = lf.resolve(resolved_at=SCAN3_AT, scan_key="scan-3")
        assert lf.state is LifecycleState.RESOLVED
        assert lf.resolved_at == SCAN3_AT
        assert lf.first_seen_at == SCAN1_AT, "history is preserved through resolution"

        # Scan 4: public again -> same logical issue -> REOPENED
        lf = lf.observed_again(seen_at=SCAN4_AT, scan_key="scan-4")
        assert lf.state is LifecycleState.REOPENED
        assert lf.reopen_count == 1
        assert lf.resolved_at is None
        assert lf.first_seen_at == SCAN1_AT, "the original discovery date survives a regression"
        assert lf.occurrence_count == 3


class TestReopenSemantics:
    def test_reopened_is_distinct_from_open(self) -> None:
        # A regression is a different signal from a never-fixed issue.
        lf = first_seen().resolve(resolved_at=SCAN2_AT, scan_key="s2")
        lf = lf.observed_again(seen_at=SCAN3_AT, scan_key="s3")
        assert lf.state is LifecycleState.REOPENED
        assert lf.state is not LifecycleState.OPEN

    def test_both_open_and_reopened_are_active(self) -> None:
        assert LifecycleState.OPEN.is_active
        assert LifecycleState.REOPENED.is_active
        assert not LifecycleState.RESOLVED.is_active
        assert not LifecycleState.SUPPRESSED.is_active

    def test_repeated_regressions_increment_the_counter(self) -> None:
        lf = first_seen()
        for i in range(3):
            lf = lf.resolve(resolved_at=SCAN2_AT, scan_key=f"r{i}")
            lf = lf.observed_again(seen_at=SCAN3_AT, scan_key=f"o{i}")
        assert lf.reopen_count == 3

    def test_reopened_can_resolve_again(self) -> None:
        lf = first_seen().resolve(resolved_at=SCAN2_AT, scan_key="s2")
        lf = lf.observed_again(seen_at=SCAN3_AT, scan_key="s3")
        lf = lf.resolve(resolved_at=SCAN4_AT, scan_key="s4")
        assert lf.state is LifecycleState.RESOLVED


class TestSuppression:
    def test_open_can_be_suppressed(self) -> None:
        lf = first_seen().suppress(reason="accepted risk: public by design")
        assert lf.state is LifecycleState.SUPPRESSED
        assert lf.suppressed_reason

    def test_suppression_requires_a_reason(self) -> None:
        with pytest.raises(InvalidFindingLifecycle, match="non-blank reason"):
            first_seen().suppress(reason="  ")

    def test_suppressed_finding_seen_again_stays_suppressed(self) -> None:
        # An accepted risk that is still present is not a new alert.
        lf = first_seen().suppress(reason="accepted")
        lf = lf.observed_again(seen_at=SCAN2_AT, scan_key="s2")
        assert lf.state is LifecycleState.SUPPRESSED
        assert lf.last_seen_at == SCAN2_AT, "last_seen still advances"
        assert lf.occurrence_count == 2

    def test_unsuppress_restores_open(self) -> None:
        lf = first_seen().suppress(reason="accepted").unsuppress()
        assert lf.state is LifecycleState.OPEN

    def test_unsuppress_restores_reopened_if_it_had_regressed(self) -> None:
        lf = first_seen().resolve(resolved_at=SCAN2_AT, scan_key="s2")
        lf = lf.observed_again(seen_at=SCAN3_AT, scan_key="s3")  # REOPENED
        lf = lf.suppress(reason="accepted").unsuppress()
        assert lf.state is LifecycleState.REOPENED

    def test_cannot_unsuppress_a_non_suppressed_finding(self) -> None:
        with pytest.raises(InvalidFindingLifecycle):
            first_seen().unsuppress()


class TestIllegalTransitions:
    def test_resolved_cannot_be_resolved_again(self) -> None:
        lf = first_seen().resolve(resolved_at=SCAN2_AT, scan_key="s2")
        with pytest.raises(InvalidFindingLifecycle, match="illegal lifecycle transition"):
            lf.resolve(resolved_at=SCAN3_AT, scan_key="s3")

    def test_resolved_state_requires_resolved_at(self) -> None:
        with pytest.raises(InvalidFindingLifecycle, match="must carry resolved_at"):
            LogicalFinding(
                logical_finding_id=LOGICAL_ID,
                tenant_id=TENANT,
                provider=CloudProvider.AWS,
                account_id="1",
                resource_id=ResourceId("b"),
                rule_id=RuleId("r"),
                state=LifecycleState.RESOLVED,
                severity=Severity.HIGH,
                first_seen_at=SCAN1_AT,
                last_seen_at=SCAN1_AT,
                first_seen_scan_key="s1",
                last_seen_scan_key="s1",
            )

    def test_last_seen_cannot_precede_first_seen(self) -> None:
        with pytest.raises(InvalidFindingLifecycle, match="must not precede"):
            LogicalFinding(
                logical_finding_id=LOGICAL_ID,
                tenant_id=TENANT,
                provider=CloudProvider.AWS,
                account_id="1",
                resource_id=ResourceId("b"),
                rule_id=RuleId("r"),
                state=LifecycleState.OPEN,
                severity=Severity.HIGH,
                first_seen_at=SCAN2_AT,
                last_seen_at=SCAN1_AT,
                first_seen_scan_key="s1",
                last_seen_scan_key="s1",
            )


class TestImmutabilityAndSeverity:
    def test_transitions_return_new_objects(self) -> None:
        lf = first_seen()
        assert lf.observed_again(seen_at=SCAN2_AT, scan_key="s2") is not lf
        assert lf.occurrence_count == 1, "the original is untouched"

    def test_severity_can_be_refreshed_when_a_rule_is_re_rated(self) -> None:
        lf = first_seen()
        assert lf.severity is Severity.CRITICAL
        lf = lf.observed_again(seen_at=SCAN2_AT, scan_key="s2", severity=Severity.HIGH)
        assert lf.severity is Severity.HIGH

    def test_severity_is_retained_when_not_supplied(self) -> None:
        lf = first_seen().observed_again(seen_at=SCAN2_AT, scan_key="s2")
        assert lf.severity is Severity.CRITICAL
