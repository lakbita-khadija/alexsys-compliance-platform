"""STEP 6.5 — the gate inside a real scan, end to end (§13, §14).

One distinction runs through this whole file and reversing it would be a
serious defect:

    AccessDenied reading a security group  →  UNKNOWN, the scan continues
    Authenticated as the wrong account     →  the scan is rejected

The first is uncertainty about a *resource*. The second means we are
looking at the wrong estate entirely, and no downstream care repairs a
scan that collected someone else's infrastructure under this tenant's
name.

These run the real `ScanCloudAccount` — real graph build, real rule
evaluation, real attack path analysis — over a fake collector. No cloud
account is involved.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from application.scanning.dtos import ScanConfiguration
from application.scanning.scan_cloud_account import ScanCloudAccount
from application.scanning.verify_cloud_identity import (
    CloudAuthenticationFailure,
    VerifyCloudIdentity,
)
from domain.audit.models import AuditAction
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.errors import CloudIdentityMismatch
from domain.shared.identifiers import ResourceId, TenantId
from domain.shared.unknown import UNKNOWN
from domain.tenants.cloud_accounts import AuthenticatedCloudIdentity, CloudAccountBinding
from infrastructure.cloud.account_directory import StaticCloudAccountDirectory
from tests.unit.application.test_verify_cloud_identity import RecordingAudit

ACME = TenantId("acme")
AWS_A = "111111111111"
AWS_B = "222222222222"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class RecordingCollector:
    """A collector that notices whether it was allowed to run at all."""

    def __init__(self, resources=()) -> None:
        self._resources = tuple(resources)
        self.collected = False

    def collect(self):
        self.collected = True
        return self._resources


class StubIdentity:
    def __init__(self, account: str) -> None:
        self._account = account

    def authenticated_identity(self):
        return AuthenticatedCloudIdentity(
            provider=CloudProvider.AWS,
            account_id=self._account,
            principal=f"arn:aws:iam::{self._account}:role/scanner",
        )


class EmptyCatalog:
    def load(self, rule_ids=None):
        return ()


def a_bucket(*, public=True, encrypted=True):
    return NormalizedResource(
        resource_id=ResourceId("bucket-1"),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=ACME,
        region="us-east-1",
        attributes={"public": public, "encrypted": encrypted},
        tags={},
        relationships=(),
        collected_at=NOW,
        account_id=AWS_A,
    )


def scanner(*, authenticated_account, bound_account=AWS_A, resources=(), audit=None):
    collector = RecordingCollector(resources)
    gate = VerifyCloudIdentity(
        identity_provider=StubIdentity(authenticated_account),
        directory=StaticCloudAccountDirectory(
            [
                CloudAccountBinding(
                    tenant_id=ACME, provider=CloudProvider.AWS, account_id=bound_account
                )
            ]
            if bound_account is not None
            else []
        ),
        audit=audit,
    )
    use_case = ScanCloudAccount(
        collector=collector, rule_catalog=EmptyCatalog(), verify_identity=gate
    )
    return use_case, collector


def run(use_case, **kwargs):
    return use_case.run(
        tenant_id=ACME,
        provider=CloudProvider.AWS,
        credentials_reference="aws-profile://scanner",
        scan_configuration=ScanConfiguration(),
        scanned_at=NOW,
        **kwargs,
    )


class TestTheCorrectAccountScans:
    def test_a_scan_proceeds(self) -> None:
        use_case, collector = scanner(
            authenticated_account=AWS_A, resources=[a_bucket()]
        )
        result = run(use_case)
        assert collector.collected is True
        assert len(result.resources) == 1

    def test_the_pipeline_runs_to_completion(self) -> None:
        use_case, _ = scanner(authenticated_account=AWS_A, resources=[a_bucket()])
        result = run(use_case)
        # Graph built, rules evaluated, attack paths analyzed — the gate
        # is a precondition, not a replacement for the pipeline.
        assert result.graph is not None
        assert result.findings == ()


class TestTheWrongAccountIsRejected:
    def test_the_scan_raises(self) -> None:
        use_case, _ = scanner(
            authenticated_account=AWS_B, bound_account=AWS_A, resources=[a_bucket()]
        )
        with pytest.raises(CloudIdentityMismatch):
            run(use_case)

    def test_nothing_is_collected(self) -> None:
        """The load-bearing assertion of this entire step.

        Rejecting *after* collection would be theatre: the resources
        would already exist in memory tagged with this tenant, and the
        misattribution the gate exists to prevent would have happened.
        """

        use_case, collector = scanner(
            authenticated_account=AWS_B, bound_account=AWS_A, resources=[a_bucket()]
        )
        with pytest.raises(CloudIdentityMismatch):
            run(use_case)
        assert collector.collected is False

    def test_an_unbound_tenant_is_rejected(self) -> None:
        use_case, collector = scanner(
            authenticated_account=AWS_A, bound_account=None, resources=[a_bucket()]
        )
        with pytest.raises(CloudIdentityMismatch):
            run(use_case)
        assert collector.collected is False

    def test_the_rejection_is_audited(self) -> None:
        audit = RecordingAudit()
        use_case, _ = scanner(
            authenticated_account=AWS_B, bound_account=AWS_A, audit=audit
        )
        with pytest.raises(CloudIdentityMismatch):
            run(use_case)
        assert audit.events[0]["action"] is AuditAction.AUTHENTICATION_FAILED

    def test_the_correlation_id_reaches_the_audit_event(self) -> None:
        audit = RecordingAudit()
        use_case, _ = scanner(
            authenticated_account=AWS_B, bound_account=AWS_A, audit=audit
        )
        with pytest.raises(CloudIdentityMismatch):
            run(use_case, correlation_id="scan-corr-1")
        assert audit.events[0]["correlation_id"] == "scan-corr-1"


class TestIdentityUnavailableIsRejected:
    def test_a_failing_identity_provider_stops_the_scan(self) -> None:
        class Broken:
            def authenticated_identity(self):
                raise RuntimeError("STS unreachable")

        collector = RecordingCollector([a_bucket()])
        use_case = ScanCloudAccount(
            collector=collector,
            rule_catalog=EmptyCatalog(),
            verify_identity=VerifyCloudIdentity(
                identity_provider=Broken(),
                directory=StaticCloudAccountDirectory(
                    [
                        CloudAccountBinding(
                            tenant_id=ACME, provider=CloudProvider.AWS, account_id=AWS_A
                        )
                    ]
                ),
            ),
        )
        with pytest.raises(CloudAuthenticationFailure):
            run(use_case)
        assert collector.collected is False


class TestResourceUncertaintyIsNotAnIdentityFailure:
    """The semantics that must never be reversed.

    A denied resource-level API call is a gap in what we can see about
    one resource. It produces `UNKNOWN` and the scan continues. Treating
    it like an identity failure would abort scans over a single
    unreadable security group; treating an identity failure like it would
    silently collect the wrong estate.
    """

    def test_unknown_attributes_do_not_stop_a_correctly_authenticated_scan(self) -> None:
        denied = NormalizedResource(
            resource_id=ResourceId("sg-1"),
            resource_type="security_group",
            cloud_provider=CloudProvider.AWS,
            tenant_id=ACME,
            region="us-east-1",
            # Exactly what a collector records on AccessDenied.
            attributes={"has_unrestricted_ingress": UNKNOWN},
            tags={},
            relationships=(),
            collected_at=NOW,
            account_id=AWS_A,
        )
        use_case, collector = scanner(authenticated_account=AWS_A, resources=[denied])

        result = run(use_case)

        assert collector.collected is True
        assert len(result.resources) == 1
        # And the uncertainty survives as uncertainty rather than being
        # coerced to a boolean at any point.
        assert result.resources[0].attributes["has_unrestricted_ingress"] is UNKNOWN

    def test_a_wrong_account_is_not_degraded_to_unknown(self) -> None:
        # The inverse mistake: an identity mismatch must never become a
        # resource-level uncertainty that the scan shrugs off.
        use_case, _ = scanner(
            authenticated_account=AWS_B, bound_account=AWS_A, resources=[a_bucket()]
        )
        with pytest.raises(CloudIdentityMismatch):
            run(use_case)


class TestBackwardCompatibility:
    def test_a_scan_without_a_gate_still_runs(self) -> None:
        """Every pre-STEP-6.5 caller keeps working.

        The conformance suite, the collector tests and the dev script all
        construct a collector directly and never authenticate. Making the
        gate mandatory would have broken them into silence.
        """

        use_case = ScanCloudAccount(
            collector=RecordingCollector([a_bucket()]), rule_catalog=EmptyCatalog()
        )
        assert len(run(use_case).resources) == 1
