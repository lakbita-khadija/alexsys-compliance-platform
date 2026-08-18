"""Regression tests for the three Phase 3 defects the Phase 4 audit found.

Every test here runs against the **REAL** rule catalog (`rules/aws`,
`rules/azure`), deliberately. All three defects survived 704 passing
tests precisely because the only tests exercising `ScanCloudAccount` used
a *fake* catalog containing no cross-resource rules, while the tests that
did use the real catalog bypassed `ScanCloudAccount` entirely. A fake
catalog here would recreate the exact blind spot.

See docs/architecture/phase-4-persistence-audit.md §1-§3.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from application.rules.composite_rule_catalog import CompositeRuleCatalog
from application.scanning.dtos import ScanConfiguration
from application.scanning.scan_cloud_account import ScanCloudAccount
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

_REPO_ROOT = Path(__file__).resolve().parents[3]
AWS_RULES = _REPO_ROOT / "rules" / "aws"
AZURE_RULES = _REPO_ROOT / "rules" / "azure"

TENANT = TenantId("acme")
SCANNED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def real_catalog() -> CompositeRuleCatalog:
    return CompositeRuleCatalog(YamlRuleCatalog(AWS_RULES), YamlRuleCatalog(AZURE_RULES))


def aws_resource(resource_id, resource_type, *, account_id=None, attributes=None, relationships=()):
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type=resource_type,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=SCANNED_AT,
        account_id=account_id,
    )


class StaticCollector:
    def __init__(self, resources):
        self._resources = tuple(resources)

    def collect(self):
        return self._resources


def run_scan(resources, *, provider=CloudProvider.AWS, scanned_at=SCANNED_AT):
    use_case = ScanCloudAccount(collector=StaticCollector(resources), rule_catalog=real_catalog())
    return use_case.run(
        tenant_id=TENANT,
        provider=provider,
        credentials_reference="regression-test",
        scan_configuration=ScanConfiguration(),
        scanned_at=scanned_at,
    )


def open_sg_and_instance(account_id=None):
    """A security group open to the world with an EC2 instance attached —
    the exact shape the 7 cross-resource rules evaluate.
    """

    sg = aws_resource(
        "sg-open",
        "security_group",
        account_id=account_id,
        attributes={"has_unrestricted_ingress": True, "unrestricted_ingress_ports": (22,)},
    )
    instance = aws_resource(
        "i-exposed",
        "ec2_instance",
        account_id=account_id,
        attributes={"public_ip": "203.0.113.5", "imds_v2_required": False, "root_volume_encrypted": False},
        relationships=(
            ResourceRelationship(
                target_resource_id=ResourceId("sg-open"), relationship_type=RelationshipType.ATTACHED_TO
            ),
        ),
    )
    return (sg, instance)


class TestGraphIsThreadedIntoRuleEvaluation:
    """Defect 1 (BLOCKER): `ScanCloudAccount` built the graph and never
    passed it, so every scan using the real catalog raised
    `InvalidRuleCondition` from the first cross-resource rule.
    """

    def test_scan_with_relationship_rules_does_not_raise(self) -> None:
        result = run_scan(open_sg_and_instance())
        assert result.findings, "the real catalog must produce findings"

    def test_cross_resource_rule_actually_evaluates_against_the_graph(self) -> None:
        result = run_scan(open_sg_and_instance())
        relationship_findings = [
            f
            for f in result.findings
            if f.rule_id.value == "ec2-instance-attached-to-open-security-group"
        ]
        assert relationship_findings, "the cross-resource rule must be evaluated at all"
        # It must reach a REAL verdict, not INDETERMINATE-by-omission.
        assert relationship_findings[0].status.value == "fail"

    def test_graph_is_built_and_returned_consistently_with_resources(self) -> None:
        resources = open_sg_and_instance()
        result = run_scan(resources)
        assert len(result.graph.nodes) == len(resources)

    def test_azure_scan_with_relationship_rules_also_works(self) -> None:
        nsg = NormalizedResource(
            resource_id=ResourceId("/subscriptions/s1/nsg-open"),
            resource_type="azure_network_security_group",
            cloud_provider=CloudProvider.AZURE,
            tenant_id=TENANT,
            region="westeurope",
            attributes={"name": "nsg-open", "has_unrestricted_ingress": True, "unrestricted_ingress_ports": (22,)},
            tags={},
            relationships=(),
            collected_at=SCANNED_AT,
            account_id="sub-1",
        )
        vm = NormalizedResource(
            resource_id=ResourceId("/subscriptions/s1/vm-exposed"),
            resource_type="azure_virtual_machine",
            cloud_provider=CloudProvider.AZURE,
            tenant_id=TENANT,
            region="westeurope",
            attributes={"name": "vm-exposed", "public_ip_address": "203.0.113.9", "system_assigned_identity_enabled": False},
            tags={},
            relationships=(
                ResourceRelationship(
                    target_resource_id=ResourceId("/subscriptions/s1/nsg-open"),
                    relationship_type=RelationshipType.ATTACHED_TO,
                ),
            ),
            collected_at=SCANNED_AT,
            account_id="sub-1",
        )
        result = run_scan((nsg, vm), provider=CloudProvider.AZURE)
        matching = [
            f for f in result.findings if f.rule_id.value == "azure-vm-attached-to-open-network-security-group"
        ]
        assert matching and matching[0].status.value == "fail"


class TestScanIdIsAccountQualified:
    """Defect 2 (BLOCKER for persistence): `scan_id` omitted the account,
    so two accounts scanned at the same instant collided.
    """

    def test_scan_id_includes_the_account(self) -> None:
        result = run_scan(open_sg_and_instance(account_id="111111111111"))
        assert "111111111111" in result.scan_id

    def test_two_accounts_at_the_same_instant_do_not_collide(self) -> None:
        first = run_scan(open_sg_and_instance(account_id="111111111111"))
        second = run_scan(open_sg_and_instance(account_id="222222222222"))
        assert first.scan_id != second.scan_id

    def test_scan_id_is_deterministic_for_the_same_inputs(self) -> None:
        first = run_scan(open_sg_and_instance(account_id="111111111111"))
        second = run_scan(open_sg_and_instance(account_id="111111111111"))
        assert first.scan_id == second.scan_id

    def test_unknown_account_is_explicit_not_absent(self) -> None:
        result = run_scan(open_sg_and_instance(account_id=None))
        assert "unknown-account" in result.scan_id

    def test_empty_scan_still_produces_a_scan_id(self) -> None:
        result = run_scan(())
        assert result.scan_id and "unknown-account" in result.scan_id


class TestLogicalFindingIdIsAccountSafe:
    """Defect 3 (HIGH): a missing account rendered as the literal "None",
    merging two accounts' lifecycle history onto one logical finding.
    """

    def test_logical_finding_id_never_contains_the_none_repr(self) -> None:
        result = run_scan(open_sg_and_instance(account_id=None))
        for finding in result.findings:
            assert ":None:" not in (finding.logical_finding_id or "")

    def test_unknown_account_uses_the_explicit_sentinel(self) -> None:
        result = run_scan(open_sg_and_instance(account_id=None))
        assert any("unknown-account" in (f.logical_finding_id or "") for f in result.findings)

    def test_different_accounts_produce_different_logical_ids(self) -> None:
        first = run_scan(open_sg_and_instance(account_id="111111111111"))
        second = run_scan(open_sg_and_instance(account_id="222222222222"))
        first_ids = {f.logical_finding_id for f in first.findings}
        second_ids = {f.logical_finding_id for f in second.findings}
        assert first_ids.isdisjoint(second_ids)

    def test_logical_id_is_stable_across_scans_of_the_same_account(self) -> None:
        early = run_scan(open_sg_and_instance(account_id="111111111111"), scanned_at=SCANNED_AT)
        later = run_scan(
            open_sg_and_instance(account_id="111111111111"),
            scanned_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )
        assert {f.logical_finding_id for f in early.findings} == {f.logical_finding_id for f in later.findings}

    def test_physical_finding_id_is_not_stable_across_scans(self) -> None:
        early = run_scan(open_sg_and_instance(account_id="111111111111"), scanned_at=SCANNED_AT)
        later = run_scan(
            open_sg_and_instance(account_id="111111111111"),
            scanned_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )
        assert {str(f.id) for f in early.findings}.isdisjoint({str(f.id) for f in later.findings})


class TestNoRegressionInExistingBehaviour:
    def test_tenant_isolation_still_enforced(self) -> None:
        foreign = NormalizedResource(
            resource_id=ResourceId("bucket-x"),
            resource_type="s3_bucket",
            cloud_provider=CloudProvider.AWS,
            tenant_id=TenantId("globex"),
            region="us-east-1",
            attributes={},
            tags={},
            relationships=(),
            collected_at=SCANNED_AT,
        )
        with pytest.raises(Exception):
            run_scan((foreign,))

    def test_provider_mismatch_still_rejected(self) -> None:
        with pytest.raises(Exception):
            run_scan(open_sg_and_instance(), provider=CloudProvider.AZURE)
