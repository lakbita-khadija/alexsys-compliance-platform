from datetime import datetime, timezone

import pytest

from application.errors import ResourceCollectionError
from application.rules.rule_catalog import LoadRuleCatalog
from application.scanning.collector import BaseCollector
from application.scanning.dtos import ScanConfiguration
from application.scanning.scan_cloud_account import ScanCloudAccount
from domain.findings.models import FindingStatus
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.rules.rule import Rule
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import ResourceId, RuleId, TenantId

SCANNED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")


def make_resource(resource_id="bucket-1", tenant_id=TENANT_A, attributes=None, relationships=(), provider=CloudProvider.AWS):
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="s3_bucket",
        cloud_provider=provider,
        tenant_id=tenant_id,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=SCANNED_AT,
    )


def make_rule(rule_id="rule-1", condition=None):
    return Rule(
        id=RuleId(rule_id),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        severity=Severity.HIGH,
        condition=condition or {"field": "public", "operator": "equals", "value": True},
    )


class FakeCollector(BaseCollector):
    def __init__(self, resources):
        self._resources = tuple(resources)
        self.call_count = 0

    def collect(self):
        self.call_count += 1
        return self._resources


class FailingCollector(BaseCollector):
    def collect(self):
        raise ConnectionError("could not reach the cloud API")


class FakeRuleCatalog(LoadRuleCatalog):
    def __init__(self, rules):
        self._rules = tuple(rules)
        self.call_count = 0

    def load(self):
        self.call_count += 1
        return self._rules


def make_use_case(resources, rules):
    return ScanCloudAccount(collector=FakeCollector(resources), rule_catalog=FakeRuleCatalog(rules))


class TestSuccessfulScan:
    def test_returns_a_scan_result_with_all_pipeline_outputs_populated(self) -> None:
        resource = make_resource(attributes={"public": True})
        use_case = make_use_case([resource], [make_rule()])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert result.tenant_id == TENANT_A
        assert result.provider is CloudProvider.AWS
        assert result.scanned_at == SCANNED_AT
        assert result.resources == (resource,)
        assert result.graph.has_node(ResourceId("bucket-1"))
        assert len(result.findings) == 1
        # This assertion used to read `== ()`, which encoded the
        # AnalyzeAttackPaths placeholder rather than any intended
        # behaviour. The fixture is a bucket with `public: True` — a
        # genuinely internet-readable data store — so the analyzer now
        # correctly reports one path. Strengthened, not weakened: it
        # asserts real discovery where it previously asserted emptiness.
        assert len(result.attack_paths) == 1
        assert result.attack_paths[0].scenario == "internet_to_sensitive_data"
        # Risk enrichment now runs, so the finding carries a score and a
        # reference back to the path. Both fields existed since Phase 1
        # and were never populated.
        assert result.findings[0].risk is not None
        assert result.findings[0].related_attack_path_ids == (result.attack_paths[0].id,)
        assert result.drift_events == ()

    def test_scan_id_is_deterministic(self) -> None:
        resource = make_resource()
        use_case = make_use_case([resource], [make_rule()])
        first = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        second = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert first.scan_id == second.scan_id
        assert first.findings[0].scan_id == first.scan_id


class TestGraphConstruction:
    def test_graph_reflects_resource_relationships(self) -> None:
        bucket = make_resource("bucket-1")
        sg = make_resource(
            "sg-1",
            relationships=(
                ResourceRelationship(
                    target_resource_id=ResourceId("bucket-1"),
                    relationship_type=RelationshipType.PROTECTS,
                ),
            ),
        )
        use_case = make_use_case([sg, bucket], [])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert len(result.graph.edges) == 1


class TestRuleEvaluationOutcomes:
    def test_fail_finding_when_condition_matches(self) -> None:
        resource = make_resource(attributes={"public": True})
        use_case = make_use_case([resource], [make_rule()])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert result.findings[0].status is FindingStatus.FAIL

    def test_pass_finding_when_condition_does_not_match(self) -> None:
        resource = make_resource(attributes={"public": False})
        use_case = make_use_case([resource], [make_rule()])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert result.findings[0].status is FindingStatus.PASS

    def test_indeterminate_finding_when_data_is_missing(self) -> None:
        resource = make_resource(attributes={})
        use_case = make_use_case([resource], [make_rule()])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert result.findings[0].status is FindingStatus.INDETERMINATE

    def test_scan_configuration_filters_which_rules_run(self) -> None:
        resource = make_resource(attributes={"public": True})
        rules = [make_rule("rule-1"), make_rule("rule-2")]
        use_case = make_use_case([resource], rules)
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(rule_ids=(RuleId("rule-1"),)),
            scanned_at=SCANNED_AT,
        )
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == RuleId("rule-1")


class TestEmptyAndMultipleResources:
    def test_empty_resource_collection_produces_an_empty_result(self) -> None:
        use_case = make_use_case([], [make_rule()])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert result.resources == ()
        assert result.graph.nodes == ()
        assert result.findings == ()

    def test_multiple_resources_are_all_processed(self) -> None:
        resources = [make_resource(f"bucket-{i}", attributes={"public": True}) for i in range(5)]
        use_case = make_use_case(resources, [make_rule()])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert len(result.resources) == 5
        assert len(result.findings) == 5
        assert len(result.graph.nodes) == 5


class TestTenantIsolation:
    def test_collector_returning_a_foreign_tenant_resource_is_rejected(self) -> None:
        resource = make_resource(tenant_id=TENANT_B)
        use_case = make_use_case([resource], [make_rule()])
        with pytest.raises(TenantIsolationViolation):
            use_case.run(
                tenant_id=TENANT_A,
                provider=CloudProvider.AWS,
                credentials_reference="ref-1",
                scan_configuration=ScanConfiguration(),
                scanned_at=SCANNED_AT,
            )

    def test_foreign_tenant_resource_is_rejected_before_any_finding_is_produced(self) -> None:
        good = make_resource("bucket-1", tenant_id=TENANT_A)
        bad = make_resource("bucket-2", tenant_id=TENANT_B)
        use_case = make_use_case([good, bad], [make_rule()])
        with pytest.raises(TenantIsolationViolation):
            use_case.run(
                tenant_id=TENANT_A,
                provider=CloudProvider.AWS,
                credentials_reference="ref-1",
                scan_configuration=ScanConfiguration(),
                scanned_at=SCANNED_AT,
            )


class TestProviderIntegrity:
    def test_resource_reporting_a_different_provider_than_declared_is_rejected(self) -> None:
        resource = make_resource(provider=CloudProvider.AZURE)
        use_case = make_use_case([resource], [make_rule()])
        with pytest.raises(ResourceCollectionError):
            use_case.run(
                tenant_id=TENANT_A,
                provider=CloudProvider.AWS,
                credentials_reference="ref-1",
                scan_configuration=ScanConfiguration(),
                scanned_at=SCANNED_AT,
            )


class TestDependencyFailure:
    def test_collector_failure_is_wrapped_not_swallowed(self) -> None:
        use_case = ScanCloudAccount(collector=FailingCollector(), rule_catalog=FakeRuleCatalog([make_rule()]))
        with pytest.raises(ResourceCollectionError) as exc_info:
            use_case.run(
                tenant_id=TENANT_A,
                provider=CloudProvider.AWS,
                credentials_reference="ref-1",
                scan_configuration=ScanConfiguration(),
                scanned_at=SCANNED_AT,
            )
        assert isinstance(exc_info.value.__cause__, ConnectionError)


class TestInvalidInputs:
    def test_blank_credentials_reference_is_rejected(self) -> None:
        use_case = make_use_case([], [])
        with pytest.raises(ValueError):
            use_case.run(
                tenant_id=TENANT_A,
                provider=CloudProvider.AWS,
                credentials_reference="   ",
                scan_configuration=ScanConfiguration(),
                scanned_at=SCANNED_AT,
            )

    def test_naive_scanned_at_is_rejected(self) -> None:
        use_case = make_use_case([], [])
        with pytest.raises(ValueError):
            use_case.run(
                tenant_id=TENANT_A,
                provider=CloudProvider.AWS,
                credentials_reference="ref-1",
                scan_configuration=ScanConfiguration(),
                scanned_at=datetime(2026, 1, 1),
            )


class TestPortCalls:
    def test_collector_and_rule_catalog_are_each_called_exactly_once(self) -> None:
        collector = FakeCollector([make_resource()])
        catalog = FakeRuleCatalog([make_rule()])
        use_case = ScanCloudAccount(collector=collector, rule_catalog=catalog)
        use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert collector.call_count == 1
        assert catalog.call_count == 1


class TestDeterminism:
    def test_identical_inputs_produce_identical_findings(self) -> None:
        resource = make_resource(attributes={"public": True})
        use_case = make_use_case([resource], [make_rule()])
        first = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        second = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert [f.id for f in first.findings] == [f.id for f in second.findings]
        assert [f.status for f in first.findings] == [f.status for f in second.findings]


class TestDriftIntegration:
    def test_drift_is_detected_when_previous_snapshot_is_supplied(self) -> None:
        resource = make_resource("bucket-1", attributes={"public": True})
        use_case = make_use_case([resource], [])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
            previous_snapshot={"bucket-1": {"public": False}},
        )
        assert len(result.drift_events) == 1

    def test_no_drift_events_when_no_previous_snapshot_is_supplied(self) -> None:
        resource = make_resource("bucket-1")
        use_case = make_use_case([resource], [])
        result = use_case.run(
            tenant_id=TENANT_A,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert result.drift_events == ()
