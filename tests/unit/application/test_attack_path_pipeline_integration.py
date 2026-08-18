"""Proves attack path analysis runs in the REAL scan pipeline (§14, §16).

Not a unit test of the analyzer — `test_attack_path_analysis.py` covers
that. This drives `ScanCloudAccount.run()`, the same entry point
`SubmitScan` and the AWS/Azure integration tests use, and asserts the
whole chain end to end:

    collect -> normalize -> build graph -> evaluate rules
    -> analyze attack paths -> enrich risk -> ScanResult

It exists because of a specific past defect class in this codebase: the
graph was built and never passed to the rule engine, and 21 collector
tests missed it because every one asserted on components in isolation.
The seam is where things break, so the seam is what gets tested.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from application.attack_paths.analyze_attack_paths import (
    SCENARIO_DATA_FLOW_TO_EXPOSED_STORE,
    SCENARIO_EXPOSED_DATA,
    SCENARIO_PUBLIC_IDENTITY,
)
from application.scanning.collector import BaseCollector
from application.scanning.dtos import ScanConfiguration
from application.scanning.scan_cloud_account import ScanCloudAccount
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.rules.rule import Rule
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId

TENANT = TenantId("acme")
SCANNED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
RT = RelationshipType


def resource(rid, rtype, attributes=None, relationships=()):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=SCANNED_AT,
        account_id="111111111111",
    )


class StaticCollector(BaseCollector):
    def __init__(self, resources):
        self._resources = tuple(resources)

    def collect(self):
        return self._resources


class StaticCatalog:
    def __init__(self, rules):
        self._rules = tuple(rules)

    def load(self):
        return self._rules


PUBLIC_BUCKET_RULE = Rule(
    id=RuleId("s3-bucket-public"),
    framework="iso_27001",
    control_id="A.8.24",
    domain="storage",
    severity=Severity.CRITICAL,
    condition={"field": "public", "operator": "is_true"},
    applies_to_resource_type="s3_bucket",
)


@pytest.fixture
def estate():
    """An estate with all three evidenced exposure shapes at once."""

    return [
        resource("bucket-public", "s3_bucket", {"public": True}),
        resource("bucket-private", "s3_bucket", {"public": False}),
        resource("trail-1", "cloudtrail", {}, (
            ResourceRelationship(
                target_resource_id=ResourceId("bucket-public"),
                relationship_type=RT.ACCESSES,
            ),
        )),
        resource(
            "role/admin",
            "iam_role",
            {"is_publicly_assumable": True, "has_administrator_access": True},
            (
                ResourceRelationship(
                    target_resource_id=ResourceId("internet"),
                    relationship_type=RT.PUBLICLY_EXPOSED,
                ),
            ),
        ),
    ]


def run(estate, rules=(PUBLIC_BUCKET_RULE,)):
    return ScanCloudAccount(
        collector=StaticCollector(estate), rule_catalog=StaticCatalog(rules)
    ).run(
        tenant_id=TENANT,
        provider=CloudProvider.AWS,
        credentials_reference="ref-1",
        scan_configuration=ScanConfiguration(),
        scanned_at=SCANNED_AT,
    )


class TestPipelineExecutesAttackPathAnalysis:
    def test_the_real_scan_produces_attack_paths(self, estate) -> None:
        result = run(estate)
        assert len(result.attack_paths) >= 3
        assert {p.scenario for p in result.attack_paths} >= {
            SCENARIO_PUBLIC_IDENTITY,
            SCENARIO_EXPOSED_DATA,
            SCENARIO_DATA_FLOW_TO_EXPOSED_STORE,
        }

    def test_resources_reach_the_analyzer(self, estate) -> None:
        """The wiring defect this guards against.

        Graph nodes carry no attributes, so if `resources` were not
        threaded through `ScanCloudAccount`, the attribute-driven
        scenarios would silently find nothing — a smaller result, not an
        error, and therefore easy to miss.
        """

        assert any(p.scenario == SCENARIO_EXPOSED_DATA for p in run(estate).attack_paths)

    def test_paths_are_ordered_by_risk(self, estate) -> None:
        scores = [p.risk_score for p in run(estate).attack_paths]
        assert scores == sorted(scores, reverse=True)

    def test_the_whole_pipeline_is_deterministic(self, estate) -> None:
        first = run(estate)
        second = run(estate)
        assert [(str(p.id), p.risk_score, p.severity) for p in first.attack_paths] == [
            (str(p.id), p.risk_score, p.severity) for p in second.attack_paths
        ]
        assert [(str(f.id), f.risk) for f in first.findings] == [
            (str(f.id), f.risk) for f in second.findings
        ]


class TestPipelineEnrichesRisk:
    def test_findings_come_back_with_a_risk_score(self, estate) -> None:
        for finding in run(estate).findings:
            assert finding.risk is not None

    def test_a_finding_on_a_path_references_it(self, estate) -> None:
        result = run(estate)
        public = next(f for f in result.findings if str(f.resource_id) == "bucket-public")
        assert public.related_attack_path_ids
        assert all(
            pid in {p.id for p in result.attack_paths} for pid in public.related_attack_path_ids
        )

    def test_exposure_context_raises_risk_above_an_identical_isolated_finding(
        self, estate
    ) -> None:
        result = run(estate)
        public = next(f for f in result.findings if str(f.resource_id) == "bucket-public")
        private = next(f for f in result.findings if str(f.resource_id) == "bucket-private")

        # Same rule, same severity, same control. The ONLY difference is
        # that one sits on an attack path — which is the entire point of
        # contextual risk.
        assert public.severity is private.severity
        assert public.risk > private.risk

    def test_findings_without_paths_are_unbroken(self, estate) -> None:
        private = next(
            f for f in run(estate).findings if str(f.resource_id) == "bucket-private"
        )
        assert private.related_attack_path_ids == ()
        assert private.risk is not None

    def test_finding_count_and_order_are_unchanged_by_enrichment(self, estate) -> None:
        # Enrichment replaces fields; it must not add, drop or reorder
        # findings, because persistence and scoring both depend on that.
        result = run(estate)
        assert [str(f.resource_id) for f in result.findings] == ["bucket-public", "bucket-private"]


class TestPipelineSafety:
    def test_an_empty_estate_scans_cleanly(self) -> None:
        result = run([])
        assert result.attack_paths == ()
        assert result.findings == ()

    def test_an_estate_with_no_exposure_produces_no_paths(self) -> None:
        result = run([resource("bucket-private", "s3_bucket", {"public": False})])
        assert result.attack_paths == ()
        # ...but the finding still exists and still carries risk.
        assert len(result.findings) == 1
        assert result.findings[0].risk is not None

    def test_the_real_rule_catalog_still_scans_with_attack_paths_enabled(self) -> None:
        """Guards the seam between the shipped catalog and the analyzer.

        The 68-rule catalog contains 7 cross-resource rules; this asserts
        adding attack-path analysis did not disturb them.
        """

        from pathlib import Path

        from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

        catalog = YamlRuleCatalog(Path(__file__).resolve().parents[3] / "rules" / "aws")
        result = ScanCloudAccount(
            collector=StaticCollector(
                [resource("bucket-public", "s3_bucket", {"public": True})]
            ),
            rule_catalog=catalog,
        ).run(
            tenant_id=TENANT,
            provider=CloudProvider.AWS,
            credentials_reference="ref-1",
            scan_configuration=ScanConfiguration(),
            scanned_at=SCANNED_AT,
        )
        assert result.findings
        assert any(p.scenario == SCENARIO_EXPOSED_DATA for p in result.attack_paths)
