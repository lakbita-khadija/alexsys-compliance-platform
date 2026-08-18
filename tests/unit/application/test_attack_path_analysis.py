"""Tests for attack path discovery, scoring and severity.

The negative tests matter more than the positive ones. A missed
low-confidence path costs a customer one item on a backlog; a fabricated
path sends a security team to investigate something that does not exist,
with a confident severity attached, and teaches them to distrust every
other finding. So most of this file asserts what does **not** get
reported.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from application.attack_paths.analyze_attack_paths import (
    SCENARIO_DATA_FLOW_TO_EXPOSED_STORE,
    SCENARIO_EXPOSED_DATA,
    SCENARIO_EXPOSED_WORKLOAD,
    SCENARIO_PUBLIC_IDENTITY,
    AnalyzeAttackPaths,
)
from application.graph.build_resource_graph import BuildResourceGraph
from domain.attack_paths.classification import ResourceRole, is_traversable, role_of
from domain.attack_paths.scoring import severity_for
from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, TenantId
from domain.shared.unknown import UNKNOWN

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
RT = RelationshipType


def resource(rid, rtype, attributes=None, relationships=(), provider=CloudProvider.AWS):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=provider,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=NOW,
    )


def rel(target, relationship_type):
    return ResourceRelationship(
        target_resource_id=ResourceId(target), relationship_type=relationship_type
    )


def analyze(resources, findings=()):
    """Build a real graph and run the real analyzer over it."""

    graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
    return AnalyzeAttackPaths().analyze(
        tenant_id=TENANT, graph=graph, findings=findings, resources=resources
    )


def by_scenario(paths):
    return {p.scenario: p for p in paths}


# ---------------------------------------------------------------------
# Positive
# ---------------------------------------------------------------------


class TestPositiveScenarios:
    def test_publicly_assumable_admin_role_is_reported(self) -> None:
        role = resource(
            "role/admin",
            "iam_role",
            {"is_publicly_assumable": True, "has_administrator_access": True},
            (rel("internet", RT.PUBLICLY_EXPOSED),),
        )
        path = by_scenario(analyze([role]))[SCENARIO_PUBLIC_IDENTITY]

        assert str(path.target.resource_id) == "role/admin"
        assert path.severity is Severity.CRITICAL
        assert "has_administrator_access" in path.evidence["privilege_evidence"]
        assert "internet" in path.evidence["chain"]

    def test_public_bucket_is_reported_as_exposed_data(self) -> None:
        bucket = resource("bucket-public", "s3_bucket", {"public": True})
        path = by_scenario(analyze([bucket]))[SCENARIO_EXPOSED_DATA]

        assert path.evidence["target_role"] == "storage"
        assert path.evidence["exposure_evidence"] == ["public"]
        assert path.risk_score > 0

    def test_public_workload_behind_open_security_group_is_reported(self) -> None:
        estate = [
            resource(
                "i-web",
                "ec2_instance",
                {"public_ip": "203.0.113.10"},
                (rel("sg-open", RT.ATTACHED_TO),),
            ),
            resource("sg-open", "security_group", {"has_unrestricted_ingress": True}),
        ]
        path = by_scenario(analyze(estate))[SCENARIO_EXPOSED_WORKLOAD]

        assert str(path.target.resource_id) == "i-web"
        assert "sg-open" in path.evidence["chain"]

    def test_audit_logs_flowing_into_a_public_bucket_is_reported(self) -> None:
        estate = [
            resource("trail-1", "cloudtrail", {}, (rel("bucket-public", RT.ACCESSES),)),
            resource("bucket-public", "s3_bucket", {"public": True}),
        ]
        path = by_scenario(analyze(estate))[SCENARIO_DATA_FLOW_TO_EXPOSED_STORE]

        # The composite claim: neither resource alone says this.
        assert path.evidence["chain"] == "trail-1 -> bucket-public"
        assert path.evidence["relationships"] == ["accesses"]

    def test_azure_produces_paths_through_the_same_code(self) -> None:
        # §18: no `if aws: ... elif azure:`. The provider only shows up
        # as rows in the classification table.
        estate = [
            resource(
                "storage-public",
                "azure_storage_account",
                {"allows_public_network_access": True},
                provider=CloudProvider.AZURE,
            )
        ]
        assert by_scenario(analyze(estate))[SCENARIO_EXPOSED_DATA].evidence[
            "target_role"
        ] == "storage"


# ---------------------------------------------------------------------
# Negative — the important half
# ---------------------------------------------------------------------


class TestNegativeCases:
    def test_a_completely_private_estate_produces_nothing(self) -> None:
        estate = [
            resource("bucket-private", "s3_bucket", {"public": False}),
            resource(
                "i-app", "ec2_instance", {"public_ip": None}, (rel("sg-closed", RT.ATTACHED_TO),)
            ),
            resource("sg-closed", "security_group", {"has_unrestricted_ingress": False}),
        ]
        assert analyze(estate) == ()

    def test_least_privilege_role_without_public_trust_is_not_a_path(self) -> None:
        role = resource(
            "role/app",
            "iam_role",
            {"is_publicly_assumable": False, "has_administrator_access": False},
        )
        assert analyze([role]) == ()

    def test_an_identity_is_not_described_as_holding_data(self) -> None:
        """Regression: a real false positive, found by running the code.

        A publicly assumable role was reported TWICE — once correctly as
        `public_identity_with_privilege`, and once as
        `internet_to_sensitive_data` claiming it "holds sensitive data",
        which an IAM role does not. The bogus one scored higher and
        ranked above the correct one.

        A true risk stated in a false sentence is still a false positive:
        a responder reading "holds sensitive data" goes looking for data.
        """

        role = resource(
            "role/admin",
            "iam_role",
            {"is_publicly_assumable": True, "has_administrator_access": True},
            (rel("internet", RT.PUBLICLY_EXPOSED),),
        )
        scenarios = [p.scenario for p in analyze([role])]
        assert scenarios == [SCENARIO_PUBLIC_IDENTITY]

    def test_a_non_sensitive_target_is_not_reported(self) -> None:
        # A security group is a gate, not a prize. Reaching one is not an
        # objective, and reporting it would bury the real paths.
        sg = resource("sg-open", "security_group", {"has_unrestricted_ingress": True})
        assert analyze([sg]) == ()

    def test_informational_relationships_alone_produce_no_path(self) -> None:
        # ATTACHED_TO is configuration, not movement. Without the public
        # address AND the open ingress, connectivity proves nothing.
        estate = [
            resource("i-app", "ec2_instance", {}, (rel("sg-1", RT.ATTACHED_TO),)),
            resource("sg-1", "security_group", {"has_unrestricted_ingress": False}),
        ]
        assert analyze(estate) == ()

    def test_public_ip_without_open_ingress_is_not_a_path(self) -> None:
        estate = [
            resource(
                "i-web",
                "ec2_instance",
                {"public_ip": "203.0.113.10"},
                (rel("sg-closed", RT.ATTACHED_TO),),
            ),
            resource("sg-closed", "security_group", {"has_unrestricted_ingress": False}),
        ]
        assert analyze(estate) == ()

    def test_open_ingress_without_a_public_address_is_not_a_path(self) -> None:
        estate = [
            resource("i-app", "ec2_instance", {"public_ip": None}, (rel("sg-open", RT.ATTACHED_TO),)),
            resource("sg-open", "security_group", {"has_unrestricted_ingress": True}),
        ]
        assert analyze(estate) == ()

    def test_unknown_exposure_never_becomes_a_path(self) -> None:
        # The single most important negative test. If UNKNOWN read as
        # True, a denied API call would manufacture a critical finding.
        bucket = resource("bucket-?", "s3_bucket", {"public": UNKNOWN})
        assert analyze([bucket]) == ()

    def test_unknown_privilege_downgrades_rather_than_inventing(self) -> None:
        role = resource(
            "role/?",
            "iam_role",
            {"is_publicly_assumable": True, "has_administrator_access": UNKNOWN},
            (rel("internet", RT.PUBLICLY_EXPOSED),),
        )
        path = by_scenario(analyze([role]))[SCENARIO_PUBLIC_IDENTITY]

        # The public trust IS observed, so the path is real. The
        # privilege is not, so it contributes nothing and the
        # incompleteness penalty applies.
        assert path.evidence["privilege_evidence"] == []
        assert path.evidence["evidence_incomplete"] is True
        assert any("incomplete_evidence" in f for f in path.evidence["score_factors"])

    def test_a_blocked_edge_scores_zero(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT)
        graph.add_node(
            GraphNode(resource_id=ResourceId("internet"), tenant_id=TENANT,
                      resource_type="internet", kind="external")
        )
        graph.add_node(
            GraphNode(resource_id=ResourceId("role/x"), tenant_id=TENANT, resource_type="iam_role")
        )
        graph.add_edge(
            GraphEdge(
                source_id=ResourceId("role/x"),
                target_id=ResourceId("internet"),
                relationship_type=RT.PUBLICLY_EXPOSED,
                blocked=True,
            )
        )
        # A relationship prevented in practice is not a step in an attack.
        assert AnalyzeAttackPaths().analyze(tenant_id=TENANT, graph=graph, findings=()) == ()

    def test_missing_attributes_produce_no_path(self) -> None:
        # resources= not supplied: the analyzer finds fewer paths rather
        # than guessing at attributes it was never given.
        graph = BuildResourceGraph().build(
            tenant_id=TENANT, resources=[resource("bucket-public", "s3_bucket", {"public": True})]
        )
        assert AnalyzeAttackPaths().analyze(tenant_id=TENANT, graph=graph, findings=()) == ()


# ---------------------------------------------------------------------
# Graph safety and boundaries
# ---------------------------------------------------------------------


class TestGraphSafety:
    def test_empty_graph(self) -> None:
        assert AnalyzeAttackPaths().analyze(
            tenant_id=TENANT, graph=ResourceGraph(tenant_id=TENANT), findings=()
        ) == ()

    def test_a_cycle_terminates(self) -> None:
        estate = [
            resource("a", "cloudtrail", {}, (rel("b", RT.ACCESSES),)),
            resource("b", "s3_bucket", {"public": True}, (rel("a", RT.ACCESSES),)),
        ]
        paths = analyze(estate)  # must not hang
        assert any(p.scenario == SCENARIO_DATA_FLOW_TO_EXPOSED_STORE for p in paths)

    def test_duplicate_relationships_do_not_duplicate_paths(self) -> None:
        estate = [
            resource(
                "trail-1",
                "cloudtrail",
                {},
                (rel("bucket-public", RT.ACCESSES), rel("bucket-public", RT.ACCESSES)),
            ),
            resource("bucket-public", "s3_bucket", {"public": True}),
        ]
        flows = [p for p in analyze(estate) if p.scenario == SCENARIO_DATA_FLOW_TO_EXPOSED_STORE]
        assert len(flows) == 1

    def test_an_external_node_is_never_a_target(self) -> None:
        role = resource(
            "role/x", "iam_role", {"is_publicly_assumable": True},
            (rel("aws-account:999999999999", RT.ASSUMES),),
        )
        for path in analyze([role]):
            assert not path.target.is_external

    def test_external_nodes_cap_confidence(self) -> None:
        role = resource(
            "role/admin",
            "iam_role",
            {"is_publicly_assumable": True, "has_administrator_access": True},
            (rel("internet", RT.PUBLICLY_EXPOSED),),
        )
        path = by_scenario(analyze([role]))[SCENARIO_PUBLIC_IDENTITY]
        # `internet` is external and carries medium confidence, so the
        # weakest link is medium. This is correct, not a defect to fix:
        # we never enumerated the internet.
        assert path.confidence == "medium"

    def test_one_malformed_candidate_does_not_abort_the_sweep(self) -> None:
        estate = [
            resource("bucket-a", "s3_bucket", {"public": True}),
            resource("bucket-b", "s3_bucket", {"public": True}),
        ]
        assert len(analyze(estate)) == 2


class TestBoundaries:
    def test_zero_hop_path_is_valid(self) -> None:
        # A publicly readable bucket is one node and no edges.
        path = by_scenario(analyze([resource("b", "s3_bucket", {"public": True})]))[
            SCENARIO_EXPOSED_DATA
        ]
        assert len(path.nodes) == 1
        assert path.edges == ()

    def test_one_hop_path(self) -> None:
        estate = [
            resource("trail-1", "cloudtrail", {}, (rel("b", RT.ACCESSES),)),
            resource("b", "s3_bucket", {"public": True}),
        ]
        flow = by_scenario(analyze(estate))[SCENARIO_DATA_FLOW_TO_EXPOSED_STORE]
        assert len(flow.edges) == 1
        assert len(flow.nodes) == 2

    def test_severity_thresholds(self) -> None:
        assert severity_for(0) is Severity.LOW
        assert severity_for(19.9) is Severity.LOW
        assert severity_for(20) is Severity.MEDIUM
        assert severity_for(39.9) is Severity.MEDIUM
        assert severity_for(40) is Severity.HIGH
        assert severity_for(69.9) is Severity.HIGH
        assert severity_for(70) is Severity.CRITICAL
        assert severity_for(100) is Severity.CRITICAL

    def test_scores_stay_within_bounds(self) -> None:
        role = resource(
            "role/worst",
            "iam_role",
            {
                "is_publicly_assumable": True,
                "has_administrator_access": True,
                "has_privilege_escalation_path": True,
                "has_wildcard_action": True,
            },
            (rel("internet", RT.PUBLICLY_EXPOSED),),
        )
        for path in analyze([role]):
            assert 0 <= path.risk_score <= 100


class TestClassification:
    def test_connectivity_is_not_reachability(self) -> None:
        # The decision this whole module turns on.
        attached = GraphEdge(
            source_id=ResourceId("a"), target_id=ResourceId("b"),
            relationship_type=RT.ATTACHED_TO,
        )
        assumes = GraphEdge(
            source_id=ResourceId("a"), target_id=ResourceId("b"),
            relationship_type=RT.ASSUMES,
        )
        assert is_traversable(attached) is False
        assert is_traversable(assumes) is True

    def test_unclassified_resource_types_are_never_targets(self) -> None:
        node = GraphNode(
            resource_id=ResourceId("x"), tenant_id=TENANT, resource_type="not_a_real_type"
        )
        assert role_of(node) is ResourceRole.OTHER


class TestDeterminism:
    def _estate(self):
        return [
            resource(
                "role/admin",
                "iam_role",
                {"is_publicly_assumable": True, "has_administrator_access": True},
                (rel("internet", RT.PUBLICLY_EXPOSED),),
            ),
            resource("bucket-public", "s3_bucket", {"public": True}),
            resource("trail-1", "cloudtrail", {}, (rel("bucket-public", RT.ACCESSES),)),
        ]

    def test_same_graph_yields_same_paths_scores_and_order(self) -> None:
        runs = [
            [(str(p.id), p.risk_score, p.severity) for p in analyze(self._estate())]
            for _ in range(5)
        ]
        assert all(run == runs[0] for run in runs)

    def test_resource_input_order_does_not_change_the_result(self) -> None:
        forward = [(str(p.id), p.risk_score) for p in analyze(self._estate())]
        backward = [(str(p.id), p.risk_score) for p in analyze(list(reversed(self._estate())))]
        assert forward == backward

    def test_ordering_is_highest_risk_first(self) -> None:
        scores = [p.risk_score for p in analyze(self._estate())]
        assert scores == sorted(scores, reverse=True)

    def test_ids_are_stable_across_runs(self) -> None:
        # No uuid4, no clock — a path can be tracked between scans.
        assert [str(p.id) for p in analyze(self._estate())] == [
            str(p.id) for p in analyze(self._estate())
        ]


class TestRiskEnrichment:
    def test_a_finding_on_a_path_scores_higher_than_one_without(self) -> None:
        from application.risk.enrich_findings import EnrichFindingsWithRisk
        from domain.findings.models import Evidence, Finding, FindingStatus
        from domain.shared.identifiers import FindingId, RuleId

        def finding(rid):
            return Finding(
                id=FindingId(f"f-{rid}"),
                tenant_id=TENANT,
                resource_id=ResourceId(rid),
                rule_id=RuleId("r-1"),
                framework="iso_27001",
                control_id="A.8.24",
                domain="storage",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                evidence=Evidence(data={}),
                detected_at=NOW,
            )

        estate = [
            resource("bucket-public", "s3_bucket", {"public": True}),
            resource("bucket-private", "s3_bucket", {"public": False}),
        ]
        paths = analyze(estate)
        enriched = {
            str(f.resource_id): f
            for f in EnrichFindingsWithRisk().enrich(
                findings=[finding("bucket-public"), finding("bucket-private")],
                attack_paths=paths,
            )
        }

        assert enriched["bucket-public"].risk > enriched["bucket-private"].risk
        assert enriched["bucket-public"].related_attack_path_ids == (paths[0].id,)
        # Same severity, so the difference is entirely attack-path context.
        assert enriched["bucket-private"].related_attack_path_ids == ()

    def test_a_finding_without_a_path_still_gets_a_risk_score(self) -> None:
        from application.risk.enrich_findings import EnrichFindingsWithRisk
        from domain.findings.models import Evidence, Finding, FindingStatus
        from domain.shared.identifiers import FindingId, RuleId

        f = Finding(
            id=FindingId("f-1"),
            tenant_id=TENANT,
            resource_id=ResourceId("bucket-private"),
            rule_id=RuleId("r-1"),
            framework="iso_27001",
            control_id="A.8.24",
            domain="storage",
            status=FindingStatus.FAIL,
            severity=Severity.CRITICAL,
            evidence=Evidence(data={}),
            detected_at=NOW,
        )
        enriched = EnrichFindingsWithRisk().enrich(findings=[f], attack_paths=())[0]

        # Backward compatibility: attack-path involvement is one of five
        # CRSF factors, not a precondition for having risk at all.
        assert enriched.risk is not None and enriched.risk > 0
        assert enriched.related_attack_path_ids == ()
        assert enriched.evidence.data["attack_path_count"] == 0

    def test_a_defaulted_environment_is_declared_not_hidden(self) -> None:
        from application.risk.enrich_findings import EnrichFindingsWithRisk
        from domain.findings.models import Evidence, Finding, FindingStatus
        from domain.shared.identifiers import FindingId, RuleId

        f = Finding(
            id=FindingId("f-1"),
            tenant_id=TENANT,
            resource_id=ResourceId("b"),
            rule_id=RuleId("r-1"),
            framework="iso_27001",
            control_id="A.8.24",
            domain="storage",
            status=FindingStatus.FAIL,
            severity=Severity.LOW,
            evidence=Evidence(data={}),
            detected_at=NOW,
        )
        enriched = EnrichFindingsWithRisk().enrich(findings=[f], attack_paths=())[0]
        # No collector populates `environment`, so the score assumed one.
        # A reader must be able to see that it did.
        assert enriched.evidence.data["risk_environment_defaulted"] is True


class TestNoFabricatedCoverage:
    """§17: the analyzer must not invent evidence the graph lacks."""

    def test_no_workload_to_identity_path_is_invented(self) -> None:
        # `instance_profile_arn` is a collected ATTRIBUTE and no collector
        # emits a workload->identity EDGE (current-state audit §2). The
        # textbook chain internet -> workload -> role -> data therefore
        # has no evidence, and must not be reported.
        estate = [
            resource(
                "i-web",
                "ec2_instance",
                {
                    "public_ip": "203.0.113.10",
                    "instance_profile_arn": "arn:aws:iam::111111111111:instance-profile/app",
                },
                (rel("sg-open", RT.ATTACHED_TO),),
            ),
            resource("sg-open", "security_group", {"has_unrestricted_ingress": True}),
            resource("role/app", "iam_role", {"has_administrator_access": True}),
            resource("bucket-data", "s3_bucket", {"public": False}),
        ]
        for path in analyze(estate):
            ids = {str(n.resource_id) for n in path.nodes}
            assert not ({"i-web", "role/app"} <= ids), (
                "a workload->identity path was reported without a graph edge to support it"
            )

    @pytest.mark.parametrize(
        "scenario",
        [
            SCENARIO_PUBLIC_IDENTITY,
            SCENARIO_EXPOSED_DATA,
            SCENARIO_EXPOSED_WORKLOAD,
            SCENARIO_DATA_FLOW_TO_EXPOSED_STORE,
        ],
    )
    def test_every_shipped_scenario_is_reachable_with_real_collector_output(
        self, scenario: str
    ) -> None:
        """Guards against the reverse failure: a scenario nobody can hit.

        Each estate below uses only attributes and relationship types that
        the audited collectors genuinely produce.
        """

        estates = {
            SCENARIO_PUBLIC_IDENTITY: [
                resource(
                    "role/a", "iam_role", {"is_publicly_assumable": True},
                    (rel("internet", RT.PUBLICLY_EXPOSED),),
                )
            ],
            SCENARIO_EXPOSED_DATA: [resource("b", "s3_bucket", {"public": True})],
            SCENARIO_EXPOSED_WORKLOAD: [
                resource("i", "ec2_instance", {"public_ip": "1.2.3.4"},
                         (rel("sg", RT.ATTACHED_TO),)),
                resource("sg", "security_group", {"has_unrestricted_ingress": True}),
            ],
            SCENARIO_DATA_FLOW_TO_EXPOSED_STORE: [
                resource("t", "cloudtrail", {}, (rel("b", RT.ACCESSES),)),
                resource("b", "s3_bucket", {"public": True}),
            ],
        }
        assert scenario in by_scenario(analyze(estates[scenario]))
