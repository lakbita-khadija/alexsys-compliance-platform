"""Rule consumption for the AWS network foundation and RDS.

Before these rules, **46 of 47** attributes added by STEP 8A and 8B were
dead: collected, normalized, put in the graph, and read by nothing. Six
resource types had zero rules.

Every rule here gets three cases, because two are not enough:

* **non-compliant** — the violation is proven;
* **compliant** — the safe configuration is proven, not merely
  "no finding was produced";
* **UNKNOWN** — the evidence could not be read, which must yield
  `INDETERMINATE` rather than a false PASS. That third case is the one
  that distinguishes a CSPM from a checkbox: "we could not determine
  whether backups are on" and "backups are on" must never look the same.

The two cross-resource rules additionally get the cases a single-resource
rule cannot fail: target missing, relationship missing, and the
neighbour present but safe.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from application.graph.build_resource_graph import BuildResourceGraph
from application.rules.evaluate_rules import EvaluateRules
from domain.findings.models import FindingStatus
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId
from domain.shared.unknown import UNKNOWN
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ACCOUNT = "111111111111"
REPO_ROOT = Path(__file__).resolve().parents[3]

SG = "sg-0a1b2c3d"
RTB = "rtb-01234567"
SUBNET = "subnet-aaaa1111"
DB = f"arn:aws:rds:us-east-1:{ACCOUNT}:db:prod-orders"


@pytest.fixture(scope="module")
def catalog():
    return YamlRuleCatalog(REPO_ROOT / "rules" / "aws")


def resource(rid, rtype, attributes, relationships=()):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes,
        tags={},
        relationships=relationships,
        collected_at=NOW,
        account_id=ACCOUNT,
    )


def rel(target, kind=RelationshipType.ATTACHED_TO):
    return ResourceRelationship(
        target_resource_id=ResourceId(target), relationship_type=kind
    )


def evaluate(catalog, resources, rule_id):
    graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
    findings = EvaluateRules(catalog).evaluate(
        tenant_id=TENANT,
        resources=resources,
        detected_at=NOW,
        scan_id="scan-1",
        rule_ids=(RuleId(rule_id),),
        graph=graph,
    )
    return findings


def status_of(catalog, resources, rule_id, subject):
    findings = [f for f in evaluate(catalog, resources, rule_id) if str(f.resource_id) == subject]
    assert len(findings) == 1, f"expected exactly one finding for {subject}, got {len(findings)}"
    return findings[0]


# ---------------------------------------------------------------------
# Network ACL
# ---------------------------------------------------------------------


class TestNaclUnrestrictedIngress:
    RULE = "nacl-allows-unrestricted-ingress"

    def acl(self, value):
        return resource("acl-1", "aws_network_acl", {"has_unrestricted_ingress_rule": value})

    def test_an_open_acl_fails(self, catalog) -> None:
        assert status_of(catalog, [self.acl(True)], self.RULE, "acl-1").status is FindingStatus.FAIL

    def test_a_restricted_acl_passes(self, catalog) -> None:
        assert status_of(catalog, [self.acl(False)], self.RULE, "acl-1").status is FindingStatus.PASS

    def test_unreadable_entries_are_indeterminate(self, catalog) -> None:
        # "We could not enumerate this ACL" must not read as "restricted".
        finding = status_of(catalog, [self.acl(UNKNOWN)], self.RULE, "acl-1")
        assert finding.status is FindingStatus.INDETERMINATE

    def test_severity_and_evidence(self, catalog) -> None:
        finding = status_of(catalog, [self.acl(True)], self.RULE, "acl-1")
        assert finding.severity is Severity.HIGH
        assert "acl-1" in finding.evidence.data.get("narrative", "")

    def test_it_maps_to_a_control(self, catalog) -> None:
        finding = status_of(catalog, [self.acl(True)], self.RULE, "acl-1")
        assert finding.framework == "iso_27001"
        assert finding.control_id == "A.8.20"


# ---------------------------------------------------------------------
# Route table
# ---------------------------------------------------------------------


class TestRouteTableInternetRoute:
    RULE = "route-table-has-internet-route"

    def rt(self, value):
        return resource(RTB, "aws_route_table", {"has_internet_route": value})

    def test_a_public_route_table_fails(self, catalog) -> None:
        assert status_of(catalog, [self.rt(True)], self.RULE, RTB).status is FindingStatus.FAIL

    def test_a_private_route_table_passes(self, catalog) -> None:
        assert status_of(catalog, [self.rt(False)], self.RULE, RTB).status is FindingStatus.PASS

    def test_unreadable_routes_are_indeterminate(self, catalog) -> None:
        assert status_of(catalog, [self.rt(UNKNOWN)], self.RULE, RTB).status is FindingStatus.INDETERMINATE

    def test_it_is_low_severity_because_routing_is_not_reachability(self, catalog) -> None:
        """The distinction §7 insists on, encoded in the severity.

        Public routing is topology. Whether anything is actually
        reachable depends on the security groups and NACLs in front of
        it, so this must not be reported at the same weight as proven
        exposure.
        """

        finding = status_of(catalog, [self.rt(True)], self.RULE, RTB)
        assert finding.severity is Severity.LOW
        assert "not confirmed reachability" in finding.evidence.data.get("narrative", "")


# ---------------------------------------------------------------------
# Subnet — cross-resource
# ---------------------------------------------------------------------


class TestPublicSubnet:
    """Both halves required — the §6 'strong evidence' requirement."""

    RULE = "subnet-auto-assigns-public-ip-with-internet-route"

    def estate(self, *, auto_ip=True, internet_route=True, with_route_table=True):
        resources = [
            resource(SUBNET, "aws_subnet", {"map_public_ip_on_launch": auto_ip})
        ]
        if with_route_table:
            resources.append(
                resource(
                    RTB,
                    "aws_route_table",
                    {"has_internet_route": internet_route},
                    (rel(SUBNET),),
                )
            )
        return resources

    def test_both_halves_present_fails(self, catalog) -> None:
        finding = status_of(catalog, self.estate(), self.RULE, SUBNET)
        assert finding.status is FindingStatus.FAIL
        assert finding.severity is Severity.MEDIUM

    def test_auto_ip_without_an_internet_route_passes(self, catalog) -> None:
        # A public address that routes nowhere is not exposure.
        finding = status_of(catalog, self.estate(internet_route=False), self.RULE, SUBNET)
        assert finding.status is FindingStatus.PASS

    def test_an_internet_route_without_auto_ip_passes(self, catalog) -> None:
        # A route out, but instances get no public address by default.
        finding = status_of(catalog, self.estate(auto_ip=False), self.RULE, SUBNET)
        assert finding.status is FindingStatus.PASS

    def test_no_associated_route_table_passes(self, catalog) -> None:
        # Relationship missing entirely. Absence of an association is
        # NOT evidence of an internet route.
        finding = status_of(catalog, self.estate(with_route_table=False), self.RULE, SUBNET)
        assert finding.status is FindingStatus.PASS

    def test_an_unreadable_auto_ip_flag_is_indeterminate(self, catalog) -> None:
        finding = status_of(catalog, self.estate(auto_ip=UNKNOWN), self.RULE, SUBNET)
        assert finding.status is FindingStatus.INDETERMINATE

    def test_an_unreadable_route_table_is_indeterminate(self, catalog) -> None:
        # The neighbour exists but its routes could not be read. That is
        # a data gap, not a clean subnet.
        finding = status_of(catalog, self.estate(internet_route=UNKNOWN), self.RULE, SUBNET)
        assert finding.status is FindingStatus.INDETERMINATE

    def test_the_finding_names_both_facts(self, catalog) -> None:
        finding = status_of(catalog, self.estate(), self.RULE, SUBNET)
        narrative = finding.evidence.data.get("narrative", "")
        assert "public IPs on launch" in narrative
        assert "internet gateway" in narrative

    def test_the_related_route_table_is_recorded(self, catalog) -> None:
        # Graph context: a responder must be able to see WHICH route
        # table made this subnet public.
        finding = status_of(catalog, self.estate(), self.RULE, SUBNET)
        assert RTB in finding.related_resources


# ---------------------------------------------------------------------
# RDS
# ---------------------------------------------------------------------


def db(**attributes):
    base = {
        "storage_encrypted": True,
        "publicly_accessible": False,
        "backup_retention_period": 7,
    }
    base.update(attributes)
    relationships = base.pop("_relationships", ())
    return resource(DB, "rds_db_instance", base, relationships)


class TestRdsEncryption:
    RULE = "rds-storage-not-encrypted"

    def test_unencrypted_fails(self, catalog) -> None:
        finding = status_of(catalog, [db(storage_encrypted=False)], self.RULE, DB)
        assert finding.status is FindingStatus.FAIL
        assert finding.severity is Severity.HIGH

    def test_encrypted_passes(self, catalog) -> None:
        assert status_of(catalog, [db()], self.RULE, DB).status is FindingStatus.PASS

    def test_unknown_is_indeterminate(self, catalog) -> None:
        finding = status_of(catalog, [db(storage_encrypted=UNKNOWN)], self.RULE, DB)
        assert finding.status is FindingStatus.INDETERMINATE

    def test_it_maps_to_the_cryptography_control(self, catalog) -> None:
        finding = status_of(catalog, [db(storage_encrypted=False)], self.RULE, DB)
        assert finding.control_id == "A.8.24"
        assert finding.domain == "encryption"


class TestRdsPublicEndpoint:
    RULE = "rds-public-endpoint-configured"

    def test_a_public_endpoint_fails(self, catalog) -> None:
        finding = status_of(catalog, [db(publicly_accessible=True)], self.RULE, DB)
        assert finding.status is FindingStatus.FAIL

    def test_a_private_endpoint_passes(self, catalog) -> None:
        assert status_of(catalog, [db()], self.RULE, DB).status is FindingStatus.PASS

    def test_unknown_is_indeterminate(self, catalog) -> None:
        finding = status_of(catalog, [db(publicly_accessible=UNKNOWN)], self.RULE, DB)
        assert finding.status is FindingStatus.INDETERMINATE

    def test_it_claims_configuration_not_reachability(self, catalog) -> None:
        """The wording that keeps this rule honest.

        A public endpoint behind a closed security group is not exposed.
        Reporting it as exposure would flag every correctly firewalled
        database in the estate.
        """

        finding = status_of(catalog, [db(publicly_accessible=True)], self.RULE, DB)
        assert finding.severity is Severity.MEDIUM
        assert "not confirmed reachability" in finding.evidence.data.get("narrative", "")


class TestRdsReachableFromInternet:
    """The cross-resource rule that makes RDS collection worth having."""

    RULE = "rds-reachable-from-internet"

    def estate(self, *, public=True, sg_open=True, with_sg=True):
        resources = [db(publicly_accessible=public, _relationships=(rel(SG),) if with_sg else ())]
        if with_sg:
            resources.append(
                resource(SG, "security_group", {"has_unrestricted_ingress": sg_open})
            )
        return resources

    def test_both_halves_present_is_critical(self, catalog) -> None:
        finding = status_of(catalog, self.estate(), self.RULE, DB)
        assert finding.status is FindingStatus.FAIL
        assert finding.severity is Severity.CRITICAL

    def test_a_public_endpoint_behind_a_closed_group_passes(self, catalog) -> None:
        # The false positive this rule exists to avoid.
        finding = status_of(catalog, self.estate(sg_open=False), self.RULE, DB)
        assert finding.status is FindingStatus.PASS

    def test_a_private_endpoint_behind_an_open_group_passes(self, catalog) -> None:
        # An open group on a database with no public address does not
        # make it internet-reachable.
        finding = status_of(catalog, self.estate(public=False), self.RULE, DB)
        assert finding.status is FindingStatus.PASS

    def test_no_attached_security_group_passes(self, catalog) -> None:
        # Relationship missing. Absence is not evidence of an open group.
        finding = status_of(catalog, self.estate(with_sg=False), self.RULE, DB)
        assert finding.status is FindingStatus.PASS

    def test_an_unreadable_security_group_is_indeterminate(self, catalog) -> None:
        # Target exists, its rules could not be read. Not a pass.
        finding = status_of(catalog, self.estate(sg_open=UNKNOWN), self.RULE, DB)
        assert finding.status is FindingStatus.INDETERMINATE

    def test_an_unreadable_endpoint_flag_is_indeterminate(self, catalog) -> None:
        finding = status_of(catalog, self.estate(public=UNKNOWN), self.RULE, DB)
        assert finding.status is FindingStatus.INDETERMINATE

    def test_the_security_group_is_recorded_as_related(self, catalog) -> None:
        finding = status_of(catalog, self.estate(), self.RULE, DB)
        assert SG in finding.related_resources

    def test_evidence_is_deterministic(self, catalog) -> None:
        runs = [
            status_of(catalog, self.estate(), self.RULE, DB).evidence.data
            for _ in range(3)
        ]
        assert all(run == runs[0] for run in runs)


class TestRdsBackups:
    RULE = "rds-automated-backups-disabled"

    def test_zero_retention_fails(self, catalog) -> None:
        # 0 is AWS's own encoding for "backups off" — a real threshold,
        # not an invented policy number.
        finding = status_of(catalog, [db(backup_retention_period=0)], self.RULE, DB)
        assert finding.status is FindingStatus.FAIL

    def test_a_positive_retention_passes(self, catalog) -> None:
        assert status_of(catalog, [db(backup_retention_period=1)], self.RULE, DB).status is FindingStatus.PASS

    def test_unknown_is_indeterminate(self, catalog) -> None:
        finding = status_of(catalog, [db(backup_retention_period=UNKNOWN)], self.RULE, DB)
        assert finding.status is FindingStatus.INDETERMINATE

    def test_it_maps_to_the_backup_control(self, catalog) -> None:
        finding = status_of(catalog, [db(backup_retention_period=0)], self.RULE, DB)
        assert finding.control_id == "A.8.13"


# ---------------------------------------------------------------------
# EC2 -> subnet -> route table (STEP 8A.1, two hops)
# ---------------------------------------------------------------------


class TestInstanceInInternetRoutedSubnet:
    """The consumer of the ``ec2_instance -> aws_subnet`` edge.

    Two hops, so there are more ways to be wrong than a single-resource
    rule has: either hop can be missing, either target can be
    uncollected, and either half of the AND can be the one that saves
    the instance. Each gets its own case below.
    """

    RULE = "ec2-instance-in-internet-routed-subnet-with-public-ip"
    INSTANCE = "i-0123456789abcdef0"

    def instance(self, *, public_ip="203.0.113.5", subnet=SUBNET):
        return resource(
            self.INSTANCE,
            "ec2_instance",
            {"public_ip": public_ip},
            relationships=(rel(subnet),) if subnet else (),
        )

    def subnet(self):
        return resource(SUBNET, "aws_subnet", {"vpc_id": "vpc-1"})

    def route_table(self, has_internet_route):
        return resource(
            RTB,
            "aws_route_table",
            {"has_internet_route": has_internet_route},
            relationships=(rel(SUBNET),),
        )

    def test_a_public_instance_in_a_public_subnet_fails(self, catalog) -> None:
        resources = [self.instance(), self.subnet(), self.route_table(True)]
        finding = status_of(catalog, resources, self.RULE, self.INSTANCE)
        assert finding.status is FindingStatus.FAIL
        assert finding.severity is Severity.MEDIUM

    def test_a_public_instance_in_a_privately_routed_subnet_passes(self, catalog) -> None:
        # The second hop is what saves it. A public IP with no route to
        # an internet gateway reaches nothing.
        resources = [self.instance(), self.subnet(), self.route_table(False)]
        assert (
            status_of(catalog, resources, self.RULE, self.INSTANCE).status
            is FindingStatus.PASS
        )

    def test_an_instance_with_no_public_ip_passes(self, catalog) -> None:
        # The first half of the AND is what saves it. An internet-routed
        # subnet does nothing for an instance with no public address.
        resources = [
            self.instance(public_ip=None),
            self.subnet(),
            self.route_table(True),
        ]
        assert (
            status_of(catalog, resources, self.RULE, self.INSTANCE).status
            is FindingStatus.PASS
        )

    def test_an_instance_with_no_subnet_edge_passes(self, catalog) -> None:
        # No placement asserted — vacuously not matched. Correct here
        # precisely because the rule claims addressability rather than
        # its absence: with no route table reachable there is no
        # evidence of public routing to report.
        resources = [self.instance(subnet=None), self.subnet(), self.route_table(True)]
        assert (
            status_of(catalog, resources, self.RULE, self.INSTANCE).status
            is FindingStatus.PASS
        )

    def test_an_uncollected_subnet_is_indeterminate_not_a_pass(self, catalog) -> None:
        # The seam this rule is most likely to fail at. If DescribeSubnets
        # was denied, the instance's subnet exists only as an external
        # node with no attributes — and "we could not look" must not
        # render as "this instance is fine".
        resources = [self.instance(), self.route_table(True)]
        assert (
            status_of(catalog, resources, self.RULE, self.INSTANCE).status
            is FindingStatus.INDETERMINATE
        )

    def test_an_unreadable_route_table_is_indeterminate(self, catalog) -> None:
        resources = [self.instance(), self.subnet(), self.route_table(UNKNOWN)]
        assert (
            status_of(catalog, resources, self.RULE, self.INSTANCE).status
            is FindingStatus.INDETERMINATE
        )

    def test_an_instance_in_a_different_subnet_is_unaffected(self, catalog) -> None:
        # The route table governs SUBNET; this instance is elsewhere.
        # Traversal must not leak between unrelated subnets.
        other = resource("subnet-bbbb2222", "aws_subnet", {"vpc_id": "vpc-1"})
        resources = [
            self.instance(subnet="subnet-bbbb2222"),
            other,
            self.subnet(),
            self.route_table(True),
        ]
        assert (
            status_of(catalog, resources, self.RULE, self.INSTANCE).status
            is FindingStatus.PASS
        )

    def test_the_evidence_names_the_instance(self, catalog) -> None:
        resources = [self.instance(), self.subnet(), self.route_table(True)]
        finding = status_of(catalog, resources, self.RULE, self.INSTANCE)
        assert self.INSTANCE in finding.evidence.data.get("narrative", "")


# ---------------------------------------------------------------------
# Catalog integration
# ---------------------------------------------------------------------


class TestEveryNewRuleReachesTheComplianceCatalog:
    NEW_RULES = (
        "nacl-allows-unrestricted-ingress",
        "route-table-has-internet-route",
        "subnet-auto-assigns-public-ip-with-internet-route",
        "ec2-instance-in-internet-routed-subnet-with-public-ip",
        "rds-storage-not-encrypted",
        "rds-public-endpoint-configured",
        "rds-reachable-from-internet",
        "rds-automated-backups-disabled",
    )

    @pytest.fixture(scope="class")
    def compliance_catalog(self):
        from domain.compliance.catalog import build_catalog

        rules: list = []
        for directory in sorted(d for d in (REPO_ROOT / "rules").iterdir() if d.is_dir()):
            rules.extend(YamlRuleCatalog(directory).load())
        return build_catalog(rules)

    @pytest.mark.parametrize("rule_id", NEW_RULES)
    def test_the_rule_has_catalog_entries(self, compliance_catalog, rule_id) -> None:
        assert compliance_catalog.entries_for_rule(rule_id)

    @pytest.mark.parametrize("rule_id", NEW_RULES)
    def test_no_new_mapping_claims_verified(self, compliance_catalog, rule_id) -> None:
        # None was checked against published benchmark text, so none may
        # claim to have been. STEP 7's rule, holding for new rules.
        from domain.rules.rule import MAPPING_VERIFIED

        statuses = {e.status for e in compliance_catalog.entries_for_rule(rule_id)}
        assert MAPPING_VERIFIED not in statuses

    def test_the_new_resource_types_are_no_longer_orphaned(self, catalog) -> None:
        """The whole point of this step, asserted in one place.

        Before it, six resource types had zero rules and their data was
        collected, graphed and read by nothing.
        """

        covered = {r.applies_to_resource_type for r in catalog.load()}
        for resource_type in (
            "aws_network_acl",
            "aws_route_table",
            "aws_subnet",
            "rds_db_instance",
        ):
            assert resource_type in covered
