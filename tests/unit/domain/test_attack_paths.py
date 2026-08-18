import pytest

from domain.attack_paths.models import AttackPath, AttackTechnique
from domain.graph.models import GraphEdge, GraphNode
from domain.shared.enums import RelationshipType, Severity
from domain.shared.errors import InvalidAttackPath
from domain.shared.identifiers import AttackPathId, FindingId, ResourceId, TenantId

TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")


def node(resource_id: str, tenant_id: TenantId = TENANT_A) -> GraphNode:
    return GraphNode(resource_id=ResourceId(resource_id), tenant_id=tenant_id, resource_type="ec2_instance")


def edge(source: str, target: str, blocked: bool = False) -> GraphEdge:
    return GraphEdge(
        source_id=ResourceId(source),
        target_id=ResourceId(target),
        relationship_type=RelationshipType.CONNECTS_TO,
        blocked=blocked,
    )


def make_path(**overrides) -> AttackPath:
    defaults = dict(
        id=AttackPathId("path-1"),
        tenant_id=TENANT_A,
        nodes=(node("internet"), node("ec2-1"), node("bucket-1")),
        edges=(edge("internet", "ec2-1"), edge("ec2-1", "bucket-1")),
        contributing_finding_ids=(FindingId("finding-1"),),
        attack_techniques=(AttackTechnique(id="T1190", name="Exploit Public-Facing Application"),),
        severity=Severity.CRITICAL,
        risk_score=0,
        algorithm_version="attack-path-v1",
    )
    defaults.update(overrides)
    return AttackPath(**defaults)


class TestAttackTechnique:
    def test_valid_technique(self) -> None:
        technique = AttackTechnique(id="T1190", name="Exploit Public-Facing Application")
        assert technique.id == "T1190"

    def test_blank_id_is_rejected(self) -> None:
        with pytest.raises(Exception):
            AttackTechnique(id="", name="x")


class TestValidAttackPath:
    def test_valid_path(self) -> None:
        path = make_path()
        assert path.tenant_id == TENANT_A
        assert len(path.nodes) == 3
        assert path.algorithm_version == "attack-path-v1"

    def test_contributing_findings_are_preserved(self) -> None:
        path = make_path(contributing_finding_ids=(FindingId("f-1"), FindingId("f-2")))
        assert path.contributing_finding_ids == (FindingId("f-1"), FindingId("f-2"))

    def test_path_is_immutable(self) -> None:
        path = make_path()
        with pytest.raises(Exception):
            path.risk_score = 50  # type: ignore[misc]


class TestInvalidAttackPath:
    def test_empty_nodes_is_rejected(self) -> None:
        with pytest.raises(InvalidAttackPath):
            make_path(nodes=(), edges=())

    def test_blank_algorithm_version_is_rejected(self) -> None:
        with pytest.raises(InvalidAttackPath):
            make_path(algorithm_version="")

    def test_risk_score_out_of_bounds_is_rejected(self) -> None:
        with pytest.raises(InvalidAttackPath):
            make_path(risk_score=150)


class TestTenantIsolation:
    def test_node_from_a_different_tenant_is_rejected(self) -> None:
        with pytest.raises(InvalidAttackPath):
            make_path(nodes=(node("internet"), node("ec2-1", tenant_id=TENANT_B)))


class TestPathIntegrity:
    def test_edge_referencing_unknown_node_is_rejected(self) -> None:
        with pytest.raises(InvalidAttackPath):
            make_path(
                nodes=(node("internet"), node("ec2-1")),
                edges=(edge("internet", "does-not-exist"),),
            )


class TestBlockedPathInvariant:
    def test_blocked_path_must_score_zero(self) -> None:
        with pytest.raises(InvalidAttackPath):
            make_path(
                edges=(edge("internet", "ec2-1", blocked=True), edge("ec2-1", "bucket-1")),
                risk_score=40,
            )

    def test_blocked_path_with_zero_score_is_valid(self) -> None:
        path = make_path(
            edges=(edge("internet", "ec2-1", blocked=True), edge("ec2-1", "bucket-1")),
            risk_score=0,
        )
        assert path.risk_score == 0

    def test_unblocked_path_may_have_a_nonzero_score(self) -> None:
        path = make_path(
            edges=(edge("internet", "ec2-1"), edge("ec2-1", "bucket-1")),
            risk_score=75,
        )
        assert path.risk_score == 75


class TestAlgorithmVersion:
    def test_algorithm_version_is_required_and_preserved(self) -> None:
        path = make_path(algorithm_version="attack-path-v2")
        assert path.algorithm_version == "attack-path-v2"


class TestRelationshipClassificationCompleteness:
    """Every RelationshipType must be explicitly classified.

    `is_traversable()` checks MEMBERSHIP of the traversable set, so a
    relationship type that nobody classified silently returns ``False``:
    attack paths never route through it, with no error and no warning.
    The capability simply does not appear.

    The informational set is enumerated explicitly (rather than defined
    as "everything not traversable") precisely so that adding a type
    forces a decision — but a convention is not an enforcement. This test
    is the enforcement.

    Required by the execution plan §6.1: "Do NOT silently default unknown
    relationship types to traversable", and "this must fail loudly if a
    developer adds a new relationship and forgets to decide whether an
    attacker can traverse it."
    """

    def test_every_relationship_type_is_classified_exactly_once(self) -> None:
        from domain.attack_paths.classification import (
            _INFORMATIONAL_RELATIONSHIPS,
            _TRAVERSABLE_RELATIONSHIPS,
        )
        from domain.shared.enums import RelationshipType

        unclassified = []
        both = []
        for relationship in RelationshipType:
            traversable = relationship in _TRAVERSABLE_RELATIONSHIPS
            informational = relationship in _INFORMATIONAL_RELATIONSHIPS
            if traversable and informational:
                both.append(relationship.value)
            elif not (traversable or informational):
                unclassified.append(relationship.value)

        assert not unclassified, (
            f"unclassified relationship type(s): {sorted(unclassified)} — "
            "an attacker's ability to traverse them was never decided, so "
            "is_traversable() silently returns False and attack paths will "
            "never route through them. Add each to exactly one of "
            "_TRAVERSABLE_RELATIONSHIPS or _INFORMATIONAL_RELATIONSHIPS."
        )
        assert not both, (
            f"relationship type(s) in BOTH sets: {sorted(both)} — "
            "traversability must be a single unambiguous decision."
        )

    def test_the_two_sets_together_cover_the_whole_vocabulary(self) -> None:
        from domain.attack_paths.classification import (
            _INFORMATIONAL_RELATIONSHIPS,
            _TRAVERSABLE_RELATIONSHIPS,
        )
        from domain.shared.enums import RelationshipType

        assert (
            _TRAVERSABLE_RELATIONSHIPS | _INFORMATIONAL_RELATIONSHIPS
        ) == set(RelationshipType)

    def test_neither_set_contains_anything_outside_the_vocabulary(self) -> None:
        # Guards the reverse error: a stale member left behind after a
        # relationship type is renamed or removed.
        from domain.attack_paths.classification import (
            _INFORMATIONAL_RELATIONSHIPS,
            _TRAVERSABLE_RELATIONSHIPS,
        )
        from domain.shared.enums import RelationshipType

        assert (_TRAVERSABLE_RELATIONSHIPS | _INFORMATIONAL_RELATIONSHIPS).issubset(
            set(RelationshipType)
        )
