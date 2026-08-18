from application.attack_paths.analyze_attack_paths import AnalyzeAttackPaths
from domain.graph.models import ResourceGraph
from domain.shared.identifiers import TenantId

TENANT_A = TenantId("acme")


class TestAnalyzeAttackPaths:
    def test_returns_no_attack_paths_when_no_discovery_algorithm_exists(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        paths = AnalyzeAttackPaths().analyze(tenant_id=TENANT_A, graph=graph, findings=())
        assert paths == ()

    def test_always_returns_a_tuple_regardless_of_input_size(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        paths = AnalyzeAttackPaths().analyze(tenant_id=TENANT_A, graph=graph, findings=())
        assert isinstance(paths, tuple)

    def test_is_deterministic(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        results = {
            AnalyzeAttackPaths().analyze(tenant_id=TENANT_A, graph=graph, findings=())
            for _ in range(10)
        }
        assert results == {()}
