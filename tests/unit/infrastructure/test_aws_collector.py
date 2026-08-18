from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from application.scanning.collector import BaseCollector
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.aws.collector import AwsCollector, _resolve_account_id
from infrastructure.cloud.aws.errors import AwsCollectionError, AwsPermissionError, AwsServiceError

TENANT = TenantId("acme")
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731


def make_resource(resource_id: str) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes={},
        tags={},
        relationships=(),
        collected_at=CLOCK(),
    )


class FakeSubCollector:
    resource_type = "fake resources"

    def __init__(self, resources=(), error=None):
        self._resources = resources
        self._error = error

    def collect(self):
        if self._error is not None:
            raise self._error
        return self._resources


class TestAwsCollectorIsAPort:
    def test_aws_collector_satisfies_base_collector(self) -> None:
        assert issubclass(AwsCollector, BaseCollector)


class TestAwsCollectorAggregation:
    def test_aggregates_resources_from_every_sub_collector(self) -> None:
        sub_collectors = (
            FakeSubCollector(resources=(make_resource("a"),)),
            FakeSubCollector(resources=(make_resource("b"),)),
        )
        collector = AwsCollector(session=object(), tenant_id=TENANT, sub_collectors=sub_collectors)
        resources = collector.collect()
        assert {str(r.resource_id) for r in resources} == {"a", "b"}

    def test_empty_account_across_all_collectors_returns_empty_tuple(self) -> None:
        sub_collectors = (FakeSubCollector(resources=()), FakeSubCollector(resources=()))
        collector = AwsCollector(session=object(), tenant_id=TENANT, sub_collectors=sub_collectors)
        assert collector.collect() == ()


class TestAwsCollectorIsolation:
    def test_one_failing_service_does_not_prevent_others_from_being_collected(self) -> None:
        sub_collectors = (
            FakeSubCollector(resources=(make_resource("a"),)),
            FakeSubCollector(error=AwsPermissionError("no kms access")),
        )
        collector = AwsCollector(session=object(), tenant_id=TENANT, sub_collectors=sub_collectors)
        resources = collector.collect()
        assert {str(r.resource_id) for r in resources} == {"a"}

    def test_all_services_failing_raises_a_diagnosable_error(self) -> None:
        sub_collectors = (
            FakeSubCollector(error=AwsPermissionError("no s3 access")),
            FakeSubCollector(error=AwsServiceError("kms throttled")),
        )
        collector = AwsCollector(session=object(), tenant_id=TENANT, sub_collectors=sub_collectors)
        with pytest.raises(AwsCollectionError) as exc_info:
            collector.collect()
        assert isinstance(exc_info.value.__cause__, AwsPermissionError)
        assert "no s3 access" in str(exc_info.value)
        assert "kms throttled" in str(exc_info.value)


class TestAwsCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        sub_collectors = (FakeSubCollector(resources=(make_resource("a"),)),)
        collector = AwsCollector(session=object(), tenant_id=TENANT, sub_collectors=sub_collectors)
        first = collector.collect()
        second = collector.collect()
        assert first == second


class FakeStsClient:
    def __init__(self, account_id=None, error=None):
        self._account_id = account_id
        self._error = error

    def get_caller_identity(self):
        if self._error is not None:
            raise self._error
        return {"Account": self._account_id}


class FakeStsSession:
    def __init__(self, sts_client):
        self._sts_client = sts_client

    def client(self, service_name):
        assert service_name == "sts"
        return self._sts_client


class TestResolveAccountId:
    def test_returns_account_id_on_success(self) -> None:
        session = FakeStsSession(FakeStsClient(account_id="123456789012"))
        assert _resolve_account_id(session) == "123456789012"

    def test_returns_none_when_sts_denies_access(self) -> None:
        error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity")
        session = FakeStsSession(FakeStsClient(error=error))
        assert _resolve_account_id(session) is None

    def test_returns_none_on_unexpected_failure_rather_than_raising(self) -> None:
        session = FakeStsSession(FakeStsClient(error=RuntimeError("network unreachable")))
        assert _resolve_account_id(session) is None


class TestAwsCollectorRealSubCollectorWiring:
    def test_account_id_resolution_failure_does_not_prevent_collector_construction(self) -> None:
        class DenyingSession:
            region_name = "us-east-1"

            def client(self, service_name):
                if service_name == "sts":
                    return FakeStsClient(error=RuntimeError("no sts access"))
                raise AssertionError(f"unexpected client requested during construction: {service_name}")

        # Constructing AwsCollector with no `sub_collectors` override builds
        # the real chain; this only verifies STS failure during that
        # construction doesn't raise, matching the module's documented
        # "account_id is additive, never fatal" contract.
        #
        # This assertion used to read `== 7`, and the comment above it said
        # "six-service chain" — the magic number had already rotted twice,
        # and it silently pinned the very defect that left IamRoleCollector
        # unregistered. Counting collectors was never this test's job. The
        # authoritative check is now
        # TestDefaultSubCollectorRegistration below, which DERIVES the
        # expected set from the package instead of hardcoding a number.
        collector = AwsCollector(session=DenyingSession(), tenant_id=TENANT)
        assert collector._sub_collectors, "default construction produced no collectors"
        assert all(sc._account_id is None for sc in collector._sub_collectors)


class TestDefaultSubCollectorRegistration:
    """The seam no test covered — and it hid a production blocker.

    `IamRoleCollector` existed, was fully implemented, and had its own
    passing test file for months. It was never registered in
    `AwsCollector`'s default tuple, so **no real scan ever collected an
    IAM role**. Because it is the only producer of `PUBLICLY_EXPOSED`,
    the `public_identity_with_privilege` attack path — the
    highest-scoring scenario — could not fire in production, and the
    semantic IAM policy engine was unreachable.

    Every existing test passed throughout:

    - `test_aws_iam_role_collector.py` instantiates the collector
      **directly**, which says nothing about registration.
    - Every other test in this file passes an explicit `sub_collectors`
      tuple, which **bypasses** the default construction entirely.
    - The AWS integration tests that would have caught it are skipped
      without credentials.

    So these tests deliberately exercise the **default** construction
    path, which is the only place the defect could live.

    See docs/audits/post-study-guide-current-state.md §2.
    """

    def _default_collector_classes(self, monkeypatch):
        # `_resolve_account_id` calls STS; stub it so construction needs
        # no credentials. We are asserting on WIRING, not on collection.
        monkeypatch.setattr(
            "infrastructure.cloud.aws.collector._resolve_account_id",
            lambda session: "111111111111",
        )
        collector = AwsCollector(session=object(), tenant_id=TENANT, clock=CLOCK)
        return {type(c).__name__ for c in collector._sub_collectors}

    def test_every_implemented_collector_is_registered_by_default(self, monkeypatch) -> None:
        """Derived from the package, not hardcoded.

        A hardcoded list would have to be updated by the same person who
        forgot to register the collector — so it would have been updated
        wrongly, or not at all. Discovering the implementations means a
        new collector file that nobody registers fails here immediately.
        """

        import inspect
        import pkgutil
        import importlib

        from infrastructure.cloud.aws import resource_collectors
        from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector

        implemented = set()
        for module_info in pkgutil.iter_modules(resource_collectors.__path__):
            module = importlib.import_module(
                f"{resource_collectors.__name__}.{module_info.name}"
            )
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, AwsResourceCollector)
                    and obj is not AwsResourceCollector
                    and obj.__module__.startswith(resource_collectors.__name__)
                    # Private classes are shared abstract plumbing, not
                    # collectors — `_Ec2PaginatedCollector` factors the
                    # describe_*/paginate boilerplate out of the five
                    # network collectors. Registering one would put a
                    # class with no `_normalize` into a real scan.
                    #
                    # This exclusion is by naming convention rather than
                    # `inspect.isabstract`, because such a base can be
                    # concrete-by-ABC while still being unusable alone.
                    # Every PUBLIC collector is still required to be
                    # registered, which is what this test exists for.
                    and not obj.__name__.startswith("_")
                ):
                    implemented.add(obj.__name__)

        registered = self._default_collector_classes(monkeypatch)
        missing = implemented - registered
        assert not missing, (
            f"collector(s) implemented but never registered in AwsCollector: "
            f"{sorted(missing)} — they will not run in any real scan"
        )

    def test_iam_role_collector_specifically_is_registered(self, monkeypatch) -> None:
        # Named explicitly as a regression pin: this is the one that was
        # missing, and it is the only producer of PUBLICLY_EXPOSED.
        assert "IamRoleCollector" in self._default_collector_classes(monkeypatch)

    @pytest.mark.parametrize(
        "collector",
        [
            "VpcCollector",
            "SubnetCollector",
            "RouteTableCollector",
            "InternetGatewayCollector",
            "NetworkAclCollector",
            # STEP 8B.
            "RdsInstanceCollector",
        ],
    )
    def test_network_collectors_are_registered(self, monkeypatch, collector) -> None:
        # Named individually rather than relying on the derived check
        # alone, because the derived check now skips private classes and
        # these five arrived alongside that exclusion. Naming them keeps
        # the guard specific to the code that widened it.
        assert collector in self._default_collector_classes(monkeypatch)
