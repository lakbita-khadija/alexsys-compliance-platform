import pytest

from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.errors import DomainError
from domain.shared.identifiers import (
    FindingId,
    InvalidIdentifier,
    ResourceId,
    RuleId,
    TenantId,
)


class TestIdentifiers:
    def test_valid_identifier_stores_value(self) -> None:
        assert TenantId("acme").value == "acme"
        assert str(TenantId("acme")) == "acme"

    @pytest.mark.parametrize("bad_value", ["", "   ", None, 123])
    def test_blank_or_non_string_identifier_is_rejected(self, bad_value) -> None:
        with pytest.raises(InvalidIdentifier):
            TenantId(bad_value)

    def test_identifiers_are_immutable(self) -> None:
        tenant_id = TenantId("acme")
        with pytest.raises(Exception):
            tenant_id.value = "other"  # type: ignore[misc]

    def test_different_identifier_types_are_never_equal(self) -> None:
        assert TenantId("acme") != ResourceId("acme")
        assert ResourceId("r-1") != RuleId("r-1")
        assert RuleId("f-1") != FindingId("f-1")

    def test_identifiers_are_hashable_for_use_as_dict_keys(self) -> None:
        registry = {TenantId("acme"): "tenant record"}
        assert registry[TenantId("acme")] == "tenant record"

    def test_invalid_identifier_is_a_domain_error(self) -> None:
        assert issubclass(InvalidIdentifier, DomainError)


class TestEnums:
    def test_cloud_provider_has_aws_and_azure_only(self) -> None:
        assert {p.value for p in CloudProvider} == {"aws", "azure"}

    def test_relationship_type_is_closed_blueprint_vocabulary(self) -> None:
        assert {r.value for r in RelationshipType} == {
            "contains",
            "connects_to",
            "protects",
            "allows",
            "assumes",
            "accesses",
            "attached_to",
            "publicly_exposed",
        }

    def test_severity_has_exactly_the_four_authoritative_levels(self) -> None:
        assert {s.value for s in Severity} == {
            "critical",
            "high",
            "medium",
            "low",
        }
