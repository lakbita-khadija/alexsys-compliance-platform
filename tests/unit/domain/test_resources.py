from datetime import datetime, timezone

import pytest

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.errors import InvalidResource, InvalidResourceRelationship
from domain.shared.identifiers import ResourceId, TenantId

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_resource(**overrides) -> NormalizedResource:
    defaults = dict(
        resource_id=ResourceId("s3-bucket-1"),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=TenantId("acme"),
        region="us-east-1",
        attributes={"encrypted": False},
        tags={"env": "prod"},
        relationships=(),
        collected_at=COLLECTED_AT,
    )
    defaults.update(overrides)
    return NormalizedResource(**defaults)


class TestNormalizedResource:
    def test_valid_resource(self) -> None:
        resource = make_resource()
        assert resource.resource_id == ResourceId("s3-bucket-1")
        assert resource.resource_type == "s3_bucket"
        assert resource.cloud_provider is CloudProvider.AWS
        assert resource.tenant_id == TenantId("acme")
        assert resource.collected_at == COLLECTED_AT

    def test_account_id_defaults_to_none(self) -> None:
        assert make_resource().account_id is None

    def test_account_id_may_be_set(self) -> None:
        resource = make_resource(account_id="123456789012")
        assert resource.account_id == "123456789012"

    def test_blank_account_id_is_rejected(self) -> None:
        with pytest.raises(InvalidResource):
            make_resource(account_id="   ")

    def test_resource_type_stays_provider_specific_free_string(self) -> None:
        # Blueprint §8: resource_type is NOT abstracted into a canonical
        # category (e.g. OBJECT_STORAGE) — any non-blank string is valid.
        resource = make_resource(resource_type="blob_container")
        assert resource.resource_type == "blob_container"

    def test_invalid_resource_type_is_rejected(self) -> None:
        with pytest.raises(InvalidResource):
            make_resource(resource_type="")

    def test_global_resource_may_omit_region(self) -> None:
        # IAM users are a real, blueprint-listed AWS resource with no region.
        resource = make_resource(resource_type="iam_user", region=None)
        assert resource.region is None

    def test_attributes_preserve_provider_specific_data_without_schema(self) -> None:
        resource = make_resource(
            attributes={"encrypted": False, "versioning": {"enabled": True}}
        )
        assert resource.attributes["versioning"]["enabled"] is True

    def test_attributes_are_immutable(self) -> None:
        resource = make_resource(attributes={"encrypted": False})
        with pytest.raises(TypeError):
            resource.attributes["encrypted"] = True  # type: ignore[index]

    def test_tags_are_immutable(self) -> None:
        resource = make_resource(tags={"env": "prod"})
        with pytest.raises(TypeError):
            resource.tags["env"] = "dev"  # type: ignore[index]

    def test_tenant_association_is_required(self) -> None:
        with pytest.raises(TypeError):
            NormalizedResource(  # type: ignore[call-arg]
                resource_id=ResourceId("r-1"),
                resource_type="s3_bucket",
                cloud_provider=CloudProvider.AWS,
                region="us-east-1",
                attributes={},
                tags={},
                relationships=(),
                collected_at=COLLECTED_AT,
            )

    def test_collected_at_must_be_a_datetime(self) -> None:
        with pytest.raises(InvalidResource):
            make_resource(collected_at="2026-01-01")

    def test_collected_at_must_be_timezone_aware(self) -> None:
        with pytest.raises(InvalidResource):
            make_resource(collected_at=datetime(2026, 1, 1))

    def test_relationships_hold_resource_relationship_instances(self) -> None:
        relationship = ResourceRelationship(
            target_resource_id=ResourceId("sg-1"),
            relationship_type=RelationshipType.PROTECTS,
        )
        resource = make_resource(relationships=(relationship,))
        assert resource.relationships == (relationship,)


class TestResourceRelationship:
    def test_valid_relationship(self) -> None:
        relationship = ResourceRelationship(
            target_resource_id=ResourceId("sg-1"),
            relationship_type=RelationshipType.ALLOWS,
        )
        assert relationship.target_resource_id == ResourceId("sg-1")
        assert relationship.relationship_type is RelationshipType.ALLOWS

    def test_relationship_type_must_be_from_closed_vocabulary(self) -> None:
        with pytest.raises(InvalidResourceRelationship):
            ResourceRelationship(
                target_resource_id=ResourceId("sg-1"),
                relationship_type="hacks_into",  # type: ignore[arg-type]
            )
