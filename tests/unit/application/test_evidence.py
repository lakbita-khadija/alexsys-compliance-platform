from datetime import datetime, timezone

from application.rules.evidence import render_evidence
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_resource(attributes=None, account_id=None) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId("sg-123"),
        resource_type="security_group",
        cloud_provider=CloudProvider.AWS,
        tenant_id=TenantId("acme"),
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=(),
        collected_at=COLLECTED_AT,
        account_id=account_id,
    )


class TestRenderEvidence:
    def test_blank_template_returns_blank(self) -> None:
        assert render_evidence("", make_resource()) == ""

    def test_renders_resource_identity_placeholders(self) -> None:
        text = render_evidence("Resource {resource_id} of type {resource_type} in {region}", make_resource())
        assert text == "Resource sg-123 of type security_group in us-east-1"

    def test_renders_attribute_placeholders(self) -> None:
        text = render_evidence(
            "SG {resource_id} allows ports {unrestricted_ingress_ports}",
            make_resource(attributes={"unrestricted_ingress_ports": (22,)}),
        )
        assert text == "SG sg-123 allows ports (22,)"

    def test_missing_placeholder_renders_literally_instead_of_raising(self) -> None:
        text = render_evidence("Value is {not_a_real_field}", make_resource())
        assert text == "Value is {not_a_real_field}"

    def test_region_defaults_to_global_when_none(self) -> None:
        resource = NormalizedResource(
            resource_id=ResourceId("user-1"),
            resource_type="iam_user",
            cloud_provider=CloudProvider.AWS,
            tenant_id=TenantId("acme"),
            region=None,
            attributes={},
            tags={},
            relationships=(),
            collected_at=COLLECTED_AT,
        )
        assert render_evidence("Region: {region}", resource) == "Region: global"

    def test_account_id_defaults_to_unknown_when_none(self) -> None:
        text = render_evidence("Account: {account_id}", make_resource(account_id=None))
        assert text == "Account: unknown"

    def test_account_id_renders_when_present(self) -> None:
        text = render_evidence("Account: {account_id}", make_resource(account_id="123456789012"))
        assert text == "Account: 123456789012"

    def test_rendering_is_deterministic(self) -> None:
        resource = make_resource(attributes={"public": True})
        template = "{resource_id} public={public}"
        results = {render_evidence(template, resource) for _ in range(20)}
        assert len(results) == 1
