"""Azure Activity Log diagnostic-setting collection."""

from __future__ import annotations

from domain.resources.models import NormalizedResource
from infrastructure.cloud.azure.errors import AzureCollectionError, translate_azure_error
from infrastructure.cloud.azure.normalizers.monitor import normalize_activity_log_setting
from infrastructure.cloud.azure.resource_collectors.base import AzureResourceCollector


class ActivityLogSettingCollector(AzureResourceCollector):
    """Collects the subscription's Activity Log diagnostic settings.

    Unlike every other Azure collector here, this one is
    SUBSCRIPTION-scoped rather than resource-scoped: there is no
    per-resource-group list. An empty result is itself meaningful — it
    means Activity Log export is not configured at all, which
    ``rules/azure/monitor.yaml`` cannot flag from a missing resource,
    so this is documented as a known limitation (see
    docs/architecture/phase-3-azure.md).
    """

    resource_type = "activity log settings"

    def collect(self) -> tuple[NormalizedResource, ...]:
        try:
            return self._collect()
        except Exception as exc:
            cause = translate_azure_error(exc, context="collecting activity log settings")
            raise AzureCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        settings = list(self._clients.monitor.subscription_diagnostic_settings.list(""))
        return tuple(self._normalize(setting, collected_at) for setting in settings)

    def _normalize(self, setting, collected_at) -> NormalizedResource:
        logs = getattr(setting, "logs", None) or []
        enabled_categories = tuple(
            str(getattr(log, "category", "")) for log in logs if getattr(log, "enabled", False)
        )

        return normalize_activity_log_setting(
            resource_id=setting.id,
            name=getattr(setting, "name", "") or "",
            storage_account_id=getattr(setting, "storage_account_id", None),
            workspace_id=getattr(setting, "workspace_id", None),
            event_hub_authorization_rule_id=getattr(setting, "event_hub_authorization_rule_id", None),
            enabled_log_categories=enabled_categories,
            retention_days=_max_retention_days(logs),
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )


def _max_retention_days(logs) -> int | None:
    """The longest retention configured across enabled log categories.

    ``None`` when no enabled category carries a retention policy at all
    — genuinely uncollected, not "zero days".
    """

    values = []
    for log in logs:
        if not getattr(log, "enabled", False):
            continue
        policy = getattr(log, "retention_policy", None)
        days = getattr(policy, "days", None) if policy is not None else None
        if days is not None:
            values.append(int(days))
    return max(values) if values else None
