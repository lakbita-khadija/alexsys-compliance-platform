"""Azure RBAC collection (STEP 8C).

Two collectors over one ARM client (`azure-mgmt-authorization`):

* ``RoleDefinitionCollector`` — every role definition in the
  subscription, built-in and custom.
* ``RoleAssignmentCollector`` — every role assignment, **plus** the
  principals and the subscription-scope node those assignments name.

The second collector emitting three resource types is deliberate and is
the honest shape of the data. ARM's authorization API has no "list
principals" operation — Entra directory objects live behind Microsoft
Graph, which this step does not add (see
``docs/audits/azure-identity-current-state.md`` §5). What it *does*
return, on every assignment, is `principalId` and `principalType`. So a
principal is known exactly when something was assigned to it, and
deriving it in the same pass is what keeps the fact and its source
together. Splitting it into a separate "principal collector" would mean
a second identical `role_assignments.list_for_subscription()` call to
learn the same thing.

De-duplication matters here in a way it does not for the other Azure
collectors: one principal typically holds several assignments, so the
same `principalId` is seen repeatedly. Each becomes exactly one
resource.
"""

from __future__ import annotations

from typing import Any, Iterable

from domain.resources.models import NormalizedResource
from infrastructure.cloud.azure.errors import AzureCollectionError, translate_azure_error
from infrastructure.cloud.azure.normalizers.authorization import (
    normalize_principal,
    normalize_role_assignment,
    normalize_role_definition,
    normalize_subscription,
)
from infrastructure.cloud.azure.resource_collectors.base import AzureResourceCollector
from infrastructure.cloud.azure.resource_ids import (
    AzureScopeType,
    parse_azure_resource_id,
    subscription_scope_id,
)


def _value(raw: Any) -> Any:
    """Unwrap an Azure SDK enum to its string value.

    The SDK returns some fields as enum objects and some as plain
    strings depending on the API version, and a rule comparing against
    ``"ServicePrincipal"`` must work either way.
    """

    return getattr(raw, "value", raw)


def _text(raw: Any) -> str | None:
    """A non-blank string, or ``None``.

    Blank is normalized to ``None`` on purpose: an empty
    ``principalId`` is missing data, and letting ``""`` through would
    create a graph node whose id is the empty string.
    """

    value = _value(raw)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


class _AuthorizationCollector(AzureResourceCollector):
    """Shared error isolation for the two RBAC collectors.

    Wraps ``_collect`` so every Azure SDK exception becomes an
    ``AzureCollectionError`` with the translated cause attached —
    matching the existing Azure taxonomy exactly. ``AzureCollector``
    then skips just this service (typically a missing
    ``Microsoft.Authorization/*/read`` permission) and continues the
    scan, rather than the whole subscription failing because RBAC was
    not readable.
    """

    def collect(self) -> tuple[NormalizedResource, ...]:
        try:
            return self._collect()
        except Exception as exc:
            cause = translate_azure_error(exc, context=f"collecting {self.resource_type}")
            raise AzureCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self) -> tuple[NormalizedResource, ...]:  # pragma: no cover - abstract
        raise NotImplementedError


class RoleDefinitionCollector(_AuthorizationCollector):
    """Every RBAC role definition visible at the subscription scope."""

    resource_type = "role definitions"

    def _collect(self) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        scope = subscription_scope_id(self._clients.subscription_id)

        definitions: list[NormalizedResource] = []
        seen: set[str] = set()

        for definition in self._iter_definitions(scope):
            definition_id = _text(getattr(definition, "id", None))
            if not definition_id:
                # A role definition with no id cannot be referenced by
                # any assignment, so it cannot be reasoned about. Skip
                # it rather than minting an id for it.
                continue
            if definition_id in seen:
                continue
            seen.add(definition_id)
            definitions.append(
                normalize_role_definition(
                    role_definition_id=definition_id,
                    role_name=_text(getattr(definition, "role_name", None)),
                    role_type=_text(getattr(definition, "role_type", None)),
                    permissions=_permission_blocks(definition),
                    assignable_scopes=[
                        s
                        for s in (getattr(definition, "assignable_scopes", None) or ())
                        if s
                    ],
                    description=_text(getattr(definition, "description", None)),
                    tenant_id=self._tenant_id,
                    collected_at=collected_at,
                    account_id=self._account_id,
                )
            )

        return tuple(definitions)

    def _iter_definitions(self, scope: str) -> Iterable[Any]:
        # The SDK's pager is iterable; `list()` walks every page. An
        # empty subscription yields an empty iterator, not an error.
        return self._clients.authorization.role_definitions.list(scope)


def _permission_blocks(definition: Any) -> list[dict[str, list[str]]]:
    """Azure's permission objects as plain dicts the normalizer can read.

    Converted here rather than in the normalizer so the normalizer stays
    a pure function over plain data and remains testable without the
    Azure SDK — the same boundary every other Azure normalizer keeps.
    """

    blocks: list[dict[str, list[str]]] = []
    for permission in getattr(definition, "permissions", None) or ():
        blocks.append(
            {
                "actions": [a for a in (getattr(permission, "actions", None) or ()) if a],
                "not_actions": [
                    a for a in (getattr(permission, "not_actions", None) or ()) if a
                ],
                "data_actions": [
                    a for a in (getattr(permission, "data_actions", None) or ()) if a
                ],
                "not_data_actions": [
                    a for a in (getattr(permission, "not_data_actions", None) or ()) if a
                ],
            }
        )
    return blocks


class RoleAssignmentCollector(_AuthorizationCollector):
    """Role assignments, the principals they name, and the subscription.

    Emits three resource types from one API call — see the module
    docstring for why that is the honest shape rather than a shortcut.
    """

    resource_type = "role assignments"

    def _collect(self) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        subscription_id = self._clients.subscription_id
        subscription_scope = subscription_scope_id(subscription_id)

        assignments: list[NormalizedResource] = []
        principals: dict[str, NormalizedResource] = {}
        seen_assignments: set[str] = set()
        subscription_is_a_scope = False

        for raw in self._iter_assignments():
            assignment_id = _text(getattr(raw, "id", None))
            if not assignment_id:
                # No id means nothing can reference it and two such
                # records could not be told apart. Skipped, and the rest
                # of the page is unaffected.
                continue
            if assignment_id in seen_assignments:
                continue
            seen_assignments.add(assignment_id)

            principal_id = _text(getattr(raw, "principal_id", None))
            principal_type = _text(getattr(raw, "principal_type", None))
            scope = _text(getattr(raw, "scope", None))

            assignments.append(
                normalize_role_assignment(
                    role_assignment_id=assignment_id,
                    principal_id=principal_id,
                    principal_type=principal_type,
                    role_definition_id=_text(getattr(raw, "role_definition_id", None)),
                    scope=scope,
                    tenant_id=self._tenant_id,
                    collected_at=collected_at,
                    account_id=self._account_id,
                )
            )

            if principal_id and principal_id not in principals:
                principals[principal_id] = normalize_principal(
                    principal_id=principal_id,
                    principal_type=principal_type,
                    directory_tenant_id=_text(
                        getattr(raw, "principal_tenant_id", None)
                    ),
                    tenant_id=self._tenant_id,
                    collected_at=collected_at,
                    account_id=self._account_id,
                )

            if scope is not None and _is_this_subscription(scope, subscription_id):
                subscription_is_a_scope = True

        resources: list[NormalizedResource] = list(assignments)
        # Sorted so two scans of unchanged RBAC produce an identical
        # resource sequence — the graph fingerprint depends on it.
        resources.extend(principals[key] for key in sorted(principals))

        if subscription_is_a_scope:
            resources.append(
                normalize_subscription(
                    subscription_scope=subscription_scope,
                    subscription_id=subscription_id.lower(),
                    tenant_id=self._tenant_id,
                    collected_at=collected_at,
                    account_id=self._account_id,
                )
            )

        return tuple(resources)

    def _iter_assignments(self) -> Iterable[Any]:
        return self._clients.authorization.role_assignments.list_for_subscription()


def _is_this_subscription(scope: str, subscription_id: str) -> bool:
    """Whether ``scope`` addresses exactly the subscription being scanned.

    Compared on the parsed subscription GUID rather than by string
    equality, because Azure returns the scope with its own casing and a
    GUID is case-insensitive. A resource-group or resource scope inside
    the same subscription returns ``False`` — it is a different scope,
    and the subscription node must not be created for it.
    """

    parsed = parse_azure_resource_id(scope)
    return (
        parsed.scope_type is AzureScopeType.SUBSCRIPTION
        and parsed.subscription_id == subscription_id.lower()
    )


__all__ = ["RoleAssignmentCollector", "RoleDefinitionCollector"]
