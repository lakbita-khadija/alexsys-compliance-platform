"""Parsing Azure's hierarchical resource IDs (STEP 8C).

Azure identifies everything with one path-shaped string:

    /subscriptions/{sub}
    /subscriptions/{sub}/resourceGroups/{rg}
    /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}
    /providers/Microsoft.Management/managementGroups/{mg}

The whole point of parsing it here rather than at each call site is that
the *scope* of an RBAC role assignment is one of these strings, and
"which kind of scope is this" is the single most consequential question
in Azure authorization. A subscription-scoped Owner assignment and a
resource-scoped Reader assignment are the same shape of record.

Three rules run through this module, all anti-fabrication:

**Nothing is inferred from a name.** A segment is read at its documented
position or not at all. `resourceGroups` is where the resource group
lives; a resource merely *called* "resourceGroups" is not one.

**An unparseable id stays unparsed.** `parse_azure_resource_id` returns
a result with `is_parsed=False` and the original string preserved. It
does not raise, and it does not guess — a malformed scope on one role
assignment must not lose the other assignments, and a half-understood
scope must never be reported as a confident one.

**Case is handled deliberately, per component.** See `CASE HANDLING`.

CASE HANDLING
-------------
Azure's case rules are not uniform, so neither is this module.

* **Structural keywords** (`subscriptions`, `resourceGroups`,
  `providers`) are matched **case-insensitively**. Azure's own APIs
  return these with inconsistent casing — ARM commonly returns
  `resourceGroups` while some services echo back `resourcegroups` — and
  every id names the same thing. This is the one place where equivalence
  is safe and demonstrable.

* **Subscription IDs** are GUIDs, compared **case-insensitively** and
  stored **lowercased**. A GUID's hex digits are case-insensitive by
  definition (RFC 4122), and Azure returns them lowercased.

* **Resource group names, provider namespaces, resource type segments
  and resource names are PRESERVED VERBATIM.** Azure treats resource
  group names as case-insensitive for lookup but case-*preserving* for
  storage, and resource names vary by provider — a storage account name
  is lowercase-only, a key vault name is not. We have no per-provider
  table proving which is which, so we do not invent equivalence. The
  verbatim value is what Azure returned, and it is what we report.

The consequence is deliberate: two ids differing only in resource-group
casing are **not** collapsed into one resource. Doing so would require
asserting an equivalence this codebase cannot demonstrate, and the cost
of being wrong (silently merging two resources) is worse than the cost
of being conservative (two nodes a human can see and reconcile).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AzureScopeType(str, Enum):
    """What level of the Azure hierarchy an id addresses.

    ``UNKNOWN`` is a real member, not a failure code: an id we cannot
    place is reported as unplaced rather than defaulted to the most
    common case. Defaulting an unrecognized scope to ``RESOURCE`` would
    understate a management-group assignment, which is the broadest and
    most dangerous grant Azure has.
    """

    MANAGEMENT_GROUP = "management_group"
    SUBSCRIPTION = "subscription"
    RESOURCE_GROUP = "resource_group"
    RESOURCE = "resource"
    UNKNOWN = "unknown"


#: Structural keywords, lowercased for case-insensitive matching.
_SUBSCRIPTIONS = "subscriptions"
_RESOURCE_GROUPS = "resourcegroups"
_PROVIDERS = "providers"
_MANAGEMENT_GROUPS = "managementgroups"


@dataclass(frozen=True, slots=True)
class AzureResourceId:
    """A parsed Azure resource id.

    ``canonical_id`` is always the string Azure gave us, never a
    reconstruction. Rebuilding it from the parsed parts would silently
    normalize casing and drop any segment this parser does not model,
    and the id is the identity — it must survive parsing byte for byte.
    """

    #: Exactly what Azure returned.
    canonical_id: str
    scope_type: AzureScopeType
    #: Lowercased GUID. ``None`` for a management-group scope.
    subscription_id: str | None = None
    #: Verbatim, not lowercased.
    resource_group: str | None = None
    #: e.g. ``Microsoft.Storage``. Verbatim.
    provider_namespace: str | None = None
    #: e.g. ``storageAccounts`` — the type path after the namespace,
    #: joined with ``/`` for nested types (``servers/databases``).
    resource_type: str | None = None
    #: The final name segment. Verbatim.
    resource_name: str | None = None
    #: Management group name, when this is a management-group scope.
    management_group: str | None = None
    #: False when the string did not match any documented shape. Every
    #: other field is then ``None`` and only ``canonical_id`` is
    #: meaningful.
    is_parsed: bool = True

    @property
    def is_subscription_scope(self) -> bool:
        return self.scope_type is AzureScopeType.SUBSCRIPTION


def _segments(resource_id: str) -> list[str]:
    """Split on ``/``, dropping the empty segments a leading or trailing
    slash produces. Azure ids start with ``/`` and may end with one.
    """

    return [segment for segment in resource_id.split("/") if segment]


def parse_azure_resource_id(resource_id: str | None) -> AzureResourceId:
    """Parse an Azure resource id. Never raises.

    A ``None``, blank, or unrecognized id yields ``is_parsed=False``
    with the original preserved, because a scan must survive one
    malformed record and a caller must be able to tell "we could not
    read this" from "this is a subscription".
    """

    if not resource_id or not resource_id.strip():
        return AzureResourceId(
            canonical_id=resource_id or "",
            scope_type=AzureScopeType.UNKNOWN,
            is_parsed=False,
        )

    parts = _segments(resource_id)
    lowered = [part.lower() for part in parts]

    # --- Management group:
    #     /providers/Microsoft.Management/managementGroups/{name}
    if (
        len(parts) >= 4
        and lowered[0] == _PROVIDERS
        and lowered[2] == _MANAGEMENT_GROUPS
    ):
        return AzureResourceId(
            canonical_id=resource_id,
            scope_type=AzureScopeType.MANAGEMENT_GROUP,
            management_group=parts[3],
        )

    # Everything else must start /subscriptions/{guid}.
    if len(parts) < 2 or lowered[0] != _SUBSCRIPTIONS:
        return AzureResourceId(
            canonical_id=resource_id,
            scope_type=AzureScopeType.UNKNOWN,
            is_parsed=False,
        )

    subscription_id = parts[1].lower()

    if len(parts) == 2:
        return AzureResourceId(
            canonical_id=resource_id,
            scope_type=AzureScopeType.SUBSCRIPTION,
            subscription_id=subscription_id,
        )

    if lowered[2] != _RESOURCE_GROUPS or len(parts) < 4:
        # /subscriptions/{sub}/<something we do not model>
        return AzureResourceId(
            canonical_id=resource_id,
            scope_type=AzureScopeType.UNKNOWN,
            subscription_id=subscription_id,
            is_parsed=False,
        )

    resource_group = parts[3]

    if len(parts) == 4:
        return AzureResourceId(
            canonical_id=resource_id,
            scope_type=AzureScopeType.RESOURCE_GROUP,
            subscription_id=subscription_id,
            resource_group=resource_group,
        )

    # --- Resource:
    #     .../providers/{ns}/{type}/{name}[/{subtype}/{subname}...]
    if lowered[4] != _PROVIDERS or len(parts) < 8:
        return AzureResourceId(
            canonical_id=resource_id,
            scope_type=AzureScopeType.UNKNOWN,
            subscription_id=subscription_id,
            resource_group=resource_group,
            is_parsed=False,
        )

    provider_namespace = parts[5]
    remainder = parts[6:]

    # A nested type alternates type/name, so the tail must be even —
    # `servers/s1/databases/d1` is types ("servers", "databases") and
    # names ("s1", "d1"). An odd tail is a shape we do not model, and
    # guessing which segment is the name would put an invented identity
    # into the graph.
    if len(remainder) % 2 != 0:
        return AzureResourceId(
            canonical_id=resource_id,
            scope_type=AzureScopeType.UNKNOWN,
            subscription_id=subscription_id,
            resource_group=resource_group,
            provider_namespace=provider_namespace,
            is_parsed=False,
        )

    type_segments = remainder[0::2]
    name_segments = remainder[1::2]

    return AzureResourceId(
        canonical_id=resource_id,
        scope_type=AzureScopeType.RESOURCE,
        subscription_id=subscription_id,
        resource_group=resource_group,
        provider_namespace=provider_namespace,
        resource_type="/".join(type_segments),
        resource_name=name_segments[-1],
    )


def classify_scope(scope: str | None) -> AzureScopeType:
    """The scope type of an RBAC assignment's ``scope`` string."""

    return parse_azure_resource_id(scope).scope_type


def subscription_scope_id(subscription_id: str) -> str:
    """The canonical scope string for a whole subscription.

    Used to give a subscription a graph node id when a role assignment
    is scoped to it. Built from Azure's own documented form, and the
    only place in this module that constructs an id rather than reading
    one — a subscription scope has exactly one shape, so there is
    nothing to guess.
    """

    return f"/subscriptions/{subscription_id.lower()}"


__all__ = [
    "AzureResourceId",
    "AzureScopeType",
    "classify_scope",
    "parse_azure_resource_id",
    "subscription_scope_id",
]
