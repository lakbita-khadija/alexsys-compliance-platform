# Azure identity foundation (STEP 8C)

Entra principals and Azure RBAC — assignments, role definitions, scopes
— as first-class, graph-resident, rule-consumable evidence.

The single sentence this document exists to defend:

> **RBAC proves permission. It does not prove reachability.**

Everything below follows from that.

---

## 1. Authentication and API architecture

No new authentication mechanism. RBAC is read through the **same**
`DefaultAzureCredential` and the **same** `AzureClients` bundle as every
existing Azure collector:

```
AzureCredentialConfig ──> AzureSessionFactory.create()
                              │
                              └──> AzureClients
                                     ├── storage / network / compute / keyvault / monitor
                                     └── authorization   ← added by STEP 8C
```

One new dependency, `azure-mgmt-authorization`, which is an **ARM
management-plane** package exactly like `azure-mgmt-storage`. It uses
the same token audience, the same credential chain and the same
permission model.

**Microsoft Graph is deliberately not used.** It is a different
endpoint, a different token audience, and a different consent model
(Graph application permissions granted by a directory admin, not by an
RBAC role) — a second authentication mechanism in everything but name.

Scanner permission required: `Microsoft.Authorization/*/read`, which
the built-in **Reader** role already grants.

### What that costs

| Available from ARM RBAC | Requires Microsoft Graph |
|---|---|
| `principalId` (Entra object id) | `displayName` |
| `principalType` | `appId` for service principals |
| `roleDefinitionId`, role name, permissions | credential age / expiry |
| `scope`, `assignableScopes` | MFA and authentication methods |
| — | system- vs user-assigned managed identity |

The first column is enough to model the authorization graph honestly.
The second is recorded as a limitation and is not guessed at.

---

## 2. Principal model

An `azure_principal` is identified by its **Entra object id** and by
nothing else.

```python
resource_id = principal_id          # e.g. aaaaaaaa-0000-...-000000000001
attributes  = {
    "principal_id":            "...",   # restated for rule access
    "principal_type":          "ServicePrincipal",  # verbatim
    "principal_type_is_known": True,
    "directory_tenant_id":     "...",   # the Entra directory
    "is_directory_enumerated": False,
}
```

Three decisions worth stating:

**No display name is collected.** ARM's authorization API returns none.
A name derived from anything else on the assignment would be an
invention, and identity must never depend on a mutable label.

**`principal_type` is preserved verbatim, and flagged.** An
unrecognized value is kept as-is with `principal_type_is_known: False`
rather than mapped onto the nearest known kind, so a rule can refuse to
reason about a principal kind we do not understand.

**`is_directory_enumerated` is always `False`** in this step, and that
is the honest statement of where the data came from: we know this
principal exists *because something was assigned to it*, not because we
listed the directory. A future Graph collector would set it `True`, and
rules can already tell the two apart.

`directory_tenant_id` is the **Azure AD tenant**. It is never conflated
with ComplianceIQ's own `TenantId`, which is always supplied by the
caller.

### Principal types

| Type | Supported | Notes |
|---|---|---|
| User | ✅ | `principalType: User` |
| Group | ✅ | `principalType: Group` |
| Service Principal | ✅ | `principalType: ServicePrincipal` |
| **Managed Identity** | ❌ | **Not distinguishable.** Azure reports managed identities as `ServicePrincipal`; no RBAC field separates them. Claiming the distinction would be an invention. |
| ForeignGroup, Device | ✅ | Carried through; no rule consumes them yet. |

Managed identities *are* collected — they simply appear as service
principals, which is what Azure itself says they are at this API.

---

## 3. RoleDefinition model

Only fields with a consumer. Actions are unioned across Azure's
permission blocks and sorted; the raw blocks are discarded, because a
role grants the union and nothing reasons about which block an action
came from.

```python
attributes = {
    "role_definition_id": "...",
    "role_name": "Owner",
    "role_type": "BuiltInRole",
    "is_built_in": True,              # None when unknown — not False
    "description": "...",
    "actions": ["*"],                 # sorted union
    "not_actions": [], "data_actions": [], "not_data_actions": [],
    "grants_all_actions": True,       # derived ALONGSIDE the evidence
    "grants_all_data_actions": False,
    "assignable_scopes": ["..."],
}
```

`grants_all_actions` is `"*" in actions` — **exactly** `*`, not
`Microsoft.Storage/*`, which is broad but bounded.

This is why the proof rule does not test `role_name == "Owner"`. A name
test would miss a custom role with identical power and would fire on a
harmless role someone happened to name "Owner". Both cases are tested.

`grants_all_data_actions` is tracked separately because data-plane `*`
reads blob and key *content*, which control-plane `*` alone does not.

---

## 4. Scope model

Every scope string is parsed by
`infrastructure/cloud/azure/resource_ids.py` and classified:

| Scope type | Shape |
|---|---|
| `management_group` | `/providers/Microsoft.Management/managementGroups/{name}` |
| `subscription` | `/subscriptions/{guid}` |
| `resource_group` | `/subscriptions/{guid}/resourceGroups/{rg}` |
| `resource` | `.../providers/{ns}/{type}/{name}` |
| `unknown` | anything else |

`unknown` is a real member, not a failure code. An unrecognized scope
defaulted to `resource` would understate a management-group assignment
— the broadest grant Azure has. `scope_is_parsed: False` lets a rule
refuse to reason about it.

### Case handling

Deliberate per component, because Azure's own rules are not uniform:

| Component | Treatment | Why |
|---|---|---|
| `subscriptions`, `resourceGroups`, `providers` | case-**insensitive** match | Azure's APIs return these with inconsistent casing; every spelling names the same thing. |
| Subscription GUID | case-insensitive, stored **lowercased** | Hex digits are case-insensitive by definition (RFC 4122). |
| Resource group name | **verbatim** | Azure is case-preserving here. |
| Provider namespace, resource type, resource name | **verbatim** | Rules vary per provider — a storage account name is lowercase-only, a key vault name is not. We have no per-provider table proving equivalence. |

The consequence is deliberate and asserted by a test: two ids differing
only in resource-group casing are **not** collapsed into one resource.
Silently merging two resources is worse than reporting two a human can
reconcile.

### Inheritance

**Never claimed.** Azure's `list_for_subscription` returns assignments
that apply at the queried scope *and* ones inherited from above, and the
response does not mark which is which. So:

- every assignment carries `inheritance_known: False`
- no assignment is labelled DIRECT or INHERITED
- **no child-resource edges are synthesized.** A subscription-scoped
  assignment produces exactly **one** `ALLOWS` edge — to the
  subscription — not thousands of edges to every resource inside it.

Inventing that fan-out would be the single fastest way to turn this
graph into a false-positive generator.

---

## 5. Graph representation

**RoleAssignment is a first-class node.** The alternative — folding it
into evidence on the principal — was rejected for a concrete reason: a
principal typically holds several assignments, and each pairs *one* role
with *one* scope. Flattened, "Owner at the subscription" and "Reader on
one storage account" become two lists whose pairing is lost, and that
pairing is the entire security question.

The hub node keeps the pair intact and costs one node per assignment,
which is what Azure itself has.

```
azure_principal  <──ATTACHED_TO──  azure_role_assignment
                                          │
                                          ├──ATTACHED_TO──> azure_role_definition
                                          │
                                          └──ALLOWS───────> scope
```

Every edge is emitted from the **assignment**, because that is the side
Azure reports all three fields on. No inverse edges: one fact, one edge,
so the two directions cannot drift after a partial scan.

### Relationship semantics and traversability

| Edge | Type | Traversable | Source field |
|---|---|---|---|
| assignment → principal | `ATTACHED_TO` | **No** | `roleAssignments.properties.principalId` |
| assignment → role definition | `ATTACHED_TO` | **No** | `roleAssignments.properties.roleDefinitionId` |
| assignment → scope | `ALLOWS` | **No** | `roleAssignments.properties.scope` |

**No new `RelationshipType` was added.** The closed 8-member vocabulary
already expressed all three.

`ACCESSES` was available and **deliberately rejected**. It means "this
principal can reach this resource" and is **traversable**. Using it here
would turn every subscription-scoped assignment into an attack-path edge
to everything in the subscription — fabricating movement out of an
authorization record. Two tests assert no RBAC edge is traversable.

### Resource roles

| Type | Role | Why |
|---|---|---|
| `azure_principal` | `IDENTITY` | Matches `iam_role` / `iam_user`. Left unclassified it would be `OTHER` — never worth reaching. |
| `azure_role_assignment` | `OTHER` | An authorization record, not a target. |
| `azure_role_definition` | `OTHER` | Likewise. |
| `azure_subscription` | `OTHER` | A scope container, not a target. |

Classified explicitly rather than by omission, so none silently inherits
a role later.

---

## 6. External / unresolved principals

Reuses the repository's existing semantics unchanged. An Entra GUID
matches none of `BuildResourceGraph._external_type`'s prefixes, so an
assignment naming an unenumerated principal materializes:

```
resource_type    = "external_resource"     # NOT azure_principal
kind             = "external"
confidence       = "medium"
source_collector = "relationship-inference"
```

Not typed `azure_principal`: a GUID is not evidence of a type, and a
rule targeting `azure_principal` must not match a node nobody
enumerated. The edge is **kept** — dropping it would lose the fact that
Azure told us something is assigned here.

This is not hypothetical. Deleting a managed identity can leave an
orphaned role assignment pointing at a dead object id, which is exactly
this state.

---

## 7. UNKNOWN / INDETERMINATE behaviour

| Situation | Result |
|---|---|
| Evidence confirms the condition | `FAIL` |
| Evidence confirms the safe state | `PASS` |
| Role definition not enumerated | `INDETERMINATE` |
| Principal not enumerated | `INDETERMINATE` |
| `AccessDenied` on the RBAC API | service skipped; no false `PASS` |
| Scope string unparseable | `scope_is_parsed: False`; rule can refuse |
| Attribute present but `UNKNOWN` | `INDETERMINATE` |

The STEP 8A.1 unenumerated-neighbour fix was **verified, not assumed**,
to be provider-agnostic — it keys on `node.is_external`, which the graph
builder sets for any unenumerated target regardless of provider. Both
quantifiers are tested against an Azure principal:

- `relationship(...)` over an unenumerated principal → `INDETERMINATE`
  (would otherwise be a false `PASS`)
- `no_relationship(...)` over one → `INDETERMINATE` (would otherwise be
  a fabricated violation), tested with *other* principals enumerated so
  the coverage guard is not what produces the result

---

## 8. Data provenance

Every relationship carries the Azure field it came from:

```python
evidence = {"source_field": "roleAssignments.properties.principalId", ...}
confidence = "high"
```

`high` because both endpoints and the link between them came from one
API response with nothing inferred.

Nothing is derived from a display name, a resource name, a tag, or
string similarity. Where a field is absent, the attribute is `None` and
**no edge is emitted** — an unverified privilege edge is worse than a
missing one.

---

## 9. Error handling

Reuses `infrastructure/cloud/azure/errors.py` unchanged. Both RBAC
collectors wrap collection so any SDK exception becomes an
`AzureCollectionError` with the translated cause attached
(403 → `AzurePermissionError`).

`AzureCollector` then skips just RBAC and continues the scan. A missing
`Microsoft.Authorization/*/read` role is the common case and must not
cost the whole subscription.

One malformed record costs one record: a missing id, a null principal or
an unparseable scope is skipped or nulled individually.

---

## 10. Known limitations

1. **Microsoft Graph attributes are unavailable** — display names,
   `appId`, credential expiry, MFA state. See §1.
2. **Managed identities are not distinguishable from other service
   principals.** Azure's RBAC API does not separate them.
3. **Inheritance is not modelled.** Azure does not report whether an
   assignment is direct or inherited at the queried scope.
4. **Management-group scoped assignments are visible but their targets
   are not enumerated.** The collector lists at subscription scope; a
   management-group scope becomes an external node.
5. **Deny assignments are not collected.** They are a separate API and
   can override an allow — so a `FAIL` from the proof rule states
   granted permission, not effective permission.
6. **`_resource_group_from_id` remains triplicated** across three
   pre-existing collectors. STEP 8C added a proper parser and did not
   retrofit them, per the unrelated-defect discipline.
7. **No live Azure verification.** All verification is against fakes
   built from documented response shapes.
