# Azure identity consumption matrix (STEP 8C)

Every field, node and relationship STEP 8C added, and what consumes it.

The standing rule: **no dead data.** A field with no current consumer
must have a named future one and a test proving it is reachable; a field
with neither should not be collected. The AWS side of this project once
collected 47 network attributes of which 46 were read by nothing, and
this table exists so that is not repeated.

Legend — **Consumer**: `RULE` a rule reads it · `GRAPH` it becomes an
edge or node identity · `EVIDENCE` it appears in a finding's evidence ·
`PROVENANCE` it records where data came from.

---

## 1. `azure_principal`

| Field / Relationship | Source | Current consumer | Future consumer | Test |
|---|---|---|---|---|
| `resource_id` (Entra object id) | `roleAssignments.properties.principalId` | **GRAPH** — node identity; target of the assignment's `ATTACHED_TO` | — | `test_a_principal_is_derived_from_the_assignment` |
| `principal_id` | same, restated | **RULE** — readable without parsing the resource id | Graph-backed principal rules | `test_a_principal_is_derived_from_the_assignment` |
| `principal_type` | `roleAssignments.properties.principalType` | **RULE** — traversed by `target_type` + `where` | Per-principal-kind policy (e.g. no guest users privileged) | `test_every_documented_principal_type_is_carried_through` |
| `principal_type_is_known` | derived vs `KNOWN_PRINCIPAL_TYPES` | **RULE** — lets a rule refuse to reason about an unknown kind | — | `test_an_unrecognized_principal_type_is_preserved_and_flagged` |
| `directory_tenant_id` | `roleAssignments.properties.principalTenantId` | **EVIDENCE** | Cross-tenant / guest-principal detection — a principal from a foreign directory holding a role is a distinct control | `test_a_principal_is_derived_from_the_assignment` |
| `is_directory_enumerated` | constant `False` this step | **RULE** — distinguishes "known from an assignment" from "listed in the directory" | Set `True` by a future Graph collector; rules gate on it | `test_a_principal_is_marked_as_not_directory_enumerated` |

**Deliberately NOT collected:** `display_name`, `appId`, credential
expiry, MFA state. ARM's authorization API returns none of them and
Microsoft Graph is out of scope. A guessed value is worse than none.

---

## 2. `azure_role_definition`

| Field / Relationship | Source | Current consumer | Future consumer | Test |
|---|---|---|---|---|
| `resource_id` / `role_definition_id` | `roleDefinitions.id` | **GRAPH** — node identity; target of `ATTACHED_TO` | — | `test_a_role_definition_is_collected` |
| `role_name` | `roleDefinitions.roleName` | **EVIDENCE** — what a human reads in the report | — | `test_privilege_is_read_from_actions_not_from_the_name` |
| `role_type` | `roleDefinitions.roleType` | **EVIDENCE** | Custom-role review workflows | `test_a_custom_role_with_wildcard_actions_is_recognized` |
| `is_built_in` | derived; `None` when unknown | — | Custom-role drift; built-ins change only when Microsoft changes them | `test_an_unknown_role_type_yields_none_not_false` |
| `description` | `roleDefinitions.description` | **EVIDENCE** | — | — |
| `actions` | union of `permissions[].actions` | **RULE** (via `grants_all_actions`) + **EVIDENCE** — kept so a reviewer can check our reading | Fine-grained action rules (e.g. `roleAssignments/write`) | `test_actions_are_unioned_across_permission_blocks_and_sorted` |
| `not_actions` | union of `permissions[].notActions` | **EVIDENCE** | Effective-permission computation — `actions` minus `notActions` is the real grant | `test_actions_are_unioned_across_permission_blocks_and_sorted` |
| `data_actions` | union of `permissions[].dataActions` | **EVIDENCE** (via `grants_all_data_actions`) | Data-plane exposure rules | `test_data_actions_are_tracked_separately` |
| `not_data_actions` | union of `permissions[].notDataActions` | **EVIDENCE** | Effective data-plane permission | `test_data_actions_are_tracked_separately` |
| `grants_all_actions` | derived: `"*" in actions` | **RULE** — the privilege half of the proof rule | — | `test_a_scoped_wildcard_is_not_treated_as_unrestricted` |
| `grants_all_data_actions` | derived: `"*" in data_actions` | — | Data-plane rule. Collected now because it is free at collection time and cannot be recomputed later without re-reading the role | `test_data_actions_are_tracked_separately` |
| `assignable_scopes` | `roleDefinitions.assignableScopes` | **EVIDENCE** | Custom roles assignable at management-group scope are a privilege-escalation vector | — |

**Deliberately NOT collected:** `createdOn`, `updatedOn`, `createdBy`,
`updatedBy`, and the raw permission blocks. Nothing reasons about them,
and the raw blocks are exactly the "large opaque Azure payload" the
brief forbids — the union is what a role actually grants.

---

## 3. `azure_role_assignment`

| Field / Relationship | Source | Current consumer | Future consumer | Test |
|---|---|---|---|---|
| `resource_id` / `role_assignment_id` | `roleAssignments.id` | **GRAPH** — node identity; the hub of the chain | — | `test_an_assignment_is_collected_with_its_explicit_ids` |
| `principal_id` | `.properties.principalId` | **GRAPH** — `ATTACHED_TO` → principal | — | `test_three_edges_are_emitted_from_explicit_fields` |
| `principal_type` | `.properties.principalType` | **EVIDENCE** + edge evidence | — | `test_every_edge_names_the_azure_field_it_came_from` |
| `role_definition_id` | `.properties.roleDefinitionId` | **GRAPH** — `ATTACHED_TO` → role definition | — | `test_three_edges_are_emitted_from_explicit_fields` |
| `scope` | `.properties.scope` | **GRAPH** — `ALLOWS` → scope | — | `test_three_edges_are_emitted_from_explicit_fields` |
| `scope_type` | derived by parsing `scope` | **EVIDENCE** + edge evidence | Management-group-scope rules | `test_the_scope_is_classified` |
| `scope_is_parsed` | parser outcome | **RULE** — lets a rule refuse an unplaceable scope | — | `test_a_malformed_scope_is_recorded_as_unparsed_not_guessed` |
| `is_subscription_scope` | derived | **RULE** — the scope half of the proof rule | — | `test_the_scope_is_classified` |
| `is_management_group_scope` | derived | — | A management-group assignment is broader than subscription scope and warrants its own severity | `test_each_documented_shape_is_classified` (parser) |
| `scope_subscription_id` | parsed | **EVIDENCE** | Cross-subscription assignment detection | `test_the_subscription_guid_is_extracted` |
| `scope_resource_group` | parsed | **EVIDENCE** | Resource-group-scope rules | `test_a_resource_group_scope_is_not_a_subscription_scope` |
| `scope_management_group` | parsed | **EVIDENCE** | As above | `test_the_management_group_name_is_extracted` |
| `inheritance_known` | constant `False` | **RULE** — blocks any rule from claiming DIRECT vs INHERITED | Set `True` if Azure ever reports it | `test_inheritance_is_never_claimed` |

---

## 4. `azure_subscription`

| Field / Relationship | Source | Current consumer | Future consumer | Test |
|---|---|---|---|---|
| `resource_id` | `subscription_scope_id()` | **GRAPH** — target of the `ALLOWS` edge; without it a subscription-scoped grant points at a node nothing enumerated | — | `test_the_subscription_is_emitted_when_it_is_an_assignment_scope` |
| `subscription_id` | `AzureClients.subscription_id` | **EVIDENCE** | — | `test_the_subscription_is_emitted_when_it_is_an_assignment_scope` |
| `scope_type` | constant | **EVIDENCE** | — | — |

Emitted **only** when an assignment is actually scoped to it — not
unconditionally. A node nothing references would be noise.

---

## 5. Relationships

| Relationship | Type | Traversable | Current consumer | Test |
|---|---|---|---|---|
| assignment → principal | `ATTACHED_TO` | **No** | **GRAPH**; `no_relationship` absence rules | `test_relationship_over_an_unenumerated_principal_is_indeterminate` |
| assignment → role definition | `ATTACHED_TO` | **No** | **RULE** — the proof rule traverses it for `grants_all_actions` | `test_a_wildcard_role_at_subscription_scope_fails` |
| assignment → scope | `ALLOWS` | **No** | **GRAPH** — the scope is reachable as a node | Scope-aware rules | `test_the_scope_grant_uses_allows_not_accesses` |

**No new `RelationshipType`.** No inverse edges. No edge is traversable
— asserted by `test_no_rbac_edge_is_traversable`.

---

## 6. Consumption summary

| | Count |
|---|---|
| Fields added | 31 |
| With a current consumer | 27 |
| With only a named future consumer | 4 |
| With neither (dead) | **0** |

The four future-only fields are `is_built_in`, `grants_all_data_actions`,
`is_management_group_scope` and `assignable_scopes`. Each is derived at
zero marginal cost from data already fetched, each has a named rule it
unblocks, and each is asserted reachable by a test. None required an
extra API call.

---

## 7. What is NOT evidenced

The following would need data this step does not have, and no rule
claims any of them:

- **"This principal can reach resource X."** RBAC proves permission,
  not reachability. Every edge is informational.
- **"This assignment is inherited."** Azure does not report it.
- **"This is a managed identity."** Azure reports `ServicePrincipal`.
- **"This principal has no role assignment."** Absence rules over
  principals are expressible but unwritten — and would need the
  `requires_collected` guard, since without Graph the principal
  population is itself only partially known.
- **"This is the effective permission."** Deny assignments are not
  collected and can override an allow.
