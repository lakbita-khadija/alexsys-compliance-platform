# STEP 8C Phase 0 — Azure identity: current state

Audit of what the repository **actually contains** before any STEP 8C
code was written. Every row was checked against the source, not against
a previous report.

---

## 1. Inventory

| Item | Exists | Location | Notes |
|---|---|---|---|
| Azure credential config | ✅ | `infrastructure/cloud/azure/credentials.py` | `AzureCredentialConfig` — strategy pointer only, no secret fields. Carries `subscription_id`, `tenant_id`, `resource_group`. |
| Azure session factory | ✅ | `infrastructure/cloud/azure/session.py` | `AzureSessionFactory.create()` returns an `AzureClients` bundle. SDK imports deferred into `create()` so collectors are unit-testable without the SDK. |
| Azure client bundle | ✅ (partial) | `session.py::AzureClients` | Holds `storage`, `network`, `compute`, `keyvault`, `monitor`, `credential`. **No `authorization` client** — the RBAC API is not reachable. |
| Azure identity provider | ✅ | `infrastructure/cloud/azure/identity.py` | STEP 6.5. Reads the `tid` claim from a real token to verify the directory. Unrelated to RBAC, but proves the credential object is reachable. |
| Azure error taxonomy | ✅ | `infrastructure/cloud/azure/errors.py` | `AzureError` → Authentication / Permission / Service / Collection. `translate_azure_error` maps by HTTP status (401→auth, 403→permission). **Reused unchanged by STEP 8C.** |
| Azure base collector | ✅ | `resource_collectors/base.py` | `AzureResourceCollector` ABC — constructor, clock, `account_id` defaulting to `clients.subscription_id`. |
| Azure collector (port impl) | ✅ | `infrastructure/cloud/azure/collector.py` | `AzureCollector(BaseCollector)`. Registers 5 sub-collectors. Failure isolation: one service failing is skipped; **all** failing raises. |
| Entra principal collector | ❌ | — | Does not exist. |
| RoleAssignment collector | ❌ | — | Does not exist. |
| RoleDefinition collector | ❌ | — | Does not exist. |
| Azure resource ID parser | ❌ | — | **No parser exists.** See §2 — three ad-hoc partial copies instead. |
| Scope parsing / classification | ❌ | — | Does not exist. Nothing in the repo distinguishes management group / subscription / resource group / resource. |
| Azure normalizers | ✅ (5) | `normalizers/{compute,keyvault,monitor,network,storage}.py` | All emit `NormalizedResource` with `cloud_provider=AZURE`. None emits an identity/RBAC resource. |
| `resource_type` vocabulary | ✅ open | free string on `NormalizedResource` | Deliberately not an enum (ADR-003 / blueprint §8). Adding `azure_principal` etc. needs no enum change. |
| `RelationshipType` vocabulary | ✅ closed, 8 members | `domain/shared/enums.py` | `contains · connects_to · protects · allows · assumes · accesses · attached_to · publicly_exposed`. **No Azure-identity-specific member, and none is needed** — see §4. |
| `ResourceRole` | ✅ | `domain/attack_paths/classification.py` | 8 roles. Azure entries exist for VM/storage/keyvault/NSG/activity-log. **No entry for any identity type** — an Azure principal would classify `OTHER`. |
| Traversable vs informational | ✅ | `classification.py` | Traversable: `ASSUMES, ACCESSES, PUBLICLY_EXPOSED, CONNECTS_TO`. Informational: `ATTACHED_TO, ALLOWS, CONTAINS, PROTECTS`. Explicit sets, so a new type forces a decision. |
| External / unresolved nodes | ✅ | `application/graph/build_resource_graph.py` | `_external_type()` classifies by id prefix; anything unrecognized → `external_resource`, `kind="external"`, `confidence="medium"`, `source_collector="relationship-inference"`. |
| Graph builder | ✅ | `build_resource_graph.py` | Materializes external targets, isolates per-edge failure, de-duplicates by `edge.identity`. |
| Graph validation / fingerprint | ✅ | `domain/graph/validation.py` | `validate_graph()` + `graph_fingerprint()` (sorted, provenance-excluded). |
| Condition evaluator | ✅ | `domain/rules/conditions.py` | Three-valued Kleene. `relationship` / `no_relationship` nodes with `target_type` filtering. |
| UNKNOWN / INDETERMINATE | ✅ | `domain/shared/unknown.py`, `conditions.py` | `UNKNOWN` sentinel whose `__bool__` raises. `_existence_quantified_or([])` → vacuously NOT_MATCHED; `no_relationship` has a `requires_collected` coverage guard. |
| STEP 8A.1 unenumerated-neighbour fix | ✅ | `conditions.py::_partition_neighbors` | **Verified provider-agnostic — see §3.** |
| Azure tests | ✅ (7 files) | `tests/unit/infrastructure/test_azure_*.py` | Collector, compute, errors, keyvault, monitor, network, storage. **No Azure test builds a graph.** No test asserts which sub-collectors `AzureCollector` registers. |
| Azure Terraform | ✅ | `terraform/azure/` | 5 modules: compute, keyvault, monitor, network, storage. **No identity/RBAC module.** |
| Azure rules | ✅ (5 files) | `rules/azure/` | compute, keyvault, monitor, network, storage. **No identity/RBAC rule.** |
| `azure-mgmt-authorization` | ❌ | — | Not declared in `pyproject.toml`, not installed. Required for RBAC. |
| `msgraph` / Microsoft Graph SDK | ❌ | — | Not declared, not installed. See §5. |

---

## 2. Correction to earlier documentation

### 2.1 `docs/architecture/phase-3-azure.md` §9.1

> ~~**Entra ID (Azure AD) identity rules are not implemented.** The IAM
> equivalent — users, MFA, privileged role assignments — requires
> Microsoft Graph, a different SDK and a different permission model
> from the ARM management plane every other collector uses.~~

**Correction.** This is **partly wrong**, and the wrong part is the part
that mattered: it lumps *privileged role assignments* in with Graph.

Azure RBAC — `roleAssignments` and `roleDefinitions` — lives on the
**ARM management plane** (`Microsoft.Authorization`), the same plane,
the same credential and the same permission model as every existing
Azure collector. It needs `azure-mgmt-authorization`, an ARM SDK
package like `azure-mgmt-storage`, not Microsoft Graph.

What genuinely *does* require Graph is the **directory object** detail:
display names, `appId`, credential expiry, MFA state, and the
system-assigned vs user-assigned managed-identity distinction.

So the accurate statement is: RBAC assignments were reachable all along
and nobody reached for them; the Graph-only attributes remain out of
reach. STEP 8C implements the first and does not fake the second.

### 2.2 `docs/audit/aws-azure-cspm-expansion-audit.md` — missing relationships

> ~~`USES` (VM→Managed Identity), `HAS_ROLE`, `GRANTS`, `CONNECTS_TO`
> (Private Endpoint→resource) — none exist in `RelationshipType`~~

**Correction.** `CONNECTS_TO` **does** exist in `RelationshipType` and
has since Phase 1; it is emitted today by
`normalizers/network.py` (`route_table --CONNECTS_TO--> igw`). The
statement is correct only for `USES`, `HAS_ROLE` and `GRANTS`.

More importantly, the framing — that new members are *needed* — does not
survive contact with the vocabulary. STEP 8C models the full RBAC chain
using `ATTACHED_TO` and `ALLOWS` and adds **no** new `RelationshipType`
(§4).

---

## 3. Is the STEP 8A.1 evaluator fix provider-agnostic?

The brief asks not to assume this because the code is shared. It was
executed, not reasoned about, against Azure-shaped identifiers.

An Entra `principalId` is a bare GUID
(`11111111-2222-3333-4444-555555555555`) — it matches none of
`_external_type`'s prefixes (`internet`, `aws-account:`, `aws-service:`,
`azure-tenant:`).

Observed:

| Check | Result |
|---|---|
| Unenumerated GUID principal → node type | `external_resource` |
| `is_external` | `True` |
| `relationship(target_type="azure_principal")` over it | `INDETERMINATE` |
| `no_relationship(...)` with no principal collected | `INDETERMINATE` (coverage guard) |

**Verdict: genuinely provider-agnostic.** The fix keys on
`node.is_external`, which is set by the graph builder for any
unenumerated target regardless of provider, not on any AWS-specific
shape. No Azure-specific change is needed.

One caveat carried into STEP 8C's tests: the `no_relationship` result
above came from the **coverage guard** (`requires_collected` found zero
principals anywhere), not from the unenumerated-neighbour path. The
case where *some* principals are enumerated but *this* assignment's
principal is not is a different code path and is tested separately.

---

## 4. Relationship vocabulary — no new member required

The RBAC chain is `principal ← assignment → role definition` plus
`assignment → scope`. Checked against the closed vocabulary:

| Edge | Type chosen | Traversable | Why |
|---|---|---|---|
| `role_assignment → principal` | `ATTACHED_TO` | No | A configuration binding: the assignment names which principal. Same meaning as `ec2_instance --ATTACHED_TO--> security_group`. |
| `role_assignment → role_definition` | `ATTACHED_TO` | No | The same kind of binding, disambiguated by `target_type` — the precedent set by EC2's two `ATTACHED_TO` kinds in STEP 8A.1. |
| `role_assignment → scope` | `ALLOWS` | No | `ALLOWS` already means "grants permission" where the security group emits it. A role assignment grants at a scope. |

**`ACCESSES` was considered and deliberately rejected.** It means "this
principal can reach this resource" and is **traversable**. Using it here
would turn every subscription-scoped role assignment into an attack-path
edge — fabricating reachability from an authorization record, which is
the failure the AWS side spent STEP 8A/8A.1 avoiding. RBAC proves
*permission*, not *network reachability* or *movement*.

No new `RelationshipType`. No inverse edges.

---

## 5. Microsoft Graph — scope decision

Not added. The brief says not to introduce a second authentication
mechanism unnecessarily, and Graph would be exactly that: a different
endpoint (`graph.microsoft.com`), a different token audience, and a
different consent model (Graph application permissions, granted by a
directory admin, not by an RBAC role).

What ARM RBAC gives without Graph is more than expected: a
`roleAssignment` carries both `principalId` **and** `principalType`, so
principal identity and kind are explicit API facts, not inferences.

What is genuinely lost, and is recorded as a limitation rather than
guessed at:

- `display_name` for any principal
- `appId` for service principals
- **Managed identities are not distinguishable.** Azure reports them
  with `principalType: ServicePrincipal`. Claiming a
  `ManagedIdentity` principal type from RBAC data alone would be an
  invention.

---

## 6. Known pre-existing issues (documented, not fixed)

Per the unrelated-defect discipline: STEP 8C does not depend on either,
so neither is touched.

1. **`_resource_group_from_id` is triplicated** across
   `resource_collectors/{storage,keyvault,compute}.py` — three
   byte-identical private copies. Duplication, not a correctness bug.
   STEP 8C adds a proper parser in a new module and does **not**
   retrofit the three call sites.
2. ~~**No test asserts `AzureCollector`'s default sub-collector
   registration.**~~

   **Correction — this row was wrong.** `test_azure_collector.py`
   contains `TestAzureCollectorDefaultWiring`, which *did* assert the
   registration. The audit missed it because the assertion was
   `len(collector._sub_collectors) == 5` — a bare count with no
   collector name in it, so a search for the collector class names
   found nothing.

   The finding survives in weakened form, and the weakness is the
   interesting part: a count catches a deletion but says nothing about
   identity. Swapping one collector for another, or registering the
   same one twice, passed it unchanged. STEP 8C rewrites that
   assertion to name the expected set explicitly and adds a
   no-duplicates check — a strengthening, not a relaxation, and the
   count still had to be updated from 5 to 7 either way.

---

## 7. Baseline recorded before any code change

| Gate | Result |
|---|---|
| `pytest` | **1956 passed, 60 skipped, 0 failed** |
| `ruff check .` | All checks passed |
| `mypy` | Success — no issues in **193 source files** |

Interpreter note: `mypy` on `PATH` is `/root/.local/bin/mypy`, which
resolves against an interpreter that cannot see this project's
site-packages and reports ~281 spurious `import-not-found` errors. The
project interpreter is `/usr/local/bin/python`; the gate is run as
`mypy --python-executable /usr/local/bin/python <packages>`. Those
import errors are an environment artifact, not code defects.

PostgreSQL must be running for the true skip count: with it stopped the
suite reports 156 skipped instead of 60, and the 96 difference is
persistence tests, not failures.
