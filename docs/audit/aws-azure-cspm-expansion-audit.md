# AWS / Azure CSPM Expansion — Audit

> **Status: audit only. No code was modified to produce this document.**
> Every count and behaviour below was obtained by reading or executing
> against this repository.

---

## 0. Executive summary

The headline finding is a **regression introduced by the previous phase**,
found by executing the graph builder rather than by reading it.

### BLOCKER — the IAM role collector breaks every scan it participates in

`IamRoleCollector` emits relationship edges to synthetic targets —
`internet`, `aws-account:999999999999`, `aws-service:ec2.amazonaws.com` —
that are **never added as graph nodes**. `ResourceGraph.add_edge`
enforces referential integrity, so:

```
$ BuildResourceGraph().build(tenant_id=..., resources=[<any role with a trust relationship>])
GraphIntegrityViolation: edge references unknown target node: internet
```

`BuildResourceGraph` has no per-edge isolation, so this aborts
construction of the **whole graph**, which aborts the **whole scan**.

It escaped the previous phase's 21 collector tests because every one of
them asserted on `resource.relationships` directly and none built a
graph. The collector is correct in isolation and fatal in composition —
the same class of defect the Phase 4 audit found (the graph was built but
never passed to `EvaluateRules`), recurring for the same reason: the
seam between two correct components was never exercised.

**This must be fixed before any new collector emits any edge**, or every
collector added in this phase inherits the same failure.

### Everything else

| # | Gap | Severity | §  |
|---|---|---|---|
| E1 | Graph edges to external/synthetic targets abort the scan | **BLOCKER** | §7 |
| E2 | `GraphNode` carries 3 of the 8 required fields | **HIGH** | §7 |
| E3 | `GraphEdge` carries no evidence, provenance or confidence | **HIGH** | §7 |
| E4 | No graph validation module | **HIGH** | §8 |
| E5 | 14 of 15 required collectors absent | MEDIUM | §4, §5 |
| E6 | No cross-resource rules exist | MEDIUM | §9 |
| E7 | Findings carry no `graph_context` / `relationships` | MEDIUM | §11 |
| E8 | 16 of 27 framework mappings omit `status` | LOW | §2 |

---

## 1. AWS

### Existing collectors (7)

| Collector | Paginated | Resilience layer | Emits edges |
|---|---|---|---|
| `S3Collector` | no (list_buckets is unpaginated) | no | no |
| `IamCollector` (users) | yes | no | yes (2) |
| `Ec2Collector` | yes | no | yes (2) |
| `SecurityGroupCollector` | yes | no | yes (1) |
| `CloudTrailCollector` | no | no | no |
| `KmsCollector` | yes | no | no |
| `IamRoleCollector` | yes | **yes** | yes — **and breaks the graph (E1)** |

Only `IamRoleCollector` uses the resilience layer built last phase. The
other six still have no retry, backoff or throttling.

### Existing rules — 41

`cloudtrail` 6 · `ec2` 5 · `iam` 10 · `kms` 4 · `s3` 8 ·
`security_group` 8

### Missing collectors (9)

VPC · Subnet · Network ACL · Route Table · RDS · EKS · ECR ·
CloudWatch · AWS Config

### Missing security attributes

- VPC flow logs (destination, traffic type, aggregation interval) — no
  collector at all, so "VPC without flow logs" is unwritable
- Subnet `map_public_ip_on_launch` — the field that makes "public
  subnet" decidable
- Route-table routes to IGW/NAT — required for genuine internet
  reachability rather than a `0.0.0.0/0` string match
- NACL rule structures — §4 explicitly forbids reducing these to
  booleans; nothing collects them today
- RDS `publicly_accessible`, `storage_encrypted`, backup retention
- EKS endpoint configuration and public CIDRs

### Missing relationships

`CONTAINS` (VPC→Subnet), `CONNECTS_TO` (Subnet→RouteTable),
`PROTECTS` (SG→instance) are defined in `RelationshipType` and **never
emitted by any collector**.

### Missing tests

No test anywhere builds a `ResourceGraph` from collector output. That
is precisely the gap E1 fell through.

---

## 2. Azure

### Existing collectors (5)

`AzureStorageCollector` · `AzureNetworkCollector` (NSG) ·
`AzureComputeCollector` (VM) · `AzureKeyVaultCollector` ·
`AzureMonitorCollector` (Activity Log)

None uses the resilience layer. None emits `UNKNOWN`.

### Existing rules — 27

`compute` 3 · `keyvault` 5 · `monitor` 5 · `network` 7 · `storage` 7

### Missing collectors (10)

Entra ID users · Entra ID groups · Entra ID service principals ·
Entra ID managed identities · RBAC · Azure SQL (server + database) ·
AKS · PostgreSQL · Firewall · Private Endpoints · Diagnostic Settings

### Missing security attributes

- **MFA / authentication methods** — the case `UNKNOWN` was built for.
  §5 warns Graph frequently will not return it; nothing collects it yet.
- Service principal credential age and expiry
- RBAC assignment scope (subscription / management group / resource)
- SQL public network access, TLS version, auditing, TDE
- AKS API server authorized IP ranges, private cluster, network policy

### Missing relationships

`USES` (VM→Managed Identity), `HAS_ROLE`, `GRANTS`, `CONNECTS_TO`
(Private Endpoint→resource) — none exist in `RelationshipType`, which
has 8 members and no Azure-identity vocabulary at all.

### Missing tests

Same structural gap as AWS: no Azure test builds a graph.

---

## 3. Resource Graph

### Existing nodes

`GraphNode(resource_id, tenant_id, resource_type)` — **3 fields.**

§7 requires eight. Missing: `provider`, `name`, `account/subscription`,
`region/location`, `source_collector`, `confidence`.

Consequence: a finding cannot say which account or region a related
resource is in without re-joining against the resource list, and the
graph cannot express *which collector asserted this node* — so a
disputed relationship has no provenance.

### Existing edges

`GraphEdge(source_id, target_id, relationship_type, blocked)` —
**4 fields.**

§7 requires six. Missing: `evidence`, `source_collector`, `confidence`.

Consequence: an edge is an unattributable assertion. When a
cross-resource rule fires on "EC2 → publicly exposed", the finding
cannot show *why* the graph believed that.

### Relationship types — 8 defined, 5 emitted

```
contains · connects_to · protects · allows · assumes · accesses
· attached_to · publicly_exposed
```

Emitted: `attached_to`, `accesses`, `allows`, `assumes`,
`publicly_exposed`. Never emitted: `contains`, `connects_to`,
`protects`.

Absent entirely and required by §7's Azure examples: `runs_in`,
`belongs_to`, `associated_with`, `routes_to`, `encrypted_by`, `uses`,
`has_role`, `grants`.

### Graph limitations

1. **No external/synthetic node concept.** The internet, an AWS service
   principal and a foreign account are all legitimate edge targets that
   are not collectible resources. Without a way to represent them,
   collectors must either omit those edges (losing the signal) or emit
   them and crash (E1).
2. **No per-edge isolation in `BuildResourceGraph`.** One bad edge
   aborts the entire graph.
3. **No validation module** (§8): nothing checks duplicate nodes,
   dangling references, cross-account edges, or impossible relationships
   as a reportable result — `add_edge` raises instead, which is fatal
   rather than diagnostic.
4. **Determinism is untested.** Nothing asserts that identical input
   yields an equivalent graph.

### Cross-resource evaluation limitations

The DSL's `relationship` node works and is tested. **No shipped rule
uses it** — all 68 are single-resource attribute checks. The capability
exists; the catalog does not exercise it. Writing cross-resource rules
requires E1–E4 fixed first, or they would evaluate against a graph that
either crashes or carries no evidence to report.

---

## 4. Framework references (§2)

**No separate framework catalog module exists in this repository.** The
only mechanism is `domain/rules/rule.py::FrameworkMapping`
(`framework`, `control`, `status`), whose `status` defaults to
`"unresolved"` with an explicit anti-fabrication rationale already
written into its docstring.

Identifiers currently in use — to be **reused, never renamed**:

| Identifier | Usage |
|---|---|
| `iso_27001` | primary `framework` on all 68 rules |
| `cis_aws` | 17 mappings (11 `verified`, 6 unset) |
| `cis_azure` | 9 mappings (all unset) |
| `nist_800_53` | 1 mapping (unset) |

**Finding E8:** 16 of 27 mappings omit `status`, so they silently default
to `"unresolved"`. That is the correct default, but it means the catalog
currently claims only 11 verified mappings out of 27.

Per §2, this phase creates no framework catalog, invents no control ID,
and renames nothing. Any rule needing a mapping that cannot be grounded
in the above is reported as `FRAMEWORK_MAPPING_REQUIRED`.

---

## 5. Performance observations (§15)

- **S3 N+1**: one `get_bucket_*` call per property per bucket. A
  5,000-bucket account makes roughly 35,000 calls.
- **IAM role managed-policy N+1**: `get_policy` + `get_policy_version`
  per attached policy per role. AWS-managed policies are identical
  across every role and are re-fetched each time — an obvious cache.
- **No graph construction caching**; rebuilt per scan (correct, but
  worth documenting).

---

## 6. Security observations (§16)

No issues found. Redaction runs on `attributes` and `evidence`;
`DatabaseConfig`/`IssuedToken`/`RsaKeyPair` all withhold material from
`repr`; audit metadata rejects credential-shaped keys; the resilience
layer logs error **codes**, never provider messages that could quote
request parameters.

---

## 7. Implementation plan

Dependency-ordered. E1 is not negotiable as step one: every collector
added in this phase would otherwise inherit the same fatal defect.

| Phase | Work | Unblocks |
|---|---|---|
| **1** | Fix E1 — external node concept + per-edge isolation | every collector that emits edges |
| **2** | E2/E3 — node and edge provenance, evidence, confidence | contextual findings, §11 |
| **3** | E4 — graph validation + determinism tests | §8 |
| **4** | Relationship vocabulary extension | §7's examples |
| **5** | Collectors (VPC/Subnet/RouteTable first — they make "internet reachability" real) | cross-resource rules |
| **6** | Cross-resource rules using the graph | §9 |
| **7** | Finding enrichment with `graph_context` | §11 |
| **8** | Docs + Terraform fixtures | §14, §17 |

### Scope statement

§4–§5 name **19 collectors**; §9 names **15 cross-resource rules**. That
is a multi-week body of work, and §1's rules 9–11 forbid fake collectors,
fake rules and inflated counts.

This phase therefore fixes the blocker and completes the **graph
foundation** (phases 1–4 above, plus the collectors that make it
demonstrable), then reports precisely what was and was not built. A
graph with provenance and validation is worth more than fifteen
collectors feeding a graph that crashes.
