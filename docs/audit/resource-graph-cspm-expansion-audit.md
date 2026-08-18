# Resource Graph CSPM Expansion — Audit

> **Audit only. No code was modified to produce this document.**
> Every count was obtained by executing a query against the repository,
> not by reading and inferring — which is how the error corrected in §2
> was made in the first place.

Companion to [`aws-azure-cspm-expansion-audit.md`](aws-azure-cspm-expansion-audit.md),
which covered collector and rule coverage. This one focuses on the graph
as a **reasoning layer**: query surface, cross-resource evaluation,
contextual findings, attack-path readiness.

---

## 1. Current architecture

```
credentials ─▶ collectors ─▶ normalizers ─▶ NormalizedResource
                                                   │
                                    BuildResourceGraph (+ external nodes)
                                                   │
                                            ResourceGraph
                                                   │
                                    EvaluateRules (graph passed in)
                                                   │
                                    Finding ─▶ scoring ─▶ API
```

The pipeline is **complete end to end**. Every stage exists, is tested,
and the graph genuinely reaches the rule engine — a Phase 4 audit finding
that has since been fixed and regression-tested.

---

## 2. What works — and a correction

### Cross-resource evaluation is live, not theoretical

**7 shipped rules traverse the graph**, spanning both clouds:

| Rule | File |
|---|---|
| `cloudtrail-logs-to-non-versioned-bucket` | `rules/aws/cloudtrail.yaml` |
| `cloudtrail-logs-to-public-bucket` | `rules/aws/cloudtrail.yaml` |
| `ec2-instance-attached-to-open-security-group` | `rules/aws/ec2.yaml` |
| `security-group-allows-another-open-security-group` | `rules/aws/security_group.yaml` |
| `azure-vm-attached-to-open-network-security-group` | `rules/azure/compute.yaml` |
| `azure-activity-log-exports-to-publicly-exposed-storage` | `rules/azure/monitor.yaml` |
| `azure-activity-log-exports-to-storage-without-soft-delete` | `rules/azure/monitor.yaml` |

> **Correction.** The previous phase's report stated *"Cross-resource
> rules: 0"*. That was wrong. It was inferred from "no rule **I** wrote
> uses the relationship node" instead of querying the catalog, which is
> exactly the reasoning error this audit's verification policy exists to
> prevent.
>
> The difference is material: at 0, the graph looks speculative and the
> honest recommendation is "prove it with one rule". At 7, the graph is
> load-bearing across two clouds — and the blocker fixed last phase was
> breaking **all seven** whenever an IAM role was in scope.

### Also working

- Three-valued Kleene logic end to end, including through relationship
  conditions
- External nodes, node/edge provenance, graph validation, deterministic
  fingerprint (all added last phase)
- A `relationship` condition evaluated without a graph **raises** rather
  than returning INDETERMINATE — a wiring bug is not a data gap
- 32 operators; 68 rules; resilience layer; UNKNOWN tri-state; semantic
  IAM analysis

---

## 3. What is missing

### 3.1 Graph query surface (Phase C) — the real gap

`ResourceGraph` exposes exactly five query methods:

```
nodes · edges · has_node · get_node · neighbors
```

`neighbors()` is one hop, one relationship type, one direction. Every
question §1.6 asks for beyond that must be answered by the caller
scanning `graph.edges` linearly:

| §1.6 asks for | Exists |
|---|---|
| `get_neighbors` | partial — requires an exact relationship type |
| `get_children` / `get_parents` | no |
| `find_related(id, type)` | partial |
| `find_resources(resource_type)` | **no — O(n) scan** |
| `find_paths(source, target)` | **no** |
| `has_relationship(s, r, t)` | **no** |
| `find_resources_exposed_to_internet()` | **no** |
| `find_resources_using_identity()` | **no** |
| `find_public_resources()` | **no** |
| `find_resources_without_required_relationship()` | **no** |

The last one matters more than it looks: *"critical resource with **no**
private endpoint"* and *"resource with **no** diagnostic settings"* are
both **absence** queries, and the DSL's relationship node is
existence-quantified (OR across neighbours). **Absence of a relationship
is currently inexpressible**, which blocks a whole class of §21 rules.

### 3.2 Performance (§15)

No indexes. `ResourceGraph` stores `_nodes: dict` and `_edges: list`.
Every relationship query is a linear scan of all edges, so evaluating R
relationship rules over N resources is **O(R × N × E)**. Fine at 183
nodes; not fine at the 1000-resource benchmark §15 asks for. No benchmark
exists.

### 3.3 Contextual findings (§3)

`Finding` has 23 fields and **none** of `related_resources`,
`relationship_path`, `graph_context`. `graph_context_for()` exists in
`domain/graph/validation.py` and is tested, but nothing calls it.

So a cross-resource finding today says *"EC2 instance attached to an open
security group"* without naming **which** security group — the rule
traversed the edge, and the traversal result is discarded.

### 3.4 Attack paths (§4, §22)

No path-finding. `blocked` exists on `GraphEdge` and is never set `True`
by any collector. `AnalyzeAttackPaths` is a documented placeholder. No
`attack_path` / `exposure_path` / `privilege_path` representation.

### 3.5 Collectors and relationship vocabulary

Unchanged from the companion audit: **12 of 26** target services
collected; **5 of 8** relationship types emitted. `CONTAINS`,
`CONNECTS_TO`, `PROTECTS` are defined and never produced, and they are
precisely the network-topology edges §21's reachability rules need.

---

## 4. Blockers

**None.** The blocker found last phase (graph edges to synthetic targets
aborting every scan) is fixed and regression-tested.

---

## 5. Regression risks

| Change | Risk | Mitigation |
|---|---|---|
| Adding graph indexes | Silent divergence between index and edge list | Build indexes **inside** `add_edge`; assert index and scan agree |
| Absence-quantified conditions | Inverting existing OR semantics would flip all 7 live rules | New operator, never a change to `relationship` |
| Finding enrichment | `Finding` is a frozen dataclass consumed by the 11-field AI contract | Additive optional field only; the ACL already projects a fixed 11 |
| Relationship vocabulary | Renaming would break 7 live rules and 68 catalog entries | Additive only |

---

## 6. Recommended order

1. **Graph query layer + indexes** (§1.6, §15) — unblocks everything, no
   collectors needed, directly improves the 7 live rules
2. **Absence-quantified relationship condition** (§2.1) — unlocks the
   "missing private endpoint / missing diagnostics" rule class
3. **Finding contextualization** (§3) — makes the 7 live rules explain
   themselves
4. Benchmark at 100 / 500 / 1000 resources (§15)
5. Then collectors (VPC → Subnet → RouteTable first: they emit the three
   missing relationship types)
6. Then attack-path foundation, once topology edges exist

Steps 1–4 need **no new collector** and raise the value of what already
ships. That is the order this phase follows.

### Scope statement

§5–§6 name 19 collectors, §21 names 20 cross-resource rules. That is
multi-week work. This phase does 1–4 properly and reports exactly what
remains, rather than adding collectors to a graph that cannot yet be
queried efficiently or explain its own findings.
