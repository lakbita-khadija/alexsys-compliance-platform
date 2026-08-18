# CSPM Multi-Cloud Expansion — Implementation Report

> **Verification policy.** Every number was produced by executing a
> command. Work not done is listed as not done. §1 rules 9–11 forbid fake
> collectors, fake rules and inflated counts — that constraint governs
> this report as much as the code.

---

## 1. Headline

The audit found a **blocker that the previous phase shipped**, and it
changed this phase's plan entirely.

`IamRoleCollector` emitted graph edges to synthetic targets — `internet`,
`aws-account:999999999999`, `aws-service:ec2.amazonaws.com` — that were
never added as nodes. `ResourceGraph.add_edge` enforces referential
integrity and `BuildResourceGraph` had no per-edge isolation, so:

```
GraphIntegrityViolation: edge references unknown target node: internet
```

**Any IAM role with a trust policy aborted the entire scan.**

It escaped 21 collector tests because every one asserted on
`resource.relationships` directly and none built a graph. Both components
were correct; their seam was never exercised — the same class of defect,
for the same reason, as the Phase 4 audit's "graph built but never passed
to `EvaluateRules`".

Every collector this phase was asked to add emits edges. All 14 would
have inherited the same fatal defect. So the blocker was fixed first, and
the graph foundation completed, rather than stacking collectors on a
graph that crashes.

---

## 2. §19 — the requested numbers

```
AWS collectors:            7   (unchanged)
Azure collectors:          5   (unchanged)

AWS rules:                41   (unchanged)
Azure rules:              27   (unchanged)

Operators:                32   (unchanged)
Relationship types:        8 defined / 5 emitted

Graph nodes:      collected + external (new node kind)
Graph edges:      provenance-carrying (evidence, collector, confidence)

Cross-resource rules:      7   (pre-existing; see the correction in §10)
Attack-path foundations:   partial — `blocked` field + traversal substrate;
                           discovery NOT implemented

Tests:                  1245 collected
Passed:                 1185
Skipped:                  60   (AWS/Azure integration; need real credentials)
Failed:                    0
```

---

## 3. What was delivered

### 3.1 The blocker fix — external nodes

Fixed with an **external-node concept**, not by dropping the edges.
Dropping them would lose the signal cross-resource rules depend on:
*"this role is assumable from the internet"* **is** the finding.

External targets are materialized with `kind="external"` and reduced
confidence, so a rule can distinguish *"points outside the scan"* from
*"points at a resource we failed to collect"*. Conflating those produces
confident findings about resources nobody enumerated.

Edge addition is now isolated per-edge and rejections are **reported**
via `GraphBuildResult.rejected_edges`, never silently swallowed — a graph
missing an edge is a cross-resource rule that silently stops firing.

### 3.2 Provenance (§7)

| | Before | After |
|---|---|---|
| `GraphNode` | 3 fields | **10** — +provider, name, account_id, region, source_collector, confidence, kind |
| `GraphEdge` | 4 fields | **7** — +evidence, source_collector, confidence |

All additive; every existing 3- and 4-argument construction still works.

### 3.3 Validation (§8)

`domain/graph/validation.py` — **diagnostic, not fatal**. A scan should
not die because two collectors disagreed about a region.

Detects: dangling edges, duplicate edges, self-loops, cross-account edges
(INFO — a role trusting a partner account is intended), impossible
relationships, orphan external nodes.

### 3.4 Determinism (§8)

`graph_fingerprint()` sorts nodes and edges and **excludes provenance**,
so two scans learning the same topology from different collectors produce
the same fingerprint, while a genuine topology change does not.

### 3.5 Graph context for findings (§11)

`graph_context_for()` returns a resource's neighbourhood with
deterministic ordering — the structured relationship data §11 asks the
Finding to expose for the future AI Copilot.

**Not yet wired into `Finding`.** The function exists and is tested; the
application-layer plumbing that attaches it to each finding is not
written.

---

## 4. What was NOT done — explicitly

§1 rules 9–11. None of the following exists in any form, not even a
placeholder.

### Collectors — 0 of 14 added

**AWS (9):** VPC, Subnet, Network ACL, Route Table, RDS, EKS, ECR,
CloudWatch, AWS Config
**Azure (10+):** Entra ID users/groups/service principals/managed
identities, RBAC, Azure SQL server + database, AKS, PostgreSQL, Firewall,
Private Endpoints, Diagnostic Settings

### Rules — unchanged at 41 AWS / 27 Azure

**No NEW cross-resource rules were written.** Seven already existed and
this report originally said zero — see the correction in §10. Additional
ones would target resource types no collector produces and would always
return INDETERMINATE, which is fake coverage.

### Also not done

- Relationship vocabulary **not extended**. §7's examples need
  `runs_in`, `belongs_to`, `associated_with`, `routes_to`,
  `encrypted_by`, `uses`, `has_role`, `grants` — none added, because
  adding enum values with no collector emitting them is decoration.
- No Terraform fixtures added (§14).
- `Finding` not enriched with `graph_context` / `relationships` (§11).
- The six pre-existing collectors still do **not** use the resilience
  layer; only `IamRoleCollector` does. S3 and CloudTrail still lack
  paginators.
- S3 and IAM managed-policy N+1 unaddressed (§15).

### Not verified

- **No collector was run against a real AWS or Azure API.** All collector
  tests use fakes modelled on documented response shapes.
- No load testing.

---

## 5. Framework mappings (§2)

**No framework catalog was created, no control ID invented, no identifier
renamed.**

The repository has no separate framework reference module; the only
mechanism is `FrameworkMapping(framework, control, status)`, whose
`status` already defaults to `"unresolved"` with an anti-fabrication
rationale in its docstring.

Identifiers in use, to be reused: `iso_27001` (primary on all 68 rules),
`cis_aws`, `cis_azure`, `nist_800_53`.

**`FRAMEWORK_MAPPING_REQUIRED`** — 16 of 27 existing mappings omit
`status` and therefore default to `"unresolved"`. The catalog currently
carries 11 verified mappings out of 27. Resolving them requires checking
against published benchmark text, which is the framework owner's
responsibility, not this phase's.

No new rules were added, so no new mapping was needed.

---

## 6. Backward compatibility (§1 rules 6–8)

| Check | Result |
|---|---|
| Existing YAML rules still load | 68/68 |
| Public interfaces broken | none |
| Full suite | **1185 passed, 60 skipped, 0 failed** |
| ruff | clean |
| mypy | clean, 169 source files |

**One pre-existing test was rewritten, and it is not weakened.**

`test_relationship_to_uncollected_resource_raises_graph_integrity_violation`
asserted that `BuildResourceGraph` *raises* on an uncollected target —
the exact behaviour that was the blocker.

The invariant is **relocated, not removed**: `ResourceGraph.add_edge`
still refuses a dangling edge, and that is now asserted directly against
the aggregate that owns the rule. A second test pins the new builder
behaviour. Net: one assertion became two, and the docstring records why.

---

## 7. Security (§16)

No issues found. Redaction covers attributes and evidence; config, token
and key objects withhold material from `repr`; audit metadata rejects
credential-shaped keys; the resilience layer logs error **codes**, never
provider messages that could quote request parameters. Graph evidence
contains only resource identifiers and types.

---

## 8. Files

**Created (5)**
```
domain/graph/validation.py
tests/unit/domain/test_graph_expansion.py          (31 tests)
docs/audit/aws-azure-cspm-expansion-audit.md
docs/architecture/resource-graph.md
docs/architecture/cspm-expansion-report.md
```

**Modified (3)**
```
domain/graph/models.py                       node/edge provenance, external kind
application/graph/build_resource_graph.py    external materialization, edge isolation
tests/unit/application/test_build_resource_graph.py   invariant relocated (§6)
```

---

## 9. Remaining limitations

This is **not production ready**, and passing tests do not make it so.

1. **Coverage is 12 of 26 target services.** The graph foundation is
   sound; the breadth that would make it valuable is absent.
2. **Zero cross-resource rules ship.** The headline capability of a
   graph-based CSPM is unexercised by the catalog.
3. **Only 5 of 8 relationship types are emitted**, and the three missing
   ones (`contains`, `connects_to`, `protects`) are exactly the network
   topology edges that make internet-reachability rules possible.
4. **`blocked` is never set `True`** by any collector, so attack-path
   traversal would treat every path as unblocked.
5. **Six of seven AWS collectors and all five Azure collectors lack
   resilience.** The layer exists; it is applied once.
6. **No live API validation.** Response shapes are modelled from
   documentation.
7. **Attack-path discovery is not implemented** and no scoring model
   exists — inventing one would be fabrication.

### Recommended next order

1. VPC + Subnet + Route Table collectors — they emit `contains`,
   `connects_to`, `routes_to` and make internet reachability real
2. The first genuine cross-resource rule, end-to-end with a graph test
3. Migrate the six existing AWS collectors onto the resilience layer
4. Then breadth: RDS, EKS, Azure SQL, AKS


---

## 10. Correction — cross-resource rule count

This report originally stated **"Cross-resource rules: 0"**. That was
wrong, and the error was mine: I inferred it from "no rule I wrote uses
the relationship node" rather than querying the catalog.

**Seven shipped rules already traverse the graph**, enumerated by walking
every condition tree for a `relationship` node:

| Rule | File |
|---|---|
| `cloudtrail-logs-to-non-versioned-bucket` | `rules/aws/cloudtrail.yaml` |
| `cloudtrail-logs-to-public-bucket` | `rules/aws/cloudtrail.yaml` |
| `ec2-instance-attached-to-open-security-group` | `rules/aws/ec2.yaml` |
| `security-group-allows-another-open-security-group` | `rules/aws/security_group.yaml` |
| `azure-vm-attached-to-open-network-security-group` | `rules/azure/compute.yaml` |
| `azure-activity-log-exports-to-publicly-exposed-storage` | `rules/azure/monitor.yaml` |
| `azure-activity-log-exports-to-storage-without-soft-delete` | `rules/azure/monitor.yaml` |

This changes the assessment materially. The graph is not an unexercised
capability waiting for a first consumer — it has seven, spanning both
clouds, and the blocker fixed this phase was breaking all of them
whenever an IAM role was in scope.

Recorded here rather than silently edited: a reader who saw "0" would
have concluded the graph was speculative, which is the opposite of true.
