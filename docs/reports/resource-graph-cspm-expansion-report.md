# Resource Graph CSPM Expansion — Implementation Report

> **Verification policy.** Every number below was produced by executing a
> command in this repository. Work not done is listed as not done, in its
> own section, with the reason. The previous phase's report shipped a
> wrong count derived by inspection rather than query; that mistake is
> what this policy exists to prevent, and §8 records how it was found.

Companion documents:
[audit](../audit/resource-graph-cspm-expansion-audit.md) ·
[architecture](../architecture/resource-graph.md)

---

## 1. Headline

The audit found the graph's real gap was not breadth — it was that
**nothing could ask the graph a question**.

`ResourceGraph` exposed five methods. `neighbors()` required an exact
relationship type, one hop, one direction. Every other question a
cross-resource rule asks had to be answered by scanning `graph.edges`
linearly, making relationship evaluation O(R × N × E). And absence — *"no
private endpoint"*, *"no diagnostic settings"* — was not expressible at
all, because the DSL's `relationship` node is existence-quantified.

So this phase did **not** add collectors. It made the graph queryable,
made absence expressible, and made findings explain themselves. Those
three raise the value of the 68 rules that already ship; a fourteenth
collector would not have.

---

## 2. The requested numbers

```
AWS collectors:            7   (unchanged)
Azure collectors:          5   (unchanged)

AWS rules:                41   (unchanged)
Azure rules:              27   (unchanged)
Cross-resource rules:      7   (unchanged — pre-existing; see §8)

Operators:                32   (unchanged: 24 comparison + 2 presence
                                + 3 quantifier + 3 temporal)
Condition node types:      6   (was 5 — `no_relationship` is a NODE,
                                not an operator)
Relationship types:        8 defined / 5 emitted   (unchanged)

Graph query primitives:   11   (was 0)
Graph indexes:             3   (adjacency out, adjacency in, by type)
Finding context fields:    3   (was 0)
Alembic revisions:         3   (0003 added)

Tests:                  1356 collected
Passed:                 1296
Skipped:                  60   (AWS/Azure integration; need real credentials)
Failed:                    0

ruff:                   clean
mypy:                   clean, 171 source files
```

Baseline entering this phase was 1185 passed / 60 skipped. Net **+111
tests**, zero regressions, zero pre-existing tests weakened.

---

## 3. What was delivered

### 3.1 Graph query layer and indexes (§1.6, §15)

`domain/graph/queries.py` — 11 primitives: `edges_of`, `related_nodes`,
`find_resources`, `has_relationship`, `find_paths`,
`find_resources_exposed_to_internet`, `find_resources_using_identity`,
`find_resources_without_relationship`, `internet_node_ids`,
`graph_statistics`, `iter_edges`.

Deliberately **not** a general graph library. §1.6 says "implement only
the primitives really needed by the CSPM", and that constraint is load
bearing: a general traversal API invites rules that are slow,
non-deterministic, or both.

Three adjacency/type indexes are maintained **inside**
`add_node`/`add_edge` and exposed through `outgoing_edges`,
`incoming_edges`, `resource_ids_of_type`. Built at mutation time rather
than rebuilt on demand for one reason: a stale index does not raise, it
makes a cross-resource rule quietly stop firing — indistinguishable from
the rule finding nothing. The audit named this as the phase's top
regression risk, so the tests assert each index against an **independent
linear scan** rather than against hand-written expectations.

`ResourceGraph.neighbors()` was migrated onto the indexes. Its observable
contract is unchanged, pinned by tests comparing it against a linear
scan.

### 3.2 Absence-quantified conditions (§2.1)

A new `no_relationship` DSL node, **never** a flag on `relationship` —
seven shipped rules depend on that node's existence-quantified truth
table, and inverting it under an option would flip all of them.

The interesting part is not the edge counting; it is the coverage guard.

Absence in the graph means "not observed", not "does not exist". If the
private-endpoint collector lacked permission, every database looks
unprotected and the rule reports the whole estate as non-compliant. That
is the **mirror image** of the failure this codebase refuses everywhere
else: elsewhere an unknown silently becoming `False` *hides* a violation;
here an unknown silently becoming `True` *invents* one, at estate scale.
The second is worse, because a CSPM nobody believes is a CSPM nobody
reads.

So `requires_collected` names the resource type whose collection makes
absence meaningful, defaults to `target_type`, and is rejected when
neither is present. An estate-wide zero of that type yields
`INDETERMINATE`. The guard is checked *before* edges are counted, so an
uncollected type cannot produce a confident `NOT_MATCHED` either.

### 3.3 Findings that explain themselves (§3)

Before: *"EC2 instance attached to an open security group"* — without
naming **which** security group. The rule walked the edge, decided, and
discarded the traversal.

`RelationshipTrace` is an optional sink the evaluator writes to while
traversing. Three additive `Finding` fields carry the result:
`related_resources`, `indeterminate_resources`, `graph_context`.

Four decisions worth stating:

- **A sink, not a richer return type.** Threading `(result, trace)`
  through every branch would touch every node type to serve two of them.
  A test asserts the return value is identical with and without a trace.
- **Only what the rule traversed** — never the whole neighbourhood. A
  finding that names resources it did not consider is *worse* than one
  that names none, because someone will go investigate them.
- **Indeterminate stays a separate field.** Collapsing it into
  `related_resources` would undo, at the reporting layer, the
  three-valued discipline the evaluator maintains.
- **Absence observations are excluded.** Under `no_relationship` a
  satisfying neighbour is evidence the control was *met*; listing it
  beside a violation would name a resource as implicated in a finding it
  in fact prevented.

Persisted via migration `0003`, not derived on read: the graph is rebuilt
per scan and never stored, so a finding fetched tomorrow cannot recompute
which security group it matched. Context living only in the process that
produced the finding is the same as no context.

### 3.4 Benchmark (§15)

`scripts/benchmark_graph.py`, measured on this machine:

| resources | nodes | edges | build ms | indexed ms | scan ms | speedup |
|---:|---:|---:|---:|---:|---:|---:|
| 99 | 99 | 98 | 0.7 | 0.5 | 0.8 | 1.5× |
| 499 | 499 | 498 | 4.0 | 2.6 | 20.1 | 7.7× |
| 999 | 999 | 998 | 7.4 | 5.1 | 88.5 | 17.5× |

The shape matters more than the ratio. Across a 10× growth in resources,
the linear scan goes 0.8 → 88.5 ms (≈110×, quadratic as predicted) while
the indexed path goes 0.5 → 5.1 ms (≈10×, linear).

The comparison is understated on purpose: the `indexed` column runs
**full three-valued rule evaluation**, while `scan` does edge lookup
only. The indexed path does strictly more work and still wins by 17×.

**What this is not:** a production performance claim. It is in-memory,
synthetic, no cloud API, no database, no network. It answers exactly one
question — did the indexes change the complexity class — and nothing
else.

---

## 4. What was NOT done — explicitly

### No collectors added — 0 of 19

**AWS:** VPC, Subnet, Network ACL, Route Table, RDS, EKS, ECR,
CloudWatch, AWS Config.
**Azure:** Entra ID (users, groups, service principals, managed
identities), RBAC, Azure SQL, AKS, PostgreSQL, Firewall, Private
Endpoints, Diagnostic Settings.

Coverage remains **12 of 26** target services.

### No new rules — catalog unchanged at 41 AWS / 27 Azure

Including **no rule using `no_relationship`**, despite this phase adding
it. The controls it unlocks (private endpoints, diagnostic settings)
target resource types no collector produces; a rule over an uncollected
type sits at `INDETERMINATE` forever. That is fake coverage, and §1's
rules 9–11 forbid it.

### Also not done

- **Relationship vocabulary not extended.** `contains`, `connects_to`,
  `protects` remain defined-but-unemitted; adding more enum values with
  no collector emitting them is decoration.
- **No attack-path discovery.** `find_paths` exists and is tested, but
  **nothing calls it**. It is substrate, not capability. No scoring model
  was invented.
- **`relationship_path` was NOT added to `Finding`** — `find_paths` has
  no producer, so the column would have no writer.
- **No Terraform fixtures added** (§14).
- **No framework catalog, no new control IDs** (§2). The 16-of-27
  unresolved mappings from the previous phase are unchanged; resolving
  them requires checking published benchmark text.
- **The query layer has no DSL surface.** Only `no_relationship` reached
  YAML; `find_paths`, the exposure query and the identity query cannot be
  called from a rule.
- **The API does not expose the new Finding fields.** They are persisted
  and readable from the domain; no response schema surfaces them.
- **`blocked` is still never set `True` by any collector.** `find_paths`
  and the exposure query both honour the flag, so the plumbing is correct
  and the input is always `False`.
- Six of seven AWS collectors and all five Azure collectors still lack
  the resilience layer.

### Not verified

- **No collector was run against a real AWS or Azure API.** All collector
  tests use fakes modelled on documented response shapes. The 60 skipped
  tests are exactly the ones that would need live credentials.
- No load testing beyond §3.4, which is synthetic and in-process.

---

## 5. Backward compatibility

| Check | Result |
|---|---|
| Existing YAML rules still load | 68/68 |
| Public interfaces broken | none |
| Pre-existing tests weakened or rewritten | **none** |
| Full suite | 1296 passed, 60 skipped, 0 failed |
| ruff | clean |
| mypy | clean, 171 source files |

Every addition is additive by construction: new optional parameters
defaulting to `None`, new `Finding` fields defaulting to empty, a new DSL
node beside the existing one, new columns with server defaults.

A dedicated test class (`TestExistingRelationshipNodeIsUnchanged`) pins
the existence-quantified truth table the seven live rules depend on.

---

## 6. Two defects found by tests, not by review

**The exposure query's identity assumption.** A test asking about an
unused identity returned a result, revealing that
`find_resources_using_identity` cannot distinguish an identity from a
data resource: `ASSUMES` is only ever emitted toward an identity, but
`ACCESSES` serves double duty — a VM using a managed identity and a role
reading a bucket are the same edge type. Rather than hardcode a list of
"identity resource types" (only `iam_role` and `iam_user` exist today, so
the list would invent a vocabulary ahead of the Entra ID collectors that
would produce it, and silently exclude every identity added later), an
optional `identity_types` argument lets a caller that knows the
vocabulary opt into the guard. The hazard is pinned by a test that
asserts the unguarded behaviour deliberately.

**Migration/model drift.** The schema-parity test rejected migration
`0003` because it declared a `server_default` the ORM model did not. The
default is real and deliberate — a `NOT NULL` column cannot be added to a
populated table without one, and during a rolling deploy an older process
still inserts rows that never mention the new columns — so the fix was to
declare it in both places rather than drop it.

---

## 7. Security

No new exposure. Graph evidence and context contain resource identifiers,
resource types and relationship types only — no attribute values. The
persistence mapper still routes `graph_context` through `redact()`
anyway, because "this payload cannot contain a secret" is an assumption a
future collector change can silently invalidate.

`UNKNOWN` semantics are preserved throughout: no unknown was converted to
`false`, and the one place where an unknown could have become a
*violation* (absence) is guarded, which is the point of §3.2.

---

## 8. Correction carried forward

The previous phase's report stated **"Cross-resource rules: 0"**. It is
**7**, verified by walking every condition tree in the catalog for a
`relationship` node. The error was inferring from "no rule *I* wrote uses
it" instead of querying.

It is repeated here rather than quietly dropped because it changes the
reading of this phase's work: the graph is not a speculative capability
awaiting its first consumer. It has seven, spanning both clouds — and the
blocker fixed last phase was breaking all seven whenever an IAM role was
in scope. Everything this phase added serves rules that already ship.

---

## 9. Honest state

This is **not production ready**, and 1296 passing tests do not make it
so.

The graph is now queryable, efficient, absence-aware, and its findings
explain themselves. What it still lacks is **breadth**: 12 of 26 services
collected, 5 of 8 relationship types emitted, and the three missing types
(`contains`, `connects_to`, `protects`) are precisely the network
topology edges that would make internet-reachability rules real.

### Recommended next order

1. **VPC + Subnet + Route Table collectors** — they emit the three
   missing relationship types and make internet reachability real.
2. **The first `no_relationship` rule, end to end** — Private Endpoints
   or Diagnostic Settings collector first, then the rule, so the coverage
   guard has something to guard.
3. **Migrate the eleven collectors that still lack the resilience
   layer.**
4. **Surface `related_resources` in the API**, so the context this phase
   captured reaches a human.
5. Then attack-path discovery, once topology edges exist and `blocked`
   has a producer.
