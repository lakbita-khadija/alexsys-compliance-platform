# Phase 7 — Answers

**1. Why is `max_depth` a safety bound? What breaks at 20?**

Because **path count grows combinatorially with depth**. In a graph where
each node has average out-degree *d*, the number of simple paths to
explore at depth *k* is roughly *d^k*. At d=5, depth 4 is ~625 walks; depth
20 is ~10¹⁴.

`find_paths` is called **per (source, target) pair** inside
`_data_flows_into_exposed_stores`, which loops over every node against
every exposed store. So the blow-up multiplies by N².

Concretely at depth 20: the scan never finishes, the worker holds memory
for the accumulating results list, and the tenant's scan appears hung.
That is a **denial of service against our own scanner**, triggerable by a
customer simply having a well-connected estate.

Four hops also covers every chain the current relationship vocabulary can
express, so raising it buys nothing today.

**2. Blocked-edge handling with no producer — dead code?**

**Not dead — unexercised in production, and worth keeping.**

Three arguments:

- The **domain invariant already depends on it**: `AttackPath` raises if
  any edge is blocked and `risk_score != 0`. If `find_paths` returned
  blocked paths, the analyzer would construct paths the aggregate rejects.
- It is **tested** (`test_blocked_edges_are_excluded_by_default`,
  `test_a_blocked_edge_scores_zero`), so it is verified behaviour, not
  hopeful code.
- The alternative — adding blocked-handling later, once a collector sets
  it — means retrofitting the semantics through traversal, scoring and the
  aggregate simultaneously, at the moment when real data is finally
  flowing. That is the worst possible time.

The honest framing used throughout the docs: *the plumbing is correct and
the input is always `False`.*

**3. Why compare indexes against a linear scan?**

Because hand-written expectations test **the test author's model**, not
the invariant.

The real invariant is: *the index agrees with the authoritative
collection*. `graph.edges` and `graph.nodes` are authoritative; `_out`,
`_in`, `_by_type` are derived accounting. Comparing derived against
authoritative tests exactly that relationship.

It is also robust: if someone changes the fixture, adds an edge, or
changes insertion order, the test still checks the right thing. Hardcoded
expectations would need updating and could be updated *wrongly* — masking
the drift they exist to catch.

And the failure mode being guarded is silent: a stale index does not
raise. The rule just quietly stops firing, indistinguishable from finding
nothing.

**4. 500 buckets, no `private_endpoint` nodes — is 500 right?**

**Yes — the function is correct, and the answer is dangerous.**

It reports graph structure faithfully: no bucket has a `CONNECTS_TO` edge,
so all 500 lack the relationship. That is a true statement.

But it is indistinguishable from the case where the private-endpoint
collector was **denied permission**. Structurally identical graphs, wildly
different meanings — and acting on the wrong one reports the entire estate
as non-compliant.

**What the caller must do:** gate on evidence the collector ran. That is
precisely `no_relationship`'s `requires_collected`: if the graph holds no
node of the required type *at all*, return `INDETERMINATE` rather than
`MATCHED`. Estate-wide zero is far more likely to mean "the collector
didn't run" than "nobody has one", and erring toward INDETERMINATE costs a
data-gap report while erring toward MATCHED costs a mass false positive.

The function's own docstring says it: *it reports graph structure; it
cannot know why an edge is missing.*

**5. `find_resources_using_identity("bucket-data")` returns a role — bug?**

**Contract, not bug** — and it is pinned by a deliberate test
(`test_a_data_resource_returns_its_readers_which_is_the_caller_hazard`).

The cause: `role/app --ACCESSES--> bucket-data`. `ACCESSES` serves double
duty — a VM using a managed identity and a role reading a bucket are the
same edge type. So asking about the bucket returns its readers: true about
the graph, misleading as an answer to "who uses this identity".

**The guard** is the optional `identity_types` parameter:

```python
find_resources_using_identity(graph, rid, identity_types=["iam_role", "iam_user"])
```

Passing a non-identity target then yields `()` instead of a plausible
wrong answer.

**Why it isn't the default:** only `iam_role` and `iam_user` exist today.
`managed_identity` and `service_principal` need Entra ID collectors that
are not written. A hardcoded default list would invent a vocabulary ahead
of the collectors that produce it — and would then *silently exclude*
every identity type added later, which is a worse failure than the one it
prevents.

**6. `internet_node_ids` checks two things — what and why?**

```python
ids = set(graph.resource_ids_of_type("internet"))
if graph.has_node(INTERNET):
    ids.add(INTERNET)
```

1. Nodes whose **`resource_type` is `"internet"`** — the classification
   `BuildResourceGraph._external_type()` applies.
2. The conventional **id `"internet"`** that collectors emit.

Two sources because they come from two different layers. The *id* is a
collector convention (`iam_roles.py` hardcodes `ResourceId("internet")`);
the *type* is a builder classification. They usually coincide — but a
query trusting only one would silently miss exposure if either convention
changed independently.

Missing exposure is the highest-cost failure this query can have, so it
casts a deliberately wide net. Tested by
`test_internet_node_ids_covers_both_conventions`.

**7. Which primitives does the analyzer use?**

**Uses three:**

- `edges_of` — incoming `PUBLICLY_EXPOSED` edges to internet nodes;
  outgoing `ATTACHED_TO` for the workload scenario
- `find_paths` — the composite data-flow scenario
- `internet_node_ids` — locating internet nodes

**Does not use:**

- `find_resources_exposed_to_internet` — it finds only resources with a
  *graph edge* to the internet, and the analyzer needs
  **attribute**-driven exposure too (public buckets have no edge). The
  analyzer's own `_exposed_sensitive_data` reads
  `public_exposure_evidence()` from the resource attributes instead.
- `find_resources_using_identity` — the workload→identity edge does not
  exist, so there is nothing to ask.
- `find_resources_without_relationship` — no absence-based attack path
  scenario ships.
- `related_nodes`, `has_relationship`, `find_resources`,
  `graph_statistics`, `iter_edges` — not needed by the four scenarios.

That asymmetry is honest: the query layer was built to serve rules *and*
attack paths, and attack paths currently exercise three of eleven.
