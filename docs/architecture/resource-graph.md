# The Resource Graph

## 1. What it is

A tenant-scoped, in-memory, directed graph of the cloud resources one
scan collected and the relationships between them. Built fresh every
scan, never persisted, never mutated after construction.

```
NormalizedResource[] ──▶ BuildResourceGraph ──▶ ResourceGraph ──▶ rule engine
```

## 2. Why ComplianceIQ needs it

Most CSPM findings are single-resource facts: *this bucket is public*,
*this key has no rotation*. Those are worth reporting and they are not
where the risk is.

The risk is in combinations:

> An EC2 instance with a public IP, in a subnet whose route table points
> at an internet gateway, protected by a security group allowing
> `0.0.0.0/0`, carrying an IAM role with `AdministratorAccess`.

Every one of those five facts is individually common and individually
low-priority. Together they are a full account compromise. No amount of
per-resource attribute checking finds it, because **the finding is not a
property of any single resource** — it is a property of the path between
them.

The graph is what makes that path expressible. Without it, a rule author
has only two options, both bad: flatten relationships into fake boolean
attributes on each resource (which the collectors would have to guess at
and keep in sync), or move the security logic into Python (which
abandons the declarative rule catalog).

## 3. Nodes

```python
GraphNode(
    resource_id, tenant_id, resource_type,   # identity
    provider, name, account_id, region,      # context
    source_collector, confidence,            # provenance
    kind,                                    # "collected" | "external"
)
```

`source_collector` and `confidence` are provenance, and they exist
because a graph is a set of *assertions*, not facts. When two collectors
disagree, or a relationship is disputed, "who said this and how sure were
they" is the only way to adjudicate.

### Collected vs external nodes

This distinction fixed a blocker and is the most important thing in the
model.

A collector may legitimately assert an edge to something that is **not a
collectible resource**: the internet, an AWS service principal, a foreign
AWS account. Before external nodes existed, such an edge failed
referential integrity and aborted the entire scan — so an IAM role with a
trust policy killed every scan it appeared in.

Dropping those edges instead would have been worse: *"this role is
assumable from the internet"* **is the finding**. The edge is the signal.

So external targets are materialized as nodes with `kind="external"` and
reduced confidence. Rules can then distinguish:

- *"points at something outside the scan"* → a finding
- *"points at a resource we failed to collect"* → a data gap

Conflating those produces confident findings about resources nobody
enumerated.

## 4. Edges

```python
GraphEdge(
    source_id, target_id, relationship_type,  # the assertion
    blocked,                                  # is it prevented in practice?
    evidence, source_collector, confidence,   # provenance
)
```

`evidence` is a small mapping of observed values, never prose. It answers
*why does the graph believe this?* — without it, a cross-resource finding
can state a conclusion but not show its reasoning, which is exactly what
a security engineer needs in order to trust or dismiss it.

`identity` is `(source, target, relationship_type)` — deliberately
excluding provenance, so two collectors observing the same relationship
assert **one** edge, not two.

`ResourceRelationship` also carries optional `evidence` and `confidence`
(added in STEP 1). A collector that knows *why* it asserted a
relationship previously had that knowledge discarded — `BuildResourceGraph`
synthesized a generic evidence dict. Collector evidence is now merged
**over** the generic provenance, so the specific reason wins.

## 5. Relationship types

Currently eight, a closed vocabulary:

```
contains · connects_to · protects · allows
assumes  · accesses     · attached_to · publicly_exposed
```

Closed on purpose. An open vocabulary produces `attached_to`,
`attachedTo` and `ATTACHED_TO` in the same graph, and no query finds them
all.

**Emitted today:** `attached_to`, `accesses`, `allows`, `assumes`,
`publicly_exposed`. Not yet emitted: `contains`, `connects_to`,
`protects` — they need the VPC/subnet/route-table collectors.

### `assumes` from a workload (STEP 1)

`Ec2Collector` emits `ec2_instance --ASSUMES--> iam_role`, resolved from
`iam:GetInstanceProfile`.

`ASSUMES` is **reused rather than a new type invented**: "this workload
can act as this identity" is exactly what it already means where
`IamRoleCollector` emits it, and it is already classified traversable. A
second type with the same meaning would split every query that reasons
about identity use.

**Why the API call is required.** `ec2:DescribeInstances` returns the
*instance profile* ARN, and a profile is a container that holds a role —
a different resource:

```
arn:aws:iam::111…:instance-profile/AppServerProfile   ← what EC2 gives us
arn:aws:iam::111…:role/app-server-role                ← what we need
```

The names usually match because tooling creates them as a pair. **That is
a convention, not a fact**, and deriving one from the other would
fabricate a privilege relationship. The edge is emitted only on a
successful `iam:GetInstanceProfile` response, and the test fixtures use
deliberately *mismatched* names so any name-based inference would fail.

**Under AccessDenied**: no edge, and
`instance_profile_role_arn` is `UNKNOWN` — not `None`. Every other
non-resolving outcome (`no_profile`, `not_found`, `malformed_arn`,
`no_role`, `cross_account`) is a determinate fact and records `None`. The
reason is preserved in `instance_profile_resolution`, so a rule can tell
"there is no role" from "we were not allowed to look".

### `accesses` from an identity (STEP 2)

`BuildResourceGraph` derives `iam_role|iam_user --ACCESSES--> <resource>`
from the identity's own policy documents. This is the **only derived
edge in the graph**, and it carries `source_collector:
"identity-access-derivation"` so a reader can tell a derivation from an
observation.

The derivation is a graph concern rather than a collector one because it
needs both sides: the grant (from IAM) and the candidate resources (from
every other collector). A collector sees only its own service.

**The central problem is explosion, not extraction.** An
`AdministratorAccess` role is allowed `*` on `*`. Drawing one edge per
resource it *could* reach turns one role into |resources| edges, every
downstream query into a scan of the whole estate, and every attack path
report into noise. So each grant's resource pattern is classified
**before** any edge is drawn (`domain/graph/identity_access.py`):

| Pattern | Class | Edges | Confidence |
|---|---|---|---|
| `arn:aws:s3:::acme-reports` | `EXACT` | one, to that resource | `high` |
| `arn:aws:s3:::acme-*` | `BROAD` | one per literal-prefix match | `medium` |
| `*`, `arn:aws:s3:::*` | `POTENTIAL` | **none** | — |

A `POTENTIAL` grant is dropped rather than recorded at low confidence.
"This identity can reach everything" is true and useful, but it is a
property of the *identity*, not a set of |resources| relationships, and
the graph is the wrong place to say it. The IAM rules report it instead.

Three semantics that a naive "does the ARN match" would get wrong:

- **Explicit `Deny` wins**, evaluated across all grants before any edge
  is emitted — matching IAM's own evaluation order rather than emitting
  an edge and hoping a consumer remembers to subtract it.
- **`NotResource` inverts the match.** An inverted grant never produces
  an edge, because the set it names is "everything except these" — a
  `POTENTIAL` set by definition.
- **A `Condition` downgrades confidence** one step rather than
  suppressing the edge. The access may well be real; we simply cannot
  evaluate `aws:SourceIp` against a request that has not happened.

The edge's evidence names `evidence_level`, `matched_pattern`,
`matched_actions` and `conditioned`, so a responder can see *why* the
edge exists and judge it. When policy documents are unreadable,
`access_grants` is `UNKNOWN` and no edges are derived — the same
distinction as STEP 1 between "no access" and "we were not allowed to
look".

## 6. Evidence and provenance

Every assertion in the graph can be traced:

| Question | Answered by |
|---|---|
| Which collector claimed this node exists? | `GraphNode.source_collector` |
| How sure are we it exists? | `GraphNode.confidence` |
| Did we actually enumerate it? | `GraphNode.kind` |
| Which collector claimed this relationship? | `GraphEdge.source_collector` |
| What did it observe? | `GraphEdge.evidence` |
| How sure is it? | `GraphEdge.confidence` |

## 7. AWS example

```
i-1234 (ec2_instance, acct 111…, us-east-1)
 ├── ATTACHED_TO ──▶ sg-abc (security_group)
 └── ASSUMES ──────▶ arn:…:role/app (iam_role)
                      └── PUBLICLY_EXPOSED ──▶ internet   [external]
```

## 8. Azure example

```
vm-web (azure_vm, sub 0000…, westeurope)
 ├── ATTACHED_TO ──▶ nsg-web (azure_nsg)
 └── ACCESSES ─────▶ mi-web (managed_identity)
```

## 9. Cross-resource rule example

The graph is reachable from YAML through the `relationship` node — no
Python required:

```yaml
condition:
  and:
    - field: has_public_ip
      operator: is_true
    - relationship: attached_to
      direction: outgoing
      target_type: security_group
      where:
        field: allows_unrestricted_ingress
        operator: is_true
```

Read as: *this instance is public **and** at least one attached security
group allows unrestricted ingress.* Neither half alone is a finding.

Relationship conditions are existence-quantified (OR) across neighbours.
A `relationship` node evaluated **without** a graph raises rather than
returning INDETERMINATE — that is a caller wiring bug, not a data gap,
and hiding it as a data gap is how a real defect ships quietly.

## 9b. Query layer

`domain/graph/queries.py` is the vocabulary security rules reason in. It
is deliberately **not** a general graph library: every function answers a
question a CSPM control actually asks, because a general traversal API
invites rules that are slow, non-deterministic, or both.

| Function | Question it answers |
|---|---|
| `edges_of` | What is this connected to at all? |
| `related_nodes` | What is one hop away, optionally filtered by type? |
| `find_resources` | Every resource of a type — index-backed, not a scan |
| `has_relationship` | Does this one specific edge exist? |
| `find_paths` | How can A reach B, within N hops? |
| `find_resources_exposed_to_internet` | What is directly reachable from outside? |
| `find_resources_using_identity` | Which workloads run as this role? |
| `find_resources_without_relationship` | What is **missing** a required relationship? |
| `graph_statistics` | Did the Azure half of this scan collect anything? |

Three properties hold across all of them.

**Index-backed.** Queries use the adjacency (`_out`, `_in`) and type
(`_by_type`) indexes maintained *inside* `add_node`/`add_edge`, exposed
through `outgoing_edges` / `incoming_edges` / `resource_ids_of_type`.
Relationship evaluation was O(R × N × E); it is now proportional to the
neighbourhood actually touched. The indexes are built at mutation time
rather than rebuilt on demand precisely so they cannot drift — a stale
index does not raise, it makes a cross-resource rule quietly stop firing,
which is indistinguishable from the rule finding nothing. Tests assert
each index against an independent linear scan for exactly that reason.

**Deterministic ordering.** Every function that returns a collection
sorts it. Insertion order reflects collector scheduling, which is not a
property of the customer's infrastructure, and a finding whose evidence
lists resources in a different order on every scan is a finding nobody
can diff.

**Absence is expressible.** The DSL's `relationship` node is
existence-quantified (OR across neighbours), so *"critical resource with
**no** private endpoint"* and *"resource with **no** diagnostic
settings"* were previously inexpressible.
`find_resources_without_relationship` closes that gap — with a caveat
serious enough to restate here: **absence in the graph means "not
observed", not "does not exist"**. If a collector lacked permission to
enumerate private endpoints, every resource looks like it has none and
the query reports the whole estate as non-compliant. A rule built on it
must gate on evidence that the relevant collector ran, exactly as
finding-lifecycle resolution gates on `covered_resources`.

### Two hazards the query layer refuses to paper over

`find_paths` excludes `blocked` edges by default, and
`find_resources_exposed_to_internet` does the same: a relationship that
exists structurally but is prevented in practice is not a walkable path,
and reporting it as one is a false positive on the highest-severity
signal a CSPM emits. `max_depth` defaults to 4 and is not a knob to raise
casually — path count grows combinatorially, and an unbounded search over
a large tenant's graph is a denial of service against our own scanner.

`find_resources_using_identity` carries a caller contract rather than a
guess. `ASSUMES` is only ever emitted toward an identity, but `ACCESSES`
serves double duty — a VM using a managed identity and a role reading a
bucket are the same edge type — so handing the function a *data* resource
returns its readers, which is true about the graph and misleading as an
answer. The domain does **not** hardcode a list of "identity resource
types" to prevent that: only `iam_role` and `iam_user` exist today, so
such a list would invent a vocabulary ahead of the Entra ID collectors
that would produce it, and would silently exclude every identity added
later. Instead an optional `identity_types` argument lets a caller that
knows the vocabulary opt into the guard.

## 9c. Absence: the `no_relationship` node

```yaml
condition:
  and:
    - field: public_network_access
      operator: is_true
    - no_relationship: connects_to
      direction: outgoing
      target_type: private_endpoint
```

Read as: *this database is publicly reachable **and** has no private
endpoint.* Neither half is a finding alone.

A **separate node**, not a flag on `relationship`. Seven shipped rules
depend on the existence-quantified truth table, and inverting it under an
option would flip all of them.

### The coverage guard, and why it is mandatory

Absence in the graph means "not observed", not "does not exist". If the
private-endpoint collector lacked permission, every database looks
unprotected — and the rule reports the entire estate as non-compliant.

That is the mirror image of the failure this codebase refuses everywhere
else. Elsewhere, an unknown silently becoming `False` **hides** a
violation. Here, an unknown silently becoming `True` **invents** one, at
estate scale. Both hide the truth; the second also destroys trust in the
report, which is worse — a CSPM nobody believes is a CSPM nobody reads.

So `requires_collected` names the resource type whose collection makes
absence meaningful. If the graph holds no node of that type **at all**,
the condition is `INDETERMINATE`, never `MATCHED`. It defaults to
`target_type` (the same answer in almost every rule) and is rejected when
neither is present: absence over an unconstrained relationship has no
observable coverage signal, and guessing one would defeat the guard.

The guard is checked **before** edges are counted, so an uncollected type
cannot produce a confident `NOT_MATCHED` either.

| Situation | Result |
|---|---|
| Coverage guard unsatisfied | `INDETERMINATE` |
| No matching edge | `MATCHED` |
| A matching edge, no `where` | `NOT_MATCHED` |
| A matching edge, with `where` | `NOT(exists neighbour satisfying where)` |

Routing the `where` case through Kleene `NOT` keeps uncertainty
propagating: if one neighbour is unreadable and none matched, the answer
is *we cannot tell*, not *none*. Without a `where` the question is purely
structural, so an unreadable neighbour still yields a determinate
`NOT_MATCHED` — the edge exists regardless of whether its attributes do.

## 9d. Findings that explain themselves

Before this, a cross-resource finding read *"EC2 instance attached to an
open security group"* — without naming **which** security group. The rule
traversed the edge, decided, and discarded the traversal, throwing away
the one fact a responder needs to act.

`RelationshipTrace` (`domain/rules/trace.py`) is an optional sink the
evaluator writes to while traversing. Relationship and absence nodes
record each neighbour they examined and what it contributed. Three
`Finding` fields carry the result:

| Field | Contents |
|---|---|
| `related_resources` | Neighbours that satisfied a relationship condition |
| `indeterminate_resources` | Neighbours whose contribution could not be determined |
| `graph_context` | The subject's neighbourhood, only when the rule traversed |

### Four decisions worth the words

**A sink, not a richer return type.** `evaluate_condition` returns an
`EvaluationResult` and recurses from a dozen places. Threading a
`(result, trace)` pair through every branch would touch every node type
to serve two of them. The sink is additive: callers that pass nothing get
byte-identical behaviour, asserted by a test.

**Only what the rule traversed.** `related_resources` comes from the
trace, never from the resource's whole neighbourhood. A finding that
names resources it did not consider is *worse* than one that names none,
because someone will go investigate them.

**Indeterminate stays separate.** A neighbour we could not read is not a
confirmed relationship. Collapsing the two columns would undo, at the
reporting layer, the three-valued discipline the evaluator maintains.

**Absence observations are excluded from `related_resources`.** Under
`no_relationship`, a satisfying neighbour is evidence the control was
**met**. Listing it beside a violation would name a resource as
implicated in a finding it in fact prevented.

`graph_context` is attached only when the rule actually traversed, so
single-resource findings do not each carry a neighbourhood blob.

### Persisted, not derived

Migration `0003` adds all three to `finding_snapshots`. The graph is
rebuilt per scan and never stored, so a finding fetched tomorrow cannot
recompute which security group it matched — the graph that knew is gone.
Context that lives only in the process that produced the finding is the
same as no context at all.

The array columns are `NOT NULL DEFAULT '[]'`: existing rows backfill to
"related to nothing", which is the truthful value for every finding
written before traversal was recorded. The server defaults are kept
rather than dropped after backfill, because during a rolling deploy an
older process still inserts rows that never mention these columns.

### Exposed, not only persisted (STEP 6)

Persisting context that never reaches a client is the same as not having
it. All three fields — plus `related_attack_path_ids` — now appear on
`FindingResource`.

One split matters: **`graph_context` is returned by the single-finding
endpoint only.** A resource's edge count is unbounded — one security
group can front hundreds of instances — so carrying it in a 100-item
page would make response size a function of graph shape rather than page
size. The bounded id lists stay in the page, because a dashboard needs to
know *which rows sit on an attack path* before the user clicks anything.

`null` in a page therefore means *not requested*, never *no context*.
The field's own description says so, so a client generated from the spec
learns it without reading our source.

## 10. Attack-path analysis

**Implemented.** `AnalyzeAttackPaths` is no longer a placeholder — it
consumes this graph and produces scored, explainable `AttackPath`
objects, wired into the real scan pipeline. See
[attack-path-analysis.md](attack-path-analysis.md).

This changes what the graph is responsible for. It is no longer only a
substrate for cross-resource *rules*; it is the evidence base for
composite risk, and two of its properties became load bearing:

- **`GraphEdge.blocked`** now gates traversal. An edge marked blocked is
  excluded from every path, and a path containing one scores 0.
- **`confidence` on nodes and edges** now propagates into risk. A path is
  only as trustworthy as its weakest link, so `internet` being an
  external `medium`-confidence node caps every internet-origin path at
  `medium`.

The decision that matters most for graph consumers: **connectivity is not
reachability**. `ATTACHED_TO` and `ALLOWS` are *not* traversable — an
attacker does not travel into a security group. A future collector adding
a relationship type must decide explicitly which set it belongs to.

## 11. Validation

`domain/graph/validation.py` is **diagnostic, not fatal** — a deliberate
split:

- `add_node` / `add_edge` **raise** → "this graph is not constructible"
- `validate_graph` **reports** → "this graph is constructible but suspicious"

The second class is the common one in production and the one nobody
notices without a report: a cross-resource rule that quietly stops firing
because an edge was dropped looks identical to a rule that found nothing.

| Code | Severity | Meaning |
|---|---|---|
| `dangling_edge` | ERROR | Edge references a missing node |
| `impossible_relationship` | ERROR | e.g. something `ASSUMES` the internet |
| `duplicate_edge` | WARNING | Often a collector emitting per page |
| `self_loop` | WARNING | Resource relates to itself |
| `orphan_external_node` | WARNING | Its creating relationship was lost |
| `cross_account_edge` | INFO | Legitimate and worth surfacing |

`cross_account_edge` is INFO, not ERROR, on purpose: a role trusting a
partner account is an intended pattern. Flagging it as corruption would
train people to ignore the report.

## 12. Determinism

Identical cloud input must produce an equivalent graph.
`graph_fingerprint()` makes that assertable:

- nodes and edges are **sorted** — insertion order reflects collector
  scheduling, which is not a property of the infrastructure
- **provenance is excluded** — two scans learning the same topology from
  different collectors describe the same infrastructure

So a changed fingerprint means the *topology* changed, which is signal,
rather than that a collector ran in a different order, which is noise.

## 13. UNKNOWN behaviour

The graph itself carries no `UNKNOWN` values — it models structure, and a
relationship either was or was not observed.

Uncertainty is expressed two ways instead:

1. **`confidence`** on nodes and edges. External nodes are `medium`: we
   did not enumerate them, we only know something pointed at them.
2. **Absence.** A missing edge means "not observed", which is not the
   same as "does not exist". A rule that treats a missing edge as proof
   of absence will under-report whenever a collector lacked permission.

Resource *attributes* keep full `UNKNOWN` semantics
(`domain/shared/unknown.py`), and a relationship condition whose `where`
clause hits an `UNKNOWN` attribute yields INDETERMINATE, propagating
correctly through the Kleene combinators.

## 14. Known limitations

- Only 5 of 8 relationship types are emitted.
- `blocked` is never set to `True` by any collector — determining whether
  a security group rule actually blocks a path requires evaluation that
  does not exist yet. `find_paths` and the exposure query both honour the
  flag, so the *plumbing* is correct and the *input* is always `False`.
- `ACCESSES` derivation is **AWS-only** and reads **identity-based
  policies only**. A bucket policy granting access to a principal
  produces no edge, so a path that exists only through a resource-based
  policy is a false negative. Azure role assignments have no equivalent
  producer at all.
- A `POTENTIAL` grant (`*`) produces **no edges**. The trade is
  deliberate — see §5 — but it means the graph cannot answer "what can
  this administrator reach", only "what did we prove it can reach".
- Cross-account grants produce no edge, because the target resource is
  not in the graph. Correct, and still a gap: a real cross-account path
  is invisible.
- No rule consumes `find_paths` yet. `AnalyzeAttackPaths` does — it is
  the only caller — so multi-hop traversal is exercised in production,
  but the rule DSL still reasons one hop at a time.
- `no_relationship` exists and is tested, but **no shipped rule uses
  it**. The controls it unlocks (private endpoints, diagnostic settings)
  need collectors that are not written, and a rule targeting an
  uncollected type would sit at `INDETERMINATE` forever — fake coverage.
- The rest of the query layer is not reachable from YAML.
  `find_paths`, `find_resources_exposed_to_internet` and
  `find_resources_using_identity` have no DSL surface; a rule cannot call
  them.
- `find_resources_using_identity` cannot distinguish an identity from a
  data resource without the caller supplying `identity_types`.
- `relationship_path` is **not** a Finding field. `find_paths` exists but
  no rule produces a path, so a path column would have no writer —
  decoration, not capability. `related_resources` names the neighbours a
  rule matched; it does not claim they form a chain.
- The API does not expose the new Finding fields. They are persisted and
  readable from the domain, but no response schema surfaces them yet.
- No cross-scan graph diffing.
- The graph is rebuilt per scan and not cached.
- No benchmark exists. The indexes make the complexity argument sound,
  but the 100/500/1000-resource measurement has not been run.
