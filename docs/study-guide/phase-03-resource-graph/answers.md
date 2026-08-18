# Phase 3 — Answers

**1. Why can't per-resource rules detect `Internet → Workload → Identity → Sensitive Resource`?**

Because **no single resource contains the finding**. Each rule sees one
resource and its own attributes:

- The instance rule sees "has a public IP" — common, medium.
- The SG rule sees "allows 0.0.0.0/0" — common, medium.
- The role rule sees "has AdministratorAccess" — common, medium.
- The bucket rule sees "contains data" — not a finding at all.

Four medium findings. The *compromise* is the composition, and
composition is not a property of any member.

Formally: per-resource rules evaluate a predicate over a single node.
The attack path is a predicate over a **path** in a graph. You cannot
express a path predicate in a language whose universe is one node — no
matter how many rules you add.

The only per-resource workarounds are flattening relationships into fake
boolean attributes (collectors must guess and keep them in sync) or
moving the logic into Python (abandoning the declarative catalog).

**2. A trust policy names an AWS service principal — what node?**

`IamRoleCollector._relationships()` emits
`ASSUMES → aws-service:ec2.amazonaws.com`.

`_external_type()` sees the `aws-service:` prefix and classifies it as
resource_type `aws_service`, with **`kind="external"`** and reduced
(`medium`) confidence.

It is external because an AWS service principal is not a collectible
resource in the customer's account — there is no API that enumerates it.

**3. Why not create the missing node as a normal collected node?**

Because it would be a **lie about provenance**. `kind="collected"` means
"we enumerated this resource and its attributes are real". We did not
enumerate the internet.

The practical damage: rules and attack path analysis could no longer
distinguish *"this points outside the scan"* (a finding) from *"this
points at a resource we failed to collect"* (a data gap). Conflating them
produces confident findings about resources nobody looked at.

It would also corrupt confidence propagation — an external node's
`medium` confidence is what correctly caps every internet-origin attack
path in Phase 8.

**4. What did the 21 collector tests fail to exercise?**

**The seam.** Every test asserted on `resource.relationships` — the
collector's *output object* — and none of them ever passed that output to
`BuildResourceGraph`.

So they proved: "the collector emits the relationships we expect."
They did not prove: "those relationships can be assembled into a graph."

Both components were individually correct. The defect lived only in their
interaction, and no test crossed that boundary. The fix added tests that
build a real graph from real collector output.

**5. Two collectors report `sg-1 ALLOWS sg-2` — how many edges?**

**One.** The deciding field is `GraphEdge.identity`:

```python
(self.source_id, self.target_id, self.relationship_type)
```

Provenance (`source_collector`, `confidence`, `evidence`) is deliberately
**excluded**, so two independent observations of the same relationship are
the *same* edge, not two. `BuildResourceGraph` deduplicates on
`edge.identity` via a `seen` set.

If provenance were included you would get duplicate edges, doubled path
counts in traversal, and a fingerprint that changed whenever a second
collector was enabled.

**6. Why is `cross_account_edge` INFO rather than ERROR?**

Because **a role trusting a partner account is an intended pattern**, not
corruption. Cross-account access is how AWS organizations, vendor
integrations and CI/CD pipelines legitimately work.

Flagging it as ERROR would produce constant noise on healthy
infrastructure — and the real cost is behavioural: it trains people to
ignore the validation report entirely, so the *genuine* ERRORs
(`dangling_edge`, `impossible_relationship`) get ignored too.

It is still surfaced as INFO because it is worth *seeing* — you want to
know which accounts your roles trust.

**7. Different collector order — same fingerprint or different?**

**Same.**

Two mechanisms guarantee it: `graph_fingerprint()` **sorts** nodes and
edges before hashing, so insertion order cannot leak; and it **excludes
provenance**, so even if a different collector made the observation, the
topology hash is unchanged.

That is the design intent stated explicitly: a changed fingerprint means
the *topology* changed (signal), not that a collector ran in a different
order (noise).

**8. Adding `routes_to` — what must you update in `classification.py`?**

You must place it in **exactly one** of two frozensets:

- `_TRAVERSABLE_RELATIONSHIPS` — an attacker can move along it
- `_INFORMATIONAL_RELATIONSHIPS` — it describes configuration

**If you forget:** `is_traversable()` returns `False` (it checks
membership in the traversable set), so attack paths silently never route
through your new edge. No error, no warning — the capability just does not
appear.

The informational set is written out explicitly, rather than defined as
"everything not traversable", *precisely* to make this a conscious
decision. But the codebase does not currently have a test asserting every
enum member appears in one of the two sets.

⚠️ **That would be a worthwhile test to add** — see `next-work.md`.

**9. "Bucket has no logging" — can the graph answer it? What's the danger?**

The **graph** cannot: logging is an *attribute* (`logging_enabled`), not a
relationship, and nodes carry no attributes. A per-resource rule handles
it directly.

But the question points at a real hazard for the graph's *absence*
queries. If the control were "bucket with **no** logging destination
relationship", you would use `no_relationship` /
`find_resources_without_relationship`, and there the danger is severe:

> **Absence in the graph means "not observed", not "does not exist".**

If a collector lacked permission to enumerate logging destinations, every
bucket would look like it has none, and the rule would report the **entire
estate** as non-compliant — a mass false positive.

That is why `no_relationship` requires `requires_collected`: if the graph
contains no node of that type at all, it returns `INDETERMINATE` rather
than `MATCHED`. Covered fully in Phase 4.
