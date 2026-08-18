# Phase 8 — Answers

**1. Why is a fabricated attack path worse than a missing one?**

A missing path costs one item on a backlog. A fabricated path costs
**trust**, and trust is the product.

Concretely: a `CRITICAL` attack path arrives at 2am. An on-call engineer
is paged, spends an hour tracing a chain, and discovers the workload→role
edge does not exist — ComplianceIQ inferred it from a naming convention.

Two things now happen, and the second is worse:
- That hour is gone.
- **Every future critical alert is discounted.** The next real one gets
  triaged tomorrow instead of tonight.

A CSPM nobody believes is a CSPM nobody reads. Which is why
`test_no_workload_to_identity_path_is_invented` exists.

**2. `ATTACHED_TO` is non-traversable, yet scenario 3 uses it — contradiction?**

No — two different roles for the same edge.

**Traversal** asks "can an attacker *move* along this?" An attacker does
not travel *into* a security group; the SG is a gate, not a destination.
So `is_traversable(ATTACHED_TO)` is `False`, and `find_paths` never routes
through one.

**Evidence** asks "what fact supports this claim?" The edge is how we know
*which* group admits the internet — actionable information a responder
needs.

Scenario 3 walks the edge to identify the control, then reads that
control's attributes. It never treats the edge as a step. The path's nodes
are `(control, workload)` and the narrative is "the internet reaches this
workload *through* that group."

This is why the docs call it a **reachability witness**.

**3. All four resources present — why no path?**

Because **two required edges do not exist**:

- `ec2_instance --?--> iam_role` — `normalizers/ec2.py` stores
  `instance_profile_arn` as an attribute; no edge is emitted. And an
  instance profile ARN is not a role ARN — resolving it needs
  `iam:GetInstanceProfile`, which no collector calls.
- `iam_role --?--> s3_bucket` — no collector extracts resource ARNs from
  policies.

`find_paths` walks edges. No edges, no path.

Enforced by `test_no_workload_to_identity_path_is_invented`, which
deliberately builds an estate with all four resources and asserts no
returned path contains both `i-web` and `role/app`.

**4. 80.0 critical at `medium` confidence — where did −10 come from?**

From `CONFIDENCE_PENALTY["medium"] = 10.0`.

The path's confidence is the **weakest link** across all its nodes and
edges. The path is `(internet, role/admin)`. `internet` is an **external
node** — materialized by `BuildResourceGraph` because it is not a
collectible resource — and external nodes carry `medium` confidence.

**Why it is right:** we never enumerated the internet. We know it exists
because something pointed at it. Claiming `high` confidence in a node we
never observed would be a false precision, and confidence is supposed to
mean something.

It is *not* a defect to fix. Every internet-origin path is capped at
`medium` by construction, and that is honest.

**5. The identity/data-bearing bug — why isn't "the risk was real" a defence?**

The bug: `is_sensitive()` included `IDENTITY`, and `is_publicly_assumable`
is a public-exposure attribute — so a role satisfied the *data store*
scenario and was reported as *"holds sensitive data and is readable from
the internet"*, scoring 85.0 and outranking the correctly-worded path for
the same resource.

**Why "the risk was real" is not a defence:**

The *sentence* is what the responder acts on. Someone reading "holds
sensitive data" goes looking for **data** — checks what is in it, who
accessed it, whether there was exfiltration. None of that exists. They
find nothing, conclude the alert was wrong, and are now less likely to
believe the next one.

A wrong explanation of a real risk fails in exactly the way a fabricated
finding fails: it sends people to investigate something untrue. Hence:
**a true risk stated in a false sentence is still a false positive.**

The duplication compounded it — the same resource reported twice with
contradictory rationales, the wrong one ranked higher.

**Worth noting how it was found:** by *running* the analyzer on a realistic
estate and reading the output, not by reviewing the diff. Every test
passed.

**6. Two ways to learn a resource is internet-facing — why different, why not additive?**

- **`EXPOSURE_DIRECT_INTERNET_EDGE` (+40)** — a graph edge. A *modelled
  relationship*: a collector parsed a trust policy, applied semantic
  analysis, and asserted a structural fact.
- **`EXPOSURE_ATTRIBUTE_EVIDENCE` (+35)** — a boolean on the resource.
  *One collector's reading* of one API response.

The edge scores higher because it survived more interpretation and is
independently checkable in the graph.

**Not additive** (an `elif`, not two `if`s) because they are two ways of
learning the **same fact**. A resource that is internet-reachable is
internet-reachable; learning it twice does not make it more so. Summing
them would give 75 for exposure alone and push essentially everything to
`CRITICAL`, destroying the ranking.

**7. `analyze()` without `resources` — which scenarios still work?**

Only **scenario 1** (`public_identity_with_privilege`) — it is driven by a
real graph edge, and its attribute lookups (`attributes.get(rid, {})`)
degrade to empty, losing the privilege bonus but keeping the path.

The other three all require attributes:
- 2 needs `public` / `allows_public_network_access`
- 3 needs `public_ip` and `has_unrestricted_ingress`
- 4 needs exposure attributes on the target store

**Why failing quietly is acceptable here:** the parameter exists for
backward compatibility, and the docstring states the contract — *"without
it the two attribute-driven scenarios simply find nothing — a smaller
result, never a wrong one."*

The failure direction matters. Omitting `resources` **under-reports**; it
never invents a path. Under-reporting is recoverable; false paths are not.

That said, silent under-reporting is genuinely easy to miss, which is why
`test_resources_reach_the_analyzer` exists in the pipeline integration
suite specifically to pin that the wiring is present.

**8. Why cap privilege at 30 when the parts sum to 60?**

Because **two routes to total control is still total control.**

A role with `AdministratorAccess` can already do everything. Discovering
it *also* has a privilege-escalation path and a wildcard action adds no
real capability — the attacker had everything at the first one.

Without the cap, exposure (40) + privilege (60) + sensitivity (20) = 120,
clamped to 100. Every over-permissioned role would saturate, and you could
no longer distinguish "publicly assumable admin role" from "publicly
assumable role with three overlapping over-permissions" — nor from any
other maximum-risk path. **The ranking would collapse at the top**, which
is precisely where you need it.

**9. Extension: you get `iam:GetInstanceProfile`. Design it.**

**The edge:**

```
ec2_instance --ASSUMES--> iam_role
```

`ASSUMES` is already in `_TRAVERSABLE_RELATIONSHIPS`, so traversal needs
no change.

**Where:** `Ec2Collector` (or a new `InstanceProfileCollector`) calls
`iam:GetInstanceProfile` on each `instance_profile_arn`, reads
`Roles[0].Arn`, and the normalizer emits the relationship. Use the
resilience layer — this is an N+1 pattern over instances.

**The scenario:** a new `internet_to_workload_to_identity` builder, or —
better — let scenario 4's `find_paths` discover it, since chains are
already what it does. The workload must satisfy scenario 3's conditions
(public IP **and** open ingress) to be an entry point.

**What you must NOT infer:**

- **Never derive the role from the profile name.** `profile/app` →
  `role/app` is a convention, not a fact. If `GetInstanceProfile` returns
  `AccessDenied`, emit **no edge** and mark the attribute `UNKNOWN` —
  do not guess.
- **Do not assume one role per profile.** AWS models `Roles` as a list.
- **Do not assume the workload's exposure implies the role's.** They are
  separate facts.
- **Do not skip the confidence question.** If the role ARN came from a
  call that was retried or partially degraded, the edge deserves reduced
  confidence, which then propagates through weakest-link scoring.

**Also update:** nothing in `classification.py` — `ec2_instance` and
`iam_role` are already mapped. Add negative tests for the denied case, and
**delete** `test_no_workload_to_identity_path_is_invented` only when the
edge genuinely exists, replacing it with a test that the path *is* found.
