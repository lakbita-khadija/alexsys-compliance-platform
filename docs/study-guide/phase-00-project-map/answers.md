# Phase 0 — Answers

**1. Why is importing `boto3` into `domain/rules/conditions.py` a design error?**

Three reasons, in increasing severity:

- It breaks the dependency rule and fails
  `tests/api/test_architecture.py`.
- It makes rule evaluation non-deterministic: the same rule against the
  same resource could produce different results depending on network
  conditions.
- It makes the *security logic* untestable without a cloud account. The
  three-valued evaluator is the most correctness-critical code in the
  product; it must be testable with plain dicts.

**2. Why is `ResourceGraph` in `domain/` but `BuildResourceGraph` in `application/`?**

`ResourceGraph` owns **invariants**: tenant isolation at `add_node`,
referential integrity at `add_edge`. Those are truths about what a graph
*is*, and they belong with the model.

`BuildResourceGraph` owns **orchestration**: iterate resources, decide
what to do when a relationship points at something uncollected, collect a
report of rejected edges. Those are policy decisions about how to
assemble one, and they change independently of the invariants.

The test at `tests/unit/application/test_build_resource_graph.py`
(`test_graph_still_refuses_a_dangling_edge_at_the_aggregate`) exists
precisely to show the invariant stayed in the domain even when the
builder's behaviour changed.

**3. The graph is never persisted — what problem, and how is it handled?**

A cross-resource finding says "EC2 instance attached to an open security
group". A week later the graph that knew *which* security group is gone,
so the finding cannot recompute it.

Handled by **storing the context on the finding at scan time**:
`Finding.related_resources`, `indeterminate_resources` and
`graph_context`, added in migration `0003`. Context that lives only in the
process that produced the finding is the same as no context.

**4. Where would a new AWS collector go, and which layers?**

- `infrastructure/cloud/aws/resource_collectors/<service>.py` — the SDK
  calls
- `infrastructure/cloud/aws/normalizers/<service>.py` — raw → `NormalizedResource`
- register it in `infrastructure/cloud/aws/collector.py` (`AwsCollector`)
- `rules/aws/<service>.yaml` — rules, if any
- `tests/unit/infrastructure/test_aws_<service>_collector.py`

**Domain and application need no changes** — that is the point of the
layering. If you find yourself editing `domain/` to add a collector,
something is wrong.

If the resource should participate in attack paths, you would also add a
row to `_ROLE_BY_RESOURCE_TYPE` in
`domain/attack_paths/classification.py`.

**5. If risk ran before attack paths, which factor would be wrong?**

`attack_path_involvement_factor`, and it would be **0.0** for every
finding — because no paths would exist yet. Since that factor carries 15%
of the CRSF-1.1 weight, every finding would lose up to 15 points of risk,
and — more damagingly — a finding on a critical attack path would score
identically to an isolated one, which defeats the entire purpose of
contextual risk.

The comment in `scan_cloud_account.py` states this, and the blueprint's
own note ("Attack Path avant Risk final") overrides its looser prose
ordering.

**6. Caching the graph between scans — which invariants?**

Several defensible answers; two strong ones:

- **Tenant isolation.** A cached graph is a cross-request object; the
  current design gets isolation almost free because each graph is built
  fresh from one tenant's resources.
- **Determinism / freshness.** `graph_fingerprint()` deliberately
  excludes provenance so that a changed fingerprint means the *topology*
  changed. A cache introduces a third state — "the topology changed but
  we did not look" — that nothing currently models.

Also acceptable: mutation. `ResourceGraph` has no removal API because
nobody mutates it after construction; a cache would need one.

**7. Which file first?**

`application/scanning/scan_cloud_account.py`. `ScanCloudAccount.run()` is
about 60 readable lines and names every stage in order.
