# Phase 11 — Answers

**1. Collector test passes, scan crashes — what was missing?**

An **integration test that builds a graph from real collector output**.

```python
def test_collector_output_can_be_assembled_into_a_graph(self) -> None:
    resources = IamRoleCollector(fake_client).collect()
    graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
    assert graph.nodes
```

The 21 existing tests asserted on `resource.relationships` — the
collector's *output object*. They proved "the collector emits what we
expect" and never proved "that output can be assembled into a graph."

The seam is the untested surface. Name it after the seam, not after either
component.

**2. Why do 19 of 40 attack path tests assert absence?**

Because the failure modes are **asymmetric in cost**.

A missed path costs one backlog item. A fabricated path costs an on-call
engineer an hour chasing a chain that does not exist — and permanently
discounts every future critical alert.

There is also a mechanical reason: **positive behaviour is
self-announcing**. If a scenario stops firing, someone notices missing
findings. If a scenario starts firing on the wrong thing, it looks like a
new detection — indistinguishable from a real one until someone
investigates.

Negative tests are the only thing standing between "we added a scenario"
and "we added a false-positive generator."

**3. Why compare an index to a linear scan?**

Because the invariant is *"the index agrees with the authoritative
collection"*, and comparing derived against authoritative tests exactly
that.

Hardcoded expectations test the **test author's model**. They also break
when a fixture changes — and can be "fixed" wrongly, masking the drift
they exist to catch.

The failure being guarded is silent: a stale index does not raise, the
rule just quietly stops firing. Any test that could be updated to agree
with the broken state is not a guard.

**4. Someone adds `routes_to` — which test should fail?**

**It should be a test asserting every `RelationshipType` member appears in
exactly one of `_TRAVERSABLE_RELATIONSHIPS` or
`_INFORMATIONAL_RELATIONSHIPS`.**

⚠️ **That test does not exist today.** This is a real gap, listed in the
Phase 11 limitations and in `next-work.md` as P2.

What happens without it: `is_traversable()` checks *membership* in the
traversable set, so an unlisted type returns `False`. Attack paths
silently never route through the new edge. No error, no warning — the
capability simply does not appear.

The informational set is enumerated explicitly (rather than defined as
"everything else") to make this a conscious decision. That is a good
convention, but a convention is not an enforcement.

```python
def test_every_relationship_type_is_classified(self) -> None:
    for rt in RelationshipType:
        assert (rt in _TRAVERSABLE_RELATIONSHIPS) ^ (rt in _INFORMATIONAL_RELATIONSHIPS)
```

**5. 131 skipped instead of 60 — diagnose.**

**PostgreSQL is not running.** The 71 extra skips are the persistence
integration suite: 36 in `test_persistence.py`, 17+7 in
`test_api_repositories.py`, 11 in `test_migrations.py`.

The fixtures skip cleanly rather than failing, with the message
*"PostgreSQL is not reachable, so the persistence integration suite cannot
run."*

Diagnose with `pytest -q -rs` to list skip reasons.

**Why this matters:** a green run at 131 skips looks identical to a green
run at 60 unless you read the count. The persistence suite is where the
schema-parity test lives — the one that caught migration `0003` drifting
from the ORM models. Skipping it silently means shipping a migration
mismatch.

Always check the skip count, not just the pass count.

**6. Write the test that would have caught the graph-threading defect.**

```python
def test_cross_resource_rules_fire_through_the_real_pipeline(self) -> None:
    estate = [
        resource("i-web", "ec2_instance", {"public_ip": "1.2.3.4"},
                 (rel("sg-open", RT.ATTACHED_TO),)),
        resource("sg-open", "security_group", {"has_unrestricted_ingress": True}),
    ]
    result = ScanCloudAccount(
        collector=StaticCollector(estate),
        rule_catalog=YamlRuleCatalog(REAL_RULES_DIR),      # ← the REAL catalog
    ).run(...)

    assert any(f.rule_id == RuleId("ec2-instance-attached-to-open-security-group")
               and f.status is FindingStatus.FAIL
               for f in result.findings)
```

**What it must NOT use:**

- **Not a fake catalog.** The original tests used one with no
  cross-resource rules — that is precisely why they missed it.
- **Not a hand-built graph.** It must go through `ScanCloudAccount`, so
  the threading is exercised.
- **Not a direct `EvaluateRules` call.** That bypasses the defective line.

The defect lived in the *combination* of the real pipeline and the real
catalog. Any test substituting either half cannot see it. This is what
`test_scan_pipeline_regressions.py` now does.

**7. When is changing an existing test legitimate?**

Legitimate when the test **encoded an implementation detail or a
placeholder**, not an intended behaviour — and the change makes the
assertion **stronger**.

The example here: `assert result.attack_paths == ()` encoded
`AnalyzeAttackPaths` returning `()`. It was never a decision that a
`public: True` bucket should produce no attack path; it was a record of
the placeholder.

**How to defend it in review:**

1. State what the assertion *encoded* versus what it *appeared* to assert.
2. Show the assertion count went **up**, not down (one → four here).
3. Add an inline comment in the test explaining the change, so the next
   reader does not have to find the commit.
4. Show that the underlying **invariant was relocated, not removed** —
   as with the graph blocker, where `add_edge` still refuses dangling
   edges and a new test asserts it directly against the aggregate.

**Illegitimate:** loosening an assertion, deleting a case, adding
`pytest.mark.skip`, or widening a tolerance so new code passes. If the
change makes the test prove *less*, it is not a fix.

**8. Three defect classes a green suite would still miss.**

1. **Real cloud API divergence.** Every collector test uses fakes modelled
   on *documented* response shapes. If AWS returns a field in a different
   form, omits one under a condition nobody modelled, or paginates where
   the docs imply it does not, the suite is silent. The 60 skipped
   integration tests are exactly the ones that would catch it — and they
   have never run.

2. **Performance and scale.** The benchmark is synthetic, in-process, no
   database, no network. Nothing tests a 10,000-resource estate, N+1
   collector patterns against real latency, or memory under load. The S3
   and IAM managed-policy N+1s are known and untested.

3. **Semantic correctness of the rules themselves.** Tests prove a rule's
   *condition evaluates as written*. Nothing proves the condition
   correctly expresses the security control — that
   `bucket_policy_allows_public_access` really captures every policy shape
   granting public access. A rule can be perfectly tested and still check
   the wrong thing.

Honourable mentions: unresolved framework mappings (16 of 27, unverifiable
without benchmark text), and the unclassified-`RelationshipType` gap from
question 4.
