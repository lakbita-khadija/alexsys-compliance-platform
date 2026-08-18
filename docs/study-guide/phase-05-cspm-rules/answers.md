# Phase 5 — Answers

**1. "CloudTrail delivers logs to a public bucket" — the condition.**

```yaml
condition:
  relationship: accesses
  direction: outgoing
  target_type: s3_bucket
  where:
    field: public
    operator: is_true
```

`ACCESSES`, direction `outgoing`, because the edge is emitted by
`aws/normalizers/cloudtrail.py` as `cloudtrail --ACCESSES--> s3_bucket`.
The subject of the rule is the trail, and the `where` clause is evaluated
against the bucket.

Getting the direction wrong is a silent failure: `incoming` would find
nothing at all, and the rule would sit at `NOT_MATCHED` forever with no
error.

**2. `severity: critical` vs `confidence: high` — and which can a finding override?**

- **`severity`** — "how serious is this violation *in the abstract*?"
  Static, decided by the rule author. A public bucket is critical
  regardless of which bucket it is.
- **`confidence`** — "how reliable is the *rule's own detection logic*?"
  A rule reading one explicit boolean is `high`; one inferring posture
  from indirect signals is lower. It is catalog metadata for a human
  reviewing rule quality — **no evaluator consumes it**.

Neither is overridden by the finding. What the finding adds is a *third*
axis: `risk`, the contextual 0–100 CRSF-1.1 score. Two findings from the
same rule share severity and differ in risk — that is the entire point of
Phase 8.

**3. Why is `automation_example` never executed?**

Because ComplianceIQ is a **detection** product, not a remediation agent,
and the blast radius of getting that wrong is unbounded. An auto-applied
"fix" that misreads intent can take down production — a bucket that
*should* be public for static hosting, an SG rule another team depends on.

Secondary reasons: executing it would require write credentials (a far
larger security surface than read-only scanning), and it would need an
approval and audit workflow that does not exist.

It is stored as plain text and surfaced in reports. A human decides.

**4. RDS rule — why not today, and why is shipping it harmful?**

There is **no RDS collector**. No RDS resource ever enters the pipeline,
so the rule never matches a resource type and produces **no finding at
all** (via `applies_to_resource_type`).

Why shipping it anyway is harmful, in increasing order:

- **Inflated coverage.** "69 rules including RDS" implies detection that
  does not exist.
- **False assurance.** A customer sees an RDS rule in the catalog,
  concludes RDS is covered, and stops looking. They now have *less*
  security awareness than before.
- **Undetectable.** Because the rule silently produces nothing rather
  than erroring, no test or dashboard reveals the gap.

This is the reasoning behind the same decision for `no_relationship`:
capability without a producing collector is not shipped.

**5. 23 network rules vs 9 encryption — is that a problem?**

**Not on its own.** The distribution reflects two legitimate things:
network misconfiguration genuinely is the most common and most exploitable
class of cloud finding, and network resources have more independently
checkable properties (per-port, per-CIDR, per-direction) than encryption,
which is often one boolean.

It becomes a problem if it reflects **collector coverage** rather than
risk. Here it partly does: encryption rules are thin because RDS, EBS
snapshots and EFS have no collectors. So the honest reading is "9
encryption rules over the *encryption surface we can see*", not "9 is
enough".

The number to watch is not rules-per-domain but **services covered: 12 of
26**.

**6. `framework_mappings` entry with no `status`.**

The value is **`"unresolved"`**, from the dataclass default on
`FrameworkMapping`.

It is the right default because the alternative — defaulting to
`verified` — means every mapping anyone ever adds silently claims to have
been checked against published benchmark text. As the model's own
docstring puts it: fabricating an unverified control mapping is the
fastest way to lose credibility with an actual auditor.

Defaulting to unresolved makes the *safe* state the *lazy* state.
Promoting to `verified` requires a deliberate act by someone who actually
opened the benchmark. Currently 11 of 27 are verified and all 16 others
inherit the default — the system is behaving exactly as designed.

**7. How does conformance catch a wrong-resource-type rule?**

A unit test asserts the rule's *logic*: given a resource with
`network_default_action: Allow`, the condition returns MATCHED. That is
true and says nothing about which resources it runs against.

The conformance framework runs the **whole catalog** against Terraform
scenarios with declared expectations — "this scenario contains a
non-compliant Key Vault and a compliant storage account". It then
classifies every finding. A Key Vault rule firing on a storage account
produces a finding nobody declared → **`UNEXPECTED_FINDING`**.

This is the same lesson as the graph blocker in Phase 3.2: the component
was correct in isolation, and only a test that exercised it **in
composition with everything else** revealed the defect. The fix was
`applies_to_resource_type`.
