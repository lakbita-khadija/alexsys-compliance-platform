# STEP 8A.1 — AWS network completion

Closing the last structural gap in the network foundation: locating the
**workload** in the topology STEP 8A built.

---

## 1. What was actually missing

STEP 8A produced a complete network graph — VPC, subnet, route table,
internet gateway, NACL — with every edge grounded in a named AWS field.
It had one hole: nothing connected an `ec2_instance` to the `aws_subnet`
it runs in. The network existed and the workloads existed, side by side,
with no edge between them.

That made every network fact unactionable at the workload level. A route
table with a default route to an internet gateway is a fact about the
route table, and before this step nobody could ask *which instances does
that affect*.

---

## 2. Correction to three earlier documents

Three documents in this repository stated that `ec2_instance` **does not
record its `SubnetId`**:

- `docs/audits/aws-network-foundation-current-state.md` §6
- `docs/architecture/aws-network-collectors.md` §9
- `docs/reports/security-data-consumption-matrix.md` §7

**That claim was wrong.** `SubnetId` has been collected since Phase 3:

| File | Line | Code |
|---|---|---|
| `infrastructure/cloud/aws/resource_collectors/ec2.py` | 87 | `subnet_id=instance.get("SubnetId")` |
| `infrastructure/cloud/aws/normalizers/ec2.py` | — | `"subnet_id": subnet_id` in `attributes` |

What was missing was the **graph edge**, not the data. The distinction
matters and is not pedantry: "the collector does not fetch this field"
implies an API change and a permission review, while "the normalizer
does not emit an edge" is a five-line change to code that already has
the value in hand. The wrong diagnosis made the gap look several times
larger than it was, and it was repeated across three documents without
anyone re-reading the collector.

All three are corrected in place, with the original claim struck through
rather than deleted. An audit that silently edits its own past findings
is not an audit.

---

## 3. The edge

```
ec2_instance --ATTACHED_TO--> aws_subnet
```

| Property | Value |
|---|---|
| Source field | `DescribeInstances.Reservations[].Instances[].SubnetId` |
| Emitted by | `infrastructure/cloud/aws/normalizers/ec2.py` |
| Relationship type | `ATTACHED_TO` (existing vocabulary — nothing invented) |
| Confidence | `high` |
| Traversable | **No** — informational |
| Emitted when | `subnet_id` is truthy. Absent/empty ⇒ no edge. |

### Why `ATTACHED_TO` and not `CONTAINS`

A real trade-off rather than an obvious call.

`CONTAINS` would match `vpc --CONTAINS--> subnet` and reads as pure
containment. But `CONTAINS` points *container → contained*, and it is
the **instance** that declares its subnet. Emitting it in that direction
would require `SubnetCollector` to call `DescribeInstances` — doubling
the heaviest API call in the scan — to buy directional elegance.

`ATTACHED_TO` is what this same normalizer already emits for security
groups, and an instance genuinely attaches to a subnet through its
network interface. The two kinds of `ATTACHED_TO` are told apart
downstream by the target node's `resource_type`, which every rule in the
catalog already filters on.

No new `RelationshipType` was added. The closed vocabulary
(`contains · connects_to · protects · allows · assumes · accesses ·
attached_to · publicly_exposed`) is unchanged.

---

## 4. Subnet → route table (verified, not re-implemented)

Already correct as built in STEP 8A. Verified against the brief's three
requirements:

| Requirement | Status |
|---|---|
| Uses the real AWS association | ✅ `DescribeRouteTables.RouteTables[].Associations[].SubnetId` |
| No name-based inference | ✅ Association records only; no id-prefix or tag matching |
| No duplicate inverse edge | ✅ `normalize_subnet` emits `relationships=()` |

Additional properties confirmed by test:

- Associations are de-duplicated and **sorted** (`associated_subnet_ids`),
  so two scans of unchanged infrastructure produce an identical edge order.
- A `Main: true` association with no `SubnetId` produces **no edge** —
  AWS does not enumerate the subnets a main table implicitly governs, and
  emitting edges to subnets we were never told about would be inference.
- A gateway association (`GatewayId`, no `SubnetId`) produces no edge.
- Malformed association records (`{}`, `{"SubnetId": None}`,
  `{"SubnetId": ""}`) are skipped individually and **do not abort the
  remaining associations**; all of them survive in `attributes.associations`
  as evidence.

### Still a gap

The **main-table fallback** is unmodelled. A subnet with no explicit
association implicitly uses its VPC's main route table, and we emit no
edge for that. So the absence of a route-table edge on a subnet must not
be read as "this subnet has no route". This is documented, not fixed —
modelling it correctly needs the VPC↔main-table relationship and a
decision about how to represent an implicit association honestly.

---

## 5. Graph validation

Full topology asserted in
`tests/unit/infrastructure/test_aws_ec2_subnet_placement.py`:

```
aws_vpc            --CONTAINS-->     aws_subnet
aws_route_table    --ATTACHED_TO-->  aws_subnet
aws_route_table    --CONNECTS_TO-->  aws_internet_gateway
aws_network_acl    --PROTECTS-->     aws_subnet
internet_gateway   --ATTACHED_TO-->  aws_vpc
ec2_instance       --ATTACHED_TO-->  aws_subnet     ← added here
ec2_instance       --ATTACHED_TO-->  security_group
```

| Check | Result |
|---|---|
| Every edge target is a node in the graph | ✅ |
| Dangling edges | none |
| Duplicate edges | none |
| Self-loops | none |
| Rejected edges | none |
| Validation ERRORs | none |
| Tenant consistency | ✅ all nodes on one tenant |
| Account consistency | ✅ no `cross_account_edge` issues |
| Fingerprint stable across identical input | ✅ |
| Fingerprint independent of collector ordering | ✅ |
| Fingerprint **changes** when the instance moves subnet | ✅ |
| Fingerprint **changes** when placement is lost | ✅ |

The last two matter as much as the stability ones: a fingerprint that
ignored the new edge entirely would satisfy the first two and be useless.

### Missing target subnet

When the instance names a subnet the scan never collected — EC2-only
scan scope, another region, or `DescribeSubnets` denied — the edge is
**kept** and `BuildResourceGraph` materializes the target as an external
node (`kind="external"`, `resource_type="external_resource"`,
`confidence="medium"`, `source_collector="relationship-inference"`).

It is deliberately **not** typed `aws_subnet`: the `subnet-` prefix is
not evidence, and a rule targeting `aws_subnet` must not match a node
nobody enumerated. No validation error is raised — a partially
enumerated graph is normal, not corrupt.

---

## 6. Defect found: unenumerated neighbours silently became determinate

The missing-target test above surfaced a **pre-existing defect in the
rule evaluator**, unrelated to this step's edge and live since the DSL
gained relationship conditions.

`target_type` was applied as a plain `resource_type != target` drop.
That is right for a *collected* node — the type is an observation and
the mismatch is a fact. It is wrong for an **external** one, whose
`resource_type` is a placeholder meaning "we never enumerated this".
Dropping it asserted a fact the scan did not have.

The failure ran in both directions, and both are the exact failure this
codebase refuses everywhere else:

| Condition | Before | Consequence |
|---|---|---|
| `relationship` | zero neighbours survive the filter ⇒ vacuously NOT_MATCHED ⇒ **PASS** | An instance whose only security group was never collected read as **confirmed compliant**. |
| `no_relationship` | the same zero ⇒ "the relationship is absent" ⇒ **MATCHED** | A database whose private endpoint was never collected read as **confirmed unprotected**. |

**Fix** (`domain/rules/conditions.py`, `_partition_neighbors`):
unenumerated neighbours are folded in as `INDETERMINATE` contributors
rather than dropped. Under Kleene OR, `MATCHED ∨ INDETERMINATE` is
`MATCHED`, so a confirmed violation is never downgraded — the fix stops
a *non*-finding from claiming certainty the scan does not have. Nodes
that are collected and simply of another type are still dropped outright.

Blast radius on the existing suite: **zero test changes required**.
13 regression tests added in
`tests/unit/domain/test_rules_unenumerated_neighbors.py`, including the
two that would catch an over-broad fix: a confirmed violation must still
FAIL, and a collected node of another type must still be dropped (else
this step's own placement edge would have poisoned every security-group
rule in the catalog).

---

## 7. Attack paths — no change

**No new attack path scenario, and none was added.**

`ATTACHED_TO` is in `_INFORMATIONAL_RELATIONSHIPS`, not
`_TRAVERSABLE_RELATIONSHIPS`. An attacker does not travel *into* a
subnet. Asserted directly:

- the new `ec2_instance → aws_subnet` edge is `is_traversable() == False`
- **no** edge anywhere in the network topology is traversable
- the existing test that the network estate produces **zero** attack
  paths still passes

A route-backed reachability scenario remains **undefensible** for two
documented reasons: stateless order-dependent NACL evaluation does not
exist, and the route-table main-table fallback is unmodelled. Building
one on top of this edge alone would fabricate reachability from
topology, which is the failure mode this project treats as worse than a
missing finding.

---

## 8. Rules — one added

The new edge would otherwise have been **dead data**, which the standing
project rule forbids: every security-relevant relationship must have a
clear consumer.

`ec2-instance-in-internet-routed-subnet-with-public-ip`
(`rules/aws/network_topology.yaml`) is that consumer, and it is the
first rule in the catalog to traverse from a workload to the network
layer governing it:

```
ec2_instance
  public_ip is not null
  AND --attached_to(outgoing, aws_subnet)-->
        <--attached_to(incoming, aws_route_table)--
            has_internet_route is true
```

Two hops, which the DSL supports because a relationship node's `where`
is evaluated recursively with the graph threaded through — verified
before the rule was written, not assumed.

**Severity `medium`, and the wording is the point.** The finding claims
internet *addressability*, not confirmed reachability: the security
group is still the deciding control, and
`ec2-instance-attached-to-open-security-group` is the rule that asserts
the firewall half. A correctly firewalled public instance is a normal
working architecture, not a violation.

Framework mapping stays `unresolved` with a rationale — nobody has
checked it against published CIS text, and STEP 7 forbids claiming
`verified` without provenance.

No existing rule changed. Every rule that traverses `attached_to`
already filters on `target_type`, so the second kind of `ATTACHED_TO`
on `ec2_instance` is invisible to them.

---

## 9. Terraform — documented, not modified

**No Terraform file was changed.**

Current state:

| Resource | Terraform status |
|---|---|
| `aws_instance` (compliant / non-compliant pair) | ✅ `terraform/aws/modules/ec2_test_resource/main.tf` |
| `aws_security_group` (3 variants) | ✅ `terraform/aws/modules/network_test_resource/main.tf` |
| `aws_vpc` | ❌ not created — `data.aws_vpc.default` |
| `aws_subnet` | ❌ not created — `data.aws_subnets.default.ids[0]` |
| `aws_route_table` | ❌ not created |
| `aws_internet_gateway` | ❌ not created |
| `aws_network_acl` | ❌ not created |

Both instances are placed in the **default VPC's** first subnet with
`subnet_id = data.aws_subnets.default.ids[0]`, so the placement edge
does have a real subnet to point at in a live scan, and the STEP 8A
collectors will enumerate the default VPC's topology.

What is **not** available is a controlled fixture: there is no
public-subnet / private-subnet pair, no route table with a known
internet route, and no NACL variant. So
`ec2-instance-in-internet-routed-subnet-with-public-ip` cannot be
exercised against a deterministic live estate — its behaviour depends on
whatever the default VPC happens to look like.

Filling this needs a dedicated network scenario module (VPC, two
subnets, two route tables, IGW, NACL pair). That is a Terraform change,
which this step does not make.

---

## 10. Verification status

| Claim | Status |
|---|---|
| `ec2_instance → aws_subnet` edge from the real AWS field | **IMPLEMENTED + LOCALLY VERIFIED** |
| `aws_route_table → aws_subnet` from the real association | **IMPLEMENTED + LOCALLY VERIFIED** |
| Graph integrity, determinism, tenant/account consistency | **IMPLEMENTED + LOCALLY VERIFIED** |
| Unenumerated-neighbour evaluator fix | **IMPLEMENTED + LOCALLY VERIFIED** |
| Two-hop rule fires / passes / is indeterminate correctly | **IMPLEMENTED + LOCALLY VERIFIED** |
| Behaviour against a live AWS account | **REQUIRES LIVE AWS VERIFICATION** |
| Controlled Terraform network fixture | **NOT IMPLEMENTED — documented gap** |
| Route-table main-table fallback | **NOT IMPLEMENTED — documented gap** |
| Stateless NACL evaluation | **NOT IMPLEMENTED — documented gap** |

All verification here is against fakes built from documented `describe_*`
response shapes. No live AWS account was used, and no live result is
claimed.
