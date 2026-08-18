# AWS Network Foundation — Current State Audit

> **STEP 8A, audit phase. No code was modified.**
>
> Baseline recorded before any change: **1700 passed, 60 skipped,
> 0 failed**; `ruff` clean; `mypy` clean over 189 source files.

---

## 1. Coverage of the five target resources

| Resource | Collector | Normalizer | Relation support | Rules | Terraform | Tests |
|---|---|---|---|---|---|---|
| **VPC** | ❌ none | ❌ none | ⚠️ referenced only as a **string attribute** | ❌ none | ❌ none | ❌ none |
| **Subnet** | ❌ none | ❌ none | ❌ none | ❌ none | ❌ none | ❌ none |
| **Route Table** | ❌ none | ❌ none | ❌ none | ❌ none | ❌ none | ❌ none |
| **Internet Gateway** | ❌ none | ❌ none | ❌ none | ❌ none | ❌ none | ❌ none |
| **Network ACL** | ❌ none | ❌ none | ❌ none | ❌ none | ❌ none | ❌ none |

None of the five exists in any layer. `vpc_id` appears today only as a
flat attribute on `security_group` — a string that names a resource the
graph does not contain, which is exactly why no edge can be drawn from
it.

`terraform/aws/modules/network_test_resource/` is named "network" but
contains **only three `aws_security_group` resources**. No VPC, subnet,
route table, internet gateway or NACL is declared anywhere in
`terraform/`.

---

## 2. What already exists and must be reused

| Capability | Location | Reuse |
|---|---|---|
| Per-service collector base | `resource_collectors/base.py` (`AwsResourceCollector`) | Constructor, clock, tenant, account plumbing |
| Session/client construction | `AwsSessionFactory` → `session.client("ec2")` | All five use the `ec2` client |
| Error translation | `translate_client_error` → `AwsCollectionError` | Never leak botocore types |
| Resilience | `infrastructure/cloud/resilience.py` | Full-jitter backoff, `paginate()` |
| Registration | `AwsCollector.__init__` default tuple | Where a collector becomes reachable in production |
| `UNKNOWN` semantics | `domain/shared/unknown.py` | AccessDenied on a sub-call → `UNKNOWN`, never `False` |

**Registration is the hazard worth naming.** The STEP 0 audit found
`IamRoleCollector` fully implemented, fully unit-tested, and **absent
from `AwsCollector`'s default tuple** — so it never ran in production
and every test still passed. A test now derives the expected collector
set from the package; any new collector must be added there or that test
fails. That is the guard, and it must not be bypassed.

---

## 3. Relationship vocabulary — the central §3 question

The enum is closed and its docstring is explicit: *"this enum must never
be extended speculatively."*

```
contains · connects_to · protects · allows
assumes  · accesses     · attached_to · publicly_exposed
```

Emitted today: `attached_to`, `accesses`, `allows`, `assumes`,
`publicly_exposed`. **Not yet emitted: `contains`, `connects_to`,
`protects`** — and their docstrings say they await exactly the
VPC/subnet/route-table collectors this step adds.

Classification (`domain/attack_paths/classification.py`):

| Type | Traversable | Documented meaning |
|---|---|---|
| `CONTAINS` | ❌ informational | Topology |
| `CONNECTS_TO` | ✅ traversable | Network reachability |
| `PROTECTS` | ❌ informational | A control, not a route |
| `ATTACHED_TO` | ❌ informational | Configuration |

### Proposed relationships, mapped to the existing vocabulary

Each is justified below rather than assumed. **No new enum value is
needed**, which is the outcome the vocabulary was designed for.

---

#### 3.1 `vpc --CONTAINS--> subnet`

```
source            aws_vpc
target            aws_subnet
relationship_type CONTAINS  (existing)
semantics         A subnet is a partition OF a VPC. It cannot exist
                  without one and cannot move between VPCs.
AWS evidence      DescribeSubnets → Subnets[].VpcId
traversable       NO — informational topology
```

Direction is container → contained, matching `CONTAINS`'s plain-English
name. An attacker does not "travel into" a VPC; containment is context,
not a step.

Which resource *emits* the edge is a real design problem, because AWS
reports the fact on the subnet while the edge points the other way. It
is worked through and resolved in **§3.6**.

---

#### 3.2 `route_table --CONTAINS--> ...` ❌ REJECTED

A route table's routes are not resources; they are attributes. Modelling
each route as a node would invent five resource types nobody collects.
Routes stay **structured attributes** on the route table, preserving
order and target type per §6.

---

#### 3.3 `route_table --CONNECTS_TO--> internet_gateway`

```
source            aws_route_table
target            aws_internet_gateway
relationship_type CONNECTS_TO  (existing)
semantics         A route with GatewayId = igw-* means traffic matching
                  the destination CIDR EGRESSES through that gateway.
                  That is genuine network reachability, which is exactly
                  what CONNECTS_TO is documented to mean.
AWS evidence      DescribeRouteTables → RouteTables[].Routes[].GatewayId
                  matching `igw-`, with DestinationCidrBlock
traversable       YES
```

This is the one traversable edge in this step, and it is the reason the
step matters: it is the first *authoritative* evidence of internet
egress, replacing the current inference from "the instance has a public
IP".

**Only emitted when `GatewayId` actually starts with `igw-`.** A
`vgw-`/`nat-`/`vpce-` target is a different kind of gateway and would be
a fabricated internet route.

---

#### 3.4 `internet_gateway --ATTACHED_TO--> vpc`

```
source            aws_internet_gateway
target            aws_vpc
relationship_type ATTACHED_TO  (existing)
semantics         An IGW is attached to a VPC — AWS's own word, and the
                  attachment is detachable, optional, and stateful. That
                  is configuration, which is what ATTACHED_TO means here
                  (cf. instance --ATTACHED_TO--> security_group).
AWS evidence      DescribeInternetGateways → InternetGateways[].Attachments[]
                  {VpcId, State}
traversable       NO — informational
```

Emitted **only** for attachments whose `State` is `available`. An
attachment mid-detach is not connectivity.

---

#### 3.5 `network_acl --PROTECTS--> subnet`

```
source            aws_network_acl
target            aws_subnet
relationship_type PROTECTS  (existing)
semantics         A NACL is a stateless filter applied AT the subnet
                  boundary. It is a control guarding a resource, which is
                  precisely PROTECTS's documented meaning ("a control,
                  not a route").
AWS evidence      DescribeNetworkAcls → NetworkAcls[].Associations[]
                  {SubnetId, NetworkAclAssociationId}
traversable       NO — a control is not a step
```

Note the direction differs from `security_group`, where the *instance*
declares `ATTACHED_TO` the group. That asymmetry is real: AWS reports
NACL associations on the NACL, and security group membership on the
instance. Emitting from whichever side AWS actually reports it keeps the
edge grounded in evidence rather than in symmetry.

---

#### 3.6 `subnet --CONTAINS--> ...` — the direction problem, resolved

`BuildResourceGraph` builds edges from `NormalizedResource.relationships`,
and a resource's relationships always have **that resource as source**.
So a subnet cannot emit `vpc --CONTAINS--> subnet`.

Three options were considered:

1. **Invent `BELONGS_TO`** — forbidden by §3, and unnecessary.
2. **Have the VPC collector emit `CONTAINS` per subnet** — requires the
   VPC collector to call `DescribeSubnets`, duplicating collection and
   coupling two collectors.
3. **Emit `CONTAINS` from the VPC, sourced from subnet data, inside the
   VPC collector's own `DescribeSubnets` call.**

**Chosen: option 2/3 — the VPC collector performs one additional
`DescribeSubnets` call and emits `vpc --CONTAINS--> subnet`.**

The cost is one extra API call; the benefit is that `CONTAINS` keeps its
plain-English direction and no new relationship type is invented. The
subnet collector remains the source of subnet *attributes*; the VPC
collector owns only the containment *edge*. Duplication is bounded and
documented.

If `DescribeSubnets` is denied for the VPC collector, it emits **no**
containment edges and records the gap — absence of an edge means "not
observed", never "does not exist".

---

## 4. Graph integration constraints

| Constraint | Where enforced | Consequence for this step |
|---|---|---|
| Dangling edge → ERROR | `validate_graph` | Every edge target must be collected, or the scan reports an integrity error |
| External nodes | `BuildResourceGraph` | A referenced-but-uncollected VPC materializes as an external node with reduced confidence |
| Duplicate edges | WARNING | Edge identity is `(source, target, type)`, excluding provenance |
| Determinism | `graph_fingerprint()` | Nodes and edges sorted; routes and ACL entries must be emitted in stable order |
| Tenant isolation | `ensure_same_tenant` | Every new resource carries `tenant_id` |
| `_IMPOSSIBLE` | `validate_graph` | Only constrains `internet` targets; none of the five new types conflicts |

**Risk identified:** if the IGW is collected but its VPC is not (a
permissions gap), `igw --ATTACHED_TO--> vpc` produces an external node
rather than a dangling-edge error. That is the correct behaviour and
matches how `security_group.vpc_id` would behave — but it means a
partial-permission scan yields `kind="external"` VPC nodes, and any
future rule must not read that as "the VPC does not exist".

---

## 5. Resource roles

None of the five types is in `_ROLE_BY_RESOURCE_TYPE`, so all classify
as `OTHER` — never a target, never an entry point in attack path
analysis.

**That is correct and must stay so in this step.** A subnet is not a
thing an attacker wants to reach; it is where things live.
`NETWORK_CONTROL` is arguably right for `network_acl` (it sits beside
`security_group`), but adding it would change attack-path output, and
§11 forbids that here. Recorded as a STEP 8B+ consideration.

---

## 6. Attack path impact (§11 — documentation only)

**New evidence this step makes available**

- Authoritative internet egress: `route_table --CONNECTS_TO--> igw`
  replaces the current inference from a public IP alone.
- Subnet public-ness: `map_public_ip_on_launch`.
- Subnet-level filtering: NACL ingress/egress entries, ordered.
- Topology: which subnet a workload's network sits in.

**Potential future scenario** (NOT implemented here)

> *A workload in a subnet whose route table routes `0.0.0.0/0` to an
> internet gateway, with a permissive NACL and an open security group.*

This would upgrade `internet_to_exposed_workload` from "has a public IP
and an open SG" to genuine route-backed reachability — the difference
between an instance that *looks* internet-facing and one that provably
is.

**Still missing before that is honest**

> **Correction (STEP 8A.1).** Item 1 below was **factually wrong** when
> written, and the error was repeated in
> `docs/architecture/aws-network-collectors.md` §9 and
> `docs/reports/security-data-consumption-matrix.md` §7.
> `ec2_instance` **has** recorded its `SubnetId` since Phase 3
> (`resource_collectors/ec2.py`, `normalizers/ec2.py`). What was missing
> was the **graph edge**, not the data. The claim is left in place with
> this correction rather than quietly rewritten, because an audit that
> silently edits its own past findings is not an audit. See
> `docs/audits/aws-network-completion.md` §2. Items 2 and 3 were
> accurate; item 2 was also resolved in STEP 8A.

1. ~~`ec2_instance` does not record its `SubnetId`~~ — **WRONG, see the
   correction above.** The attribute existed; the
   `ec2_instance --ATTACHED_TO--> aws_subnet` edge did not, and that is
   what actually prevented locating the workload in the topology. Added
   in STEP 8A.1.
2. No `subnet --ATTACHED_TO--> route_table` edge: `DescribeRouteTables`
   associations give it, but the main-table fallback (a subnet with no
   explicit association uses the VPC's main table) must be modelled or
   the absence of an edge will be misread as "no route".
   **Resolved in STEP 8A**, emitted from the route table (the side AWS
   reports the association on). The main-table fallback remains
   unmodelled and is still a genuine gap.
3. NACL evaluation is order-dependent and stateless; deciding "this NACL
   permits the traffic" requires an evaluator that does not exist.

Until at least (1) and (2) exist, no scenario change is defensible. **No
analyzer change in this step.**

STEP 8A.1 closed (1) and (2) but still made **no analyzer change**: the
new edge is `ATTACHED_TO`, which is classified informational, so it adds
topology rather than attack surface. Item (3) remains open, and a
route-backed reachability scenario is not defensible without it.

---

## 7. Terraform (§13)

**Status: GAP DOCUMENTED, not filled.**

None of the five resources exists in `terraform/`. Per §13, Terraform
expansion belongs to the dedicated infrastructure-validation step, so
this step adds none and the gap is recorded here.

Consequence: the new collectors are verified against **fakes modelled on
documented `describe_*` response shapes**, exactly as every existing AWS
collector is. The opt-in integration suite cannot exercise them until
Terraform declares the resources.

---

## 8. Rules (§12)

No existing rule targets any of the five types, and none can consume the
new fields without a new rule.

**No rule is added.** §12 permits one if strictly necessary to validate
collector integration; it is not — the graph integration tests validate
the collectors end to end without a rule, and adding one would start a
rule family this step is explicitly told not to start.

---

## 9. Plan

1. Five normalizers, five collectors, reusing the existing base.
2. Relationships exactly as mapped in §3 — no new enum value.
3. Register all five in `AwsCollector` (the STEP 0 lesson).
4. Collector, normalizer and graph tests per §14.
5. `docs/architecture/aws-network-collectors.md`.
6. No Terraform, no rules, no analyzer change, no new attack path
   scenario.
