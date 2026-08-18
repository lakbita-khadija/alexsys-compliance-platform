# AWS Network Collectors

> VPC, subnet, route table, internet gateway, network ACL (STEP 8A).
>
> Audit that preceded this:
> [aws-network-foundation-current-state.md](../audits/aws-network-foundation-current-state.md).

---

## 1. The pipeline

```
AWS API (ec2)                     Collector                 Normalizer                 GraphNode / GraphEdge
─────────────────────────────     ────────────────────      ─────────────────────      ─────────────────────
DescribeVpcs                  →   VpcCollector          →   normalize_vpc          →   aws_vpc
  + DescribeSubnets                                                                     └─ CONTAINS → subnet
DescribeSubnets               →   SubnetCollector       →   normalize_subnet       →   aws_subnet
DescribeRouteTables           →   RouteTableCollector   →   normalize_route_table  →   aws_route_table
                                                                                        └─ CONNECTS_TO → igw
DescribeInternetGateways      →   InternetGatewayColl.  →   normalize_internet_gw  →   aws_internet_gateway
                                                                                        └─ ATTACHED_TO → vpc
DescribeNetworkAcls           →   NetworkAclCollector   →   normalize_network_acl  →   aws_network_acl
                                                                                        └─ PROTECTS → subnet
```

All five share `_Ec2PaginatedCollector`, which factors out the
paginator/`translate_client_error` boilerplate. It is private because it
is plumbing, not a collector — the registration test skips private
classes for exactly that reason.

---

## 2. Two principles

### Structure is preserved, never collapsed

A route table is its **ordered list of routes**, not
`has_internet_route: true`. A NACL is its **ordered entries**, not
`allow_all: true`.

Derived booleans exist — `has_internet_route`,
`has_unrestricted_ingress_rule` — but **alongside** the evidence, never
instead of it. A rule that disagrees with our summary must be able to
look at what we actually saw. A CSPM that cannot show its working cannot
defend a finding.

### Nothing is inferred from an identifier

An AWS field containing an id is not permission to draw an edge. Every
relationship below names the exact response field it came from, and the
`CONNECTS_TO` case additionally checks the *kind* of gateway — see §4.

---

## 3. Relationships — the existing vocabulary, reused

**No new `RelationshipType` was added.** `CONTAINS`, `CONNECTS_TO` and
`PROTECTS` were already in the closed enum and had never been emitted;
their docstrings said they awaited exactly these collectors.

| Source | Target | Type | AWS evidence | Traversable |
|---|---|---|---|---|
| `aws_vpc` | `aws_subnet` | `CONTAINS` | `DescribeSubnets → Subnets[].VpcId` | ❌ informational |
| `aws_route_table` | `aws_internet_gateway` | `CONNECTS_TO` | `RouteTables[].Routes[].GatewayId` | ✅ |
| `aws_internet_gateway` | `aws_vpc` | `ATTACHED_TO` | `InternetGateways[].Attachments[]` (state `available`) | ❌ informational |
| `aws_network_acl` | `aws_subnet` | `PROTECTS` | `NetworkAcls[].Associations[].SubnetId` | ❌ informational |

`aws_subnet` emits **no** relationships. Its `VpcId` is an attribute; the
containment edge belongs to the VPC.

### Why the VPC emits `CONTAINS`, and the extra API call

AWS reports VPC membership **on the subnet**, but `CONTAINS` points
container → contained. `BuildResourceGraph` builds edges from a
resource's own `relationships`, always with that resource as source, so a
subnet cannot emit `vpc --CONTAINS--> subnet`.

Three options were weighed (audit §3.6). Inventing `BELONGS_TO` was
rejected — the vocabulary is closed on purpose. The chosen answer:
`VpcCollector` makes one additional `DescribeSubnets` call and emits the
edges itself.

Cost: one extra API call per scan. Benefit: `CONTAINS` keeps its
plain-English direction and no type is invented.

If that call is denied, the VPC is still collected and emits **no**
containment edges. Absence means *not observed*, never *no subnets*.

### Why direction differs from security groups

A security group is declared by the **instance** (`instance
--ATTACHED_TO--> sg`); a NACL is declared by the **NACL**
(`acl --PROTECTS--> subnet`). That asymmetry is real, not an
inconsistency: AWS reports SG membership on the instance and NACL
associations on the NACL. Each edge is emitted from whichever side AWS
actually reports it, which keeps it grounded in evidence rather than
symmetric for its own sake.

---

## 4. `CONNECTS_TO` — the one traversable edge, and its guard

This is the first **authoritative** internet-egress evidence in the
graph, replacing inference from "the instance has a public IP".

It is emitted only when **both** hold:

1. the route's destination is a default route (`0.0.0.0/0` or `::/0`), and
2. the target is a `gateway` whose id starts with **`igw-`**.

Everything else is refused:

| Target | Emitted? | Why |
|---|---|---|
| `nat-…` | ❌ | Outbound-only. No inbound reachability |
| `vgw-…` | ❌ | Virtual private gateway — a VPN, not the internet |
| `vpce-…` | ❌ | VPC endpoint — private AWS service access |
| `eigw-…` | ❌ | Egress-only (IPv6), outbound-only by definition |
| `local` | ❌ | Intra-VPC |
| `igw-…` on `203.0.113.0/24` | ❌ | Routing one prefix through an IGW is not "open to the world" |

Treating a NAT default route as internet exposure would manufacture a
path into every private subnet in the estate. That is the single most
likely fabrication in this step, and it is pinned by a test per gateway
prefix.

---

## 5. Normalized fields

### `aws_vpc`
`cidr_block` · `cidr_blocks` (every association, sorted) · `state` ·
`is_default` · `instance_tenancy` · `dhcp_options_id`

### `aws_subnet`
`vpc_id` · `cidr_block` · `ipv6_cidr_blocks` · `availability_zone` ·
`availability_zone_id` · `state` · **`map_public_ip_on_launch`** ·
`assign_ipv6_address_on_creation` · `available_ip_address_count` ·
`is_default_for_az`

`map_public_ip_on_launch` is only *half* of "will an instance here be
reachable" — a public IP with no route to an internet gateway reaches
nothing. The route table supplies the other half.

### `aws_route_table`
`vpc_id` · **`routes`** (ordered; each with `destination`,
`target_type`, `target_id`, `state`, `origin`) · **`associations`** ·
`associated_subnet_ids` · `is_main` · *derived:* `has_internet_route`,
`internet_gateway_ids`

`target_type` is kept as a discriminated field across ten mutually
exclusive AWS fields (`GatewayId`, `NatGatewayId`, `TransitGatewayId`, …),
because *which kind of gateway* is the whole difference between internet
egress and a private VPN link.

`is_main` matters for a reason easy to miss: a subnet with **no** explicit
route table association implicitly uses the VPC's main table. So the
absence of an association is not the absence of a route.

### `aws_internet_gateway`
`attachments` (all states, preserved) · `attached_vpc_ids` (available
only) · `is_attached`

### `aws_network_acl`
`vpc_id` · `is_default` · **`ingress_entries`** / **`egress_entries`**
(ordered by rule number) · `associations` · `associated_subnet_ids` ·
*derived:* `has_unrestricted_ingress_rule`

Entry order is load bearing: a NACL evaluates lowest rule number first
and stops at the first match, so `DENY 100` before `ALLOW 200` means the
opposite of the reverse.

`has_unrestricted_ingress_rule` is deliberately narrow — *"there is an
allow-all-from-anywhere ingress rule"*, **not** *"this NACL permits the
traffic"*. The second needs a stateless-evaluation engine that does not
exist, and claiming it would be a conclusion we cannot defend.

---

## 6. Confidence and evidence

Every emitted edge carries `confidence="high"` and an `evidence` mapping
naming its source field — these come from a single authoritative
`describe_*` response, not from correlation. The `CONNECTS_TO` edge
additionally records the destination CIDRs that justified it.

Nodes are `kind="collected"`. A referenced-but-uncollected VPC (a
permissions gap) materializes as an `external` node with reduced
confidence rather than a dangling-edge error. **A future rule must not
read that as "the VPC does not exist"** — pinned by a test.

---

## 7. Determinism

- `cidr_blocks`, `ipv6_cidr_blocks`, `associated_subnet_ids`,
  `internet_gateway_ids`, `attached_vpc_ids` — all sorted
- `CONTAINS` edges emitted in sorted subnet order
- NACL entries sorted by rule number; a malformed entry with no rule
  number sorts last rather than crashing the scan
- Routes and associations keep AWS's order, which is itself stable

`graph_fingerprint` is asserted stable across runs and across reversed
input order.

---

## 8. Failure semantics

| Situation | Behaviour |
|---|---|
| `AccessDenied` on the main `describe_*` | `AwsCollectionError`; `AwsCollector` isolates it and the scan continues with other collectors |
| Throttling | Same translation; `resilience.py` governs retry |
| `AccessDenied` on the VPC's extra `DescribeSubnets` | Logged; VPCs still collected, **no** containment edges |
| Empty response | `()` — a determinate answer, not an error |
| Malformed route | Recorded with `None` fields; the scan is not aborted over one row |
| Malformed NACL entry | Recorded verbatim, sorted last |
| Transient IGW attachment | No edge; the attachment is still preserved as evidence |

---

## 9. Attack path impact — **no scenario added** (§11)

**New evidence now available**

- Authoritative internet egress (`route_table --CONNECTS_TO--> igw`)
- Subnet public-IP-on-launch
- Subnet-level filtering (ordered NACL entries)
- VPC/subnet topology

**Still missing before any new scenario is honest**

> **Correction (STEP 8A.1).** Item 1 was **wrong**: `ec2_instance` has
> recorded `SubnetId` as an attribute since Phase 3. The missing piece
> was the graph edge. Corrected rather than deleted — see
> `docs/audits/aws-network-completion.md` §2.

1. ~~**`ec2_instance` does not record its `SubnetId`**~~ — **WRONG.** The
   attribute was always there; the
   `ec2_instance --ATTACHED_TO--> aws_subnet` **edge** was not, so the
   workload could not be joined to the topology. **Added in STEP 8A.1.**
2. **No `subnet → route_table` edge.** `DescribeRouteTables` gives
   associations, but the main-table fallback must be modelled or the
   absence of an association will be misread as "no route".
   **Association edge added in STEP 8A**; the main-table fallback is
   still unmodelled and still a real gap.
3. **NACL evaluation is stateless and order-dependent.** Deciding "this
   NACL permits the traffic" needs an evaluator that does not exist.

A test asserts the current network estate — public-IP-on-launch, default
route to an attached IGW, allow-all NACL — produces **zero** attack
paths. **That remains true after STEP 8A.1**, by design: the placement
edge is `ATTACHED_TO`, which `domain/attack_paths/classification.py`
classifies informational, so an attacker cannot travel along it.
`tests/unit/infrastructure/test_aws_ec2_subnet_placement.py` asserts it
directly. Item (3) is the remaining blocker for a route-backed
reachability scenario.

Resource roles: all five classify as `OTHER`, so none is ever an attack
path target or entry point. `network_acl` could arguably be
`NETWORK_CONTROL` beside `security_group`, but changing it would change
analyzer output, which §11 forbids here.

---

## 10. Tests

| Area | Tests |
|---|---|
| Shared collector contract (×5, parametrized) | happy path · empty · missing key · AccessDenied · throttling · tenant/account propagation · determinism · pagination |
| VPC | attributes · multi-CIDR · `CONTAINS` direction and ordering · no-subnets · extra call made · denied-subnets degradation |
| Subnet | attributes · **emits no relationships** · defaults · sorted IPv6 |
| Route table | ordered routes · target type kept · real IGW edge · **NAT rejected** · four non-IGW prefixes rejected · non-default destination rejected · associations/main · malformed route · deduplication |
| Internet gateway | available attachment · unattached · three transient states · malformed |
| Network ACL | ingress/egress split · rule-number ordering · deny · mixed · derived flag beside evidence · port ranges · `PROTECTS` · malformed entry |
| Graph | nodes created · four expected edges · no dangling · no duplicates · no errors · external-node case · fingerprint stability ×2 · edge ordering · traversability · **no new attack path** |

**96 new tests.** Full suite: **1796 passed, 60 skipped, 0 failed**
(baseline 1700).

---

## 11. Limitations

1. **No Terraform.** None of the five exists in `terraform/`; per §13 the
   gap is documented and expansion belongs to the
   infrastructure-validation step. So these collectors are verified
   against fakes modelled on documented response shapes — as every
   existing AWS collector is — and **have never run against a real AWS
   account**.
2. **No rules consume the new fields.** §12 permits one rule if strictly
   necessary; it was not, and adding one would start a rule family this
   step is told not to start.
3. **No `subnet → route_table` edge** (§9).
4. **IPv6 routing is collected but not analyzed.**
5. **VPC peering, transit gateways and endpoints** are recorded as route
   targets but have no collectors, so their far side is not in the graph.
6. **One extra `DescribeSubnets` call per scan** (§3).
