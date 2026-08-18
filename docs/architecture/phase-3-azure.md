# Phase 3B — Azure: the second cloud, added additively

> The point of this document is what did **not** change. Adding Azure
> required zero modifications to the domain layer, the application
> layer, the rule DSL, the ResourceGraph, `Finding`, or the conformance
> framework — and no modification to any existing AWS file.

---

## 1. The target architecture

```
AWS Collectors ─────┐
                    ├──> NormalizedResource ──> ResourceGraph ──> Rule Engine ──> Findings
Azure Collectors ───┘
```

Everything to the right of `NormalizedResource` is provider-agnostic
and was already written. Azure plugs in on the left.

---

## 2. Why it was this cheap

The Phase 1/2 design anticipated it:

* `CloudProvider.AZURE` already existed in `domain/shared/enums.py`,
  documented as "DESIGNED — no collector exists yet, but the Domain
  must already be able to represent an Azure-sourced resource without a
  rewrite" (blueprint §7, ADR-002).
* `BaseCollector` (`application/scanning/collector.py`) is a port with
  one method returning `tuple[NormalizedResource, ...]`. Nothing in it
  mentions AWS.
* The rule DSL operates on `NormalizedResource.attributes` /
  `.tags` / `.resource_type` — plain data, no provider branching.
* `RelationshipType` is a closed, provider-neutral vocabulary.
  `ATTACHED_TO` means the same thing for EC2→SG and VM→NSG.

A pre-implementation audit confirmed this: zero AWS-specific branching
in `domain/` or `application/`, the only AWS-specific code being under
`infrastructure/cloud/aws/` and `rules/aws/`.

---

## 3. What was added

```
infrastructure/cloud/azure/
├── credentials.py                  AzureCredentialConfig (strategy pointer, never a secret)
├── errors.py                       Azure error taxonomy + translate_azure_error
├── session.py                      AzureSessionFactory -> AzureClients bundle
├── collector.py                    AzureCollector (satisfies BaseCollector)
├── normalizers/                    storage, network, compute, keyvault, monitor
└── resource_collectors/            base + the five per-service collectors

rules/azure/                        27 rules across 5 services
terraform/azure/                    the Azure scenario laboratory
tests/unit/infrastructure/test_azure_*.py       101 unit tests
tests/integration/azure/            opt-in, real-subscription suite
tests/conformance/scenarios/azure_*.yaml        17 conformance scenarios
```

Plus exactly **two** shared additions, both driven by genuine
multi-cloud needs:

* `application/rules/composite_rule_catalog.py` — combines the
  per-provider catalogs, rejecting duplicate rule ids.
* `Rule.applies_to_resource_type` — see §7.

---

## 4. Structural differences from AWS, and how they were handled

| Azure reality | AWS analogue | How it was handled |
|---|---|---|
| Each service is its own SDK package with its own client class | one `boto3.Session` mints all clients | `AzureClients` bundle holds one client per service; `AzureSessionFactory` builds it once |
| Errors carry an HTTP `status_code` | `ClientError` carries a string error code | A separate `translate_azure_error`; 401 → auth, 403 → permission, else service |
| Subscription id is known from the client | AWS needs `sts:GetCallerIdentity` | No round trip needed; `account_id` is free |
| NSG rules have explicit Allow **and Deny** with priorities | security groups are allow-only | The normalizer considers only inbound `Allow` rules |
| "Any source" is `*`, `Internet`, or a CIDR | only CIDR form | All three recognized |
| VM→NSG is indirect (VM → NIC → NSG, or VM → NIC → subnet → NSG) | EC2 lists its SGs directly | The **collector** resolves the chain; the normalizer receives resolved ids, exactly as the EC2 normalizer does |
| No default VPC | default VPC exists | The Terraform network module provisions a minimal VNet + subnets |

The SDK imports in `session.py` are **deferred into `create()`**, so
importing any collector module — as its unit tests do — never requires
the Azure SDK to be installed.

---

## 5. Attribute naming: Azure's vocabulary, not S3's

`https_only`, not `encrypted`. `allow_blob_public_access`, not
`public`. Two reasons:

1. **The concepts genuinely differ.** Azure Storage is *always*
   encrypted at rest, so an `encrypted` field would be a meaningless
   constant `True`.
2. **A rule author reading `rules/azure/storage.yaml` should see the
   names the Azure portal shows them.** Force-mapping Azure facts onto
   S3 names would make every rule a translation exercise.

Consequence: **cross-provider rules are not attempted.** A rule targets
one provider's resource type. That is deliberate — a rule claiming to
mean the same thing across two clouds would be lying about at least one
of them.

---

## 6. Relationships

Reusing the existing closed vocabulary, no new types invented:

| Relationship | Meaning |
|---|---|
| `azure_virtual_machine` → `azure_network_security_group` (ATTACHED_TO) | The VM's effective network control, resolved through NICs and subnets |
| `azure_activity_log_setting` → `azure_storage_account` (ACCESSES) | The audit log's export destination |

These are the direct counterparts of AWS's EC2→SG and CloudTrail→S3
edges, and they are evaluated by the **same** `relationship` DSL node
with **no** Azure-specific code in `domain/rules/conditions.py`.

---

## 7. The one shared change Azure forced

Adding Azure surfaced a latent bug in the rule engine — found by the
conformance framework, not by inspection.

An Azure Key Vault and an Azure storage account both carry
`network_default_action`. Rules had no resource-type scoping, so
**every rule was evaluated against every resource of every type**, and
the Key Vault firewall rule fired against storage accounts.

The fix (`Rule.applies_to_resource_type`, full rationale in
`phase-3-rules.md` §6 and `phase-3-conformance.md` §7.2) is additive:
`None` preserves the original behaviour, every shipped rule now
declares its type, and a test enforces that. AWS benefits identically —
before the fix, all 41 AWS rules were also evaluated against every AWS
resource type, producing `INDETERMINATE` noise.

---

## 8. Coverage

| Service | Collector | Rules | Unit tests |
|---|---|---|---|
| Storage accounts | `StorageAccountCollector` | 7 | 13 |
| Network security groups | `NetworkSecurityGroupCollector` | 7 | 18 |
| Virtual machines | `VirtualMachineCollector` | 3 | 22 |
| Key Vaults | `KeyVaultCollector` | 5 | 10 |
| Activity Log settings | `ActivityLogSettingCollector` | 5 | 17 |
| Errors / collector / credentials | — | — | 21 |
| **Total** | **5 collectors** | **27** | **101** |

---

## 9. Known limitations

1. **Entra ID (Azure AD) identity rules are not implemented.** The IAM
   equivalent — users, MFA, privileged role assignments — requires
   Microsoft Graph, a different SDK and a different permission model
   from the ARM management plane every other collector uses. Out of
   scope for this phase, and stated rather than faked. There is
   therefore no Azure counterpart to the 10 AWS IAM rules.
2. **Absence of a diagnostic setting cannot be flagged.** A
   subscription with no Activity Log export produces no resource of
   that type, so no rule fires. A per-resource rule engine cannot
   report the absence of a resource.
3. **`managed_disk_encryption_enabled` reports `None`, not `False`,
   when no disk-encryption set is attached.** Azure encrypts managed
   disks with platform keys by default, so "no customer-managed key" is
   not evidence of "no encryption".
4. **Blob soft-delete requires a second API call** whose failure yields
   `None` (uncollected) rather than `False`.
5. **NSG port ranges are not expanded** into individual ports — the
   same documented limitation the AWS normalizer carries.
6. **Only the compliant Activity Log setting is provisioned** in
   Terraform; failing branches are proven by conformance and unit
   tests.

---

## 10. Verification status

| Check | Status |
|---|---|
| Azure unit tests (101) | **PASS** — run, verified |
| Azure conformance scenarios (17) | **PASS** — run, verified |
| `AzureCollector` satisfies `BaseCollector` | **PASS** — asserted by test |
| No AWS rule fires against Azure resources | **PASS** — asserted by conformance + integration test |
| `terraform fmt -check` on `terraform/azure/` | **PASS** — run, verified |
| `terraform validate` on `terraform/azure/` | **NOT RUN** — provider download blocked by sandbox egress policy |
| Integration tests against a real subscription | **NOT RUN** — no Azure credentials in this environment; suite is written and gated, skipped by default |

The last two are stated plainly because they are the difference between
"this is tested" and "this is prepared". The Azure collectors have
**never executed against a real Azure subscription** in this
environment.
