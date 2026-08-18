# Phase 3B — The Terraform Security Scenario Laboratory

> Terraform's only job here is to **create real cloud resources in
> known-good and known-bad configurations**. It contains no rule ids,
> no expected findings, no severities, and no Rule Engine metadata of
> any kind — and an automated test enforces that.

---

## 1. Objective

Give the scanner something real to scan. Two deployable environments —
one AWS, one Azure — each provisioning a compliant and a non-compliant
variant of every resource type the rule catalogs cover, so a scan
demonstrably produces both `PASS` and `FAIL` findings rather than
"always finds something".

---

## 2. The separation this document exists to defend

| Component | Job | Never does |
|---|---|---|
| **Terraform** (this document) | Create real resources in known configurations | Evaluate rules; know rule ids; declare expected findings |
| **Rule Engine** (`phase-3-rules.md`) | Decide whether a resource is compliant | Parse Terraform; read `.tfstate` |
| **Conformance Framework** (`phase-3-conformance.md`) | Compare expected vs actual | Re-evaluate rules; read Terraform |

The scenario labs and the conformance scenarios are **deliberately not
the same thing**. Terraform lives in `terraform/`; conformance
expectations live in `tests/conformance/scenarios/*.yaml`. They never
reference each other. This is enforced, not merely intended:

```python
# tests/conformance/test_rule_catalog_conformance.py
def test_terraform_contains_no_rule_engine_metadata(self) -> None:
    forbidden = ("expected_rule_id", "expected_finding", "rule_id", "logical_finding_id")
    for path in sorted((_REPO_ROOT / "terraform").rglob("*.tf")):
        for token in forbidden:
            assert token not in path.read_text()
```

---

## 3. Layout

```
terraform/
├── aws/
│   ├── main.tf, variables.tf, outputs.tf, providers.tf, versions.tf
│   ├── README.md                      ← costs, safety, deploy/destroy
│   ├── environments/test/             ← the deployable root
│   └── modules/
│       ├── s3_test_resource/
│       ├── network_test_resource/
│       ├── ec2_test_resource/
│       ├── iam_test_resource/
│       ├── kms_test_resource/
│       └── cloudtrail_test_resource/
└── azure/
    ├── main.tf, variables.tf, outputs.tf, providers.tf, versions.tf
    ├── README.md
    ├── environments/test/
    └── modules/
        ├── storage_test_resource/
        ├── network_test_resource/
        ├── compute_test_resource/
        ├── keyvault_test_resource/
        └── monitor_test_resource/
```

The existing repository convention (`modules/*_test_resource/` +
`environments/test/`) was kept rather than switching to the brief's
suggested `scenarios/{compliant,non_compliant}/` split. The brief
explicitly permits this: *"Use the repository's existing conventions if
they are better."* Grouping by **resource type** keeps each
compliant/non-compliant pair side by side in one file, where the
difference between them is readable at a glance; splitting by
compliance state would scatter each pair across two trees.

---

## 4. Safety

### The hard guard

Both environments validate:

```hcl
variable "environment" {
  validation {
    condition     = var.environment == "test"
    error_message = "environment must be exactly \"test\". This module refuses any other value ..."
  }
}
```

Terraform refuses to plan or apply with any other value. This is a
deliberate, enforced guard against pointing intentionally-insecure
configuration at a production account.

### Everything else

* Every module lives under `modules/*_test_resource/`.
* AWS resources carry `Purpose = compliance-scanning-test-environment`
  via provider `default_tags`.
* The whole Azure environment lives in one dedicated resource group, so
  deleting the group removes every billable resource.
* **No real data** is ever written: buckets and storage accounts are
  created empty and stay empty; no key, secret, or certificate is
  created in any vault; the VMs run stock images and serve no workload.
* **No credentials are generated or stored.** No AWS access key is ever
  created. Azure VMs take a *public* SSH key only, with password
  authentication disabled — no private key or password is ever written
  to state.
* `.tfstate`, `.tfvars` (except `*.example`), and `.terraform/` are
  `.gitignore`'d at the repository root.

---

## 5. AWS scenario coverage

| Resource | Compliant | Non-compliant |
|---|---|---|
| S3 | private, encrypted, versioned, logged, BPA on | **public via ACL, unencrypted**; a third bucket is **public via bucket policy** |
| Security group | HTTPS from within the VPC | **SSH open to 0.0.0.0/0**; a third group is restrictive itself but **ALLOWS the open group** |
| EC2 | no public IP, IMDSv2 required, encrypted root volume, instance profile | **public IP, IMDSv1 allowed, unencrypted root volume, no instance profile** |
| IAM user | *(see limitations)* | **no MFA**; a second user has **AdministratorAccess attached directly** |
| IAM account policy | 14-char minimum, symbols/numbers, 90-day age, 24-generation reuse | *(account-wide singleton — see limitations)* |
| KMS | rotation enabled | **rotation disabled**; a third key has a **public key policy** |
| CloudTrail | multi-region, validation on, logs to a versioned private bucket | *(see limitations)* |

The three "chained" resources — the bucket-policy-public bucket, the
security group that references the open group, and the EC2 instance in
the open group — exist specifically to give the **cross-resource rules**
real graph data to evaluate.

## 6. Azure scenario coverage

| Resource | Compliant | Non-compliant |
|---|---|---|
| Storage account | HTTPS enforced, no anonymous blob access, TLS 1.2, default-deny firewall, soft delete on | **anonymous blob access, plaintext HTTP, TLS 1.0, default-allow firewall, no soft delete** |
| Network security group | HTTPS from within the VNet | **SSH (22) and RDP (3389) open to the internet**, plus a wildcard **Deny** rule that must *not* count |
| Virtual machine | no public IP, managed identity, restrictive NSG's subnet | **public IP, no managed identity, internet-open NSG's subnet** |
| Key Vault | RBAC, public access disabled, default-deny firewall | **legacy access policies, public access, default-allow firewall** |
| Activity Log | exports Administrative/Security/Policy to a private, soft-delete-protected storage account | *(see limitations)* |

Azure has no "default VPC", so the network module also provisions the
minimum supporting infrastructure: one VNet, two subnets, one public
IP. No gateways, no NAT, no load balancers.

The wildcard-source **Deny** rule on the non-compliant NSG is
deliberate: it proves the normalizer correctly ignores Deny rules when
computing `has_unrestricted_ingress`, which an Allow-only model (like
AWS security groups) would never exercise.

---

## 7. Cost

Both READMEs carry a full per-resource cost table. Summary:

| Environment | Main ongoing cost | Notes |
|---|---|---|
| AWS | **3 KMS keys ≈ $1/month each**; 2 × `t3.micro` ≈ $0.02/hour while running | Buckets, security groups, IAM users, CloudTrail (first copy) are free or pennies |
| Azure | **2 × `Standard_B1s` ≈ $0.02/hour** while running; 1 Standard public IP ≈ $0.005/hour | Empty storage accounts and empty Key Vaults have no standing charge |

Explicitly avoided: large instance fleets, RDS/managed databases, NAT
gateways, and load balancers. Nothing here needs them.

`terraform destroy` is documented in both READMEs and should be run as
soon as a scan session ends.

---

## 8. Validation status — stated precisely

| Check | AWS | Azure |
|---|---|---|
| `terraform fmt -recursive -check` | **PASSES** (verified) | **PASSES** (verified) |
| `terraform validate` | **NOT RUN** | **NOT RUN** |
| `terraform plan` / `apply` | **NOT RUN** | **NOT RUN** |

`terraform validate` requires downloading the provider plugin from
`registry.terraform.io`, which this build environment's egress policy
denies (verified: the proxy returns 403 for `registry.terraform.io`
and `checkpoint-api.hashicorp.com`). That is a sandbox restriction, not
a configuration defect — but it means **this Terraform has not been
proven to validate or deploy**, and this document does not claim
otherwise. Both configurations were reviewed by hand against the
provider documentation.

To verify locally:

```sh
cd terraform/aws/environments/test   # or terraform/azure/environments/test
terraform init
terraform validate
```

---

## 9. Known limitations

Documented rather than hidden. Each is a genuine constraint of the
cloud provider, not a shortcut:

1. **No MFA-enabled AWS IAM user.** Registering a virtual MFA device
   requires an interactive TOTP enrollment step no Terraform provider
   can automate.
2. **The AWS account password policy is an account-wide singleton.**
   It can only hold one state, so it is set to the compliant
   configuration; the failing branches are proven by unit tests.
3. **Root MFA cannot be provisioned either way.** The rule reports the
   real account's actual state.
4. **No non-compliant CloudTrail trail / Azure diagnostic setting.**
   Running two of each purely for a demo was judged not worth the
   cost and complexity; the failing branches are proven by the
   conformance suite and unit tests.
5. **Azure Key Vault purge protection is off on both vaults.**
   Enabling it is irreversible — a protected vault cannot be deleted
   until its retention elapses, which would break `terraform destroy`.
   The compliant vault therefore legitimately reports a
   `purge-protection-disabled` finding.
6. **EBS encryption-by-default may mask a finding.** If the AWS
   account/region has it enabled, the non-compliant EC2 instance's
   root volume is encrypted regardless of the module's
   `encrypted = false`, and that finding will not fire. The account's
   own stronger default working as intended.

---

## 10. How the labs connect to the rest of the system

```
terraform apply                    (this document)
        │  creates real resources
        ▼
AwsCollector / AzureCollector      (phase-3-infrastructure.md, §Azure below)
        │  produces NormalizedResource
        ▼
ResourceGraph → Rule Engine        (phase-3-rules.md)
        │  produces Finding
        ▼
tests/integration/{aws,azure}/     opt-in, real-cloud assertions
```

The integration suites are the only place Terraform outputs and the
Rule Engine meet — and even there, they meet through **environment
variables carrying resource ids**, never through Terraform files
containing rule metadata. Both suites are skipped by default and gated
behind `COMPLIANCEIQ_AWS_INTEGRATION_TESTS` /
`COMPLIANCEIQ_AZURE_INTEGRATION_TESTS`.
