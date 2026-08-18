# ComplianceIQ Azure Test Environment

**This provisions REAL Azure resources that cost REAL money and includes
INTENTIONALLY INSECURE configuration.** Read this entire file before
running anything.

## What this is

The Azure sibling of `terraform/aws/`, and it exists for the same
purpose: giving ComplianceIQ's `AzureCollector` and the
`rules/azure/` catalog something real to scan and produce genuine
findings against. It deliberately provisions both a compliant and a
non-compliant version of each resource type, so a scan demonstrably
produces both `PASS` and `FAIL` findings — not just "always finds
something."

**This is a `ComplianceIQ TEST ENVIRONMENT`.** Every module is under
`modules/*_test_resource/`, everything lives in one dedicated resource
group, and the `environment` variable is hard-validated to the literal
value `"test"` — Terraform refuses to apply with any other value. This
is a deliberate, enforced guard against ever pointing this
configuration at a production subscription.

## What gets created

| Resource | Compliant | Non-compliant |
|---|---|---|
| Storage account | HTTPS enforced, no anonymous blob access, TLS 1.2, default-deny firewall, blob soft delete on | **anonymous blob access, plaintext HTTP allowed, TLS 1.0, default-allow firewall, no soft delete** |
| Network security group | HTTPS only, from within the VNet | **SSH (22) and RDP (3389) open to the internet** |
| Virtual machine | no public IP, system-assigned managed identity, in the restrictive NSG's subnet | **public IP, no managed identity, in the internet-open NSG's subnet** |
| Key Vault | RBAC authorization, public network access disabled, default-deny firewall | **legacy access policies, public network access, default-allow firewall** |
| Activity Log diagnostic setting | exports Administrative/Security/Policy to a private, soft-delete-protected storage account | *(not provisioned — see below)* |

Plus the supporting infrastructure Azure has no default for: one
resource group, one virtual network, two subnets, one public IP, and a
third (private) storage account used as the Activity Log destination.

Three deliberate limitations, documented rather than hidden:

* **Purge protection is left OFF on both Key Vaults.** Enabling it is
  irreversible in Azure — a vault with purge protection on cannot be
  deleted until its retention period elapses, which would make
  `terraform destroy` unable to clean up this environment. The
  compliant vault therefore legitimately reports a finding for
  `azure-key-vault-purge-protection-disabled`. That rule's passing
  branch is proven at the conformance-suite level instead
  (`tests/conformance/scenarios/azure_network_compute.yaml`).
* **No non-compliant Activity Log setting is created**, for the same
  reason `terraform/aws/` provisions only one CloudTrail trail. The
  failing branches of `rules/azure/monitor.yaml` are proven by the
  conformance suite and the collector unit tests.
* **Absence of a diagnostic setting cannot be detected.** A
  subscription with no Activity Log export at all produces no resource
  of that type, and therefore no finding — a per-resource rule engine
  cannot flag the absence of a resource. See
  `docs/architecture/phase-3-azure.md`.

No real data is ever stored in any storage account. No key, secret, or
certificate is created in either vault. The VMs run stock Ubuntu and
serve no workload — they exist purely to be scanned.

## Azure costs

Everything here is chosen to be cheap, but **not free**:

* 3 storage accounts: negligible while empty (billing is
  per-GB/per-operation).
* 3 network security groups + 1 virtual network + 2 subnets: free.
* 2 `Standard_B1s` VMs: **~$0.02/hour combined** while running — the
  main ongoing cost. Stop or destroy them when not actively scanning.
* 1 Standard public IP: **~$0.005/hour** while allocated.
* 2 Key Vaults: no standing charge while empty (billing is
  per-operation).
* 1 Activity Log diagnostic setting: free; the exported log data costs
  storage at standard rates (pennies for a short-lived environment).

Running `terraform destroy` as soon as you're done testing keeps this
to at most a few dollars. Do not leave the VMs running indefinitely.

## Credentials

No credentials are ever read from or written to any file in this
directory tree. Authentication is entirely external to Terraform, via
the `azurerm` provider's own credential chain — the same chain
`infrastructure/cloud/azure/session.py` uses for the actual scan
(`DefaultAzureCredential`: environment variables, a managed identity,
or `az login`). Run `az login` (or set the standard `ARM_*`/`AZURE_*`
environment variables) before `terraform apply`.

`admin_ssh_public_key` is a **public** key and has no default — supply
your own. Password authentication is disabled on both VMs, and no
private key or password is ever generated or stored by this
configuration.

## Deploying

```sh
cd terraform/azure/environments/test
az login
az account set --subscription <your-test-subscription-id>

terraform init
terraform validate
terraform plan -var="admin_ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"   # READ this output
terraform apply -var="admin_ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"
```

`terraform apply` will prompt for confirmation and show you the exact
non-compliant resources it's about to create (an internet-open NSG, a
publicly-accessible storage account, etc.) — read the plan, don't
rubber-stamp it.

## Destroying

```sh
cd terraform/azure/environments/test
terraform destroy -var="admin_ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"
```

Do this as soon as you're done scanning — see "Azure costs" above. If
anything is left behind, deleting the resource group removes every
resource this module created.

## State

`terraform.tfstate`/`terraform.tfstate.*`, `*.tfvars` (except
`*.tfvars.example`), and `.terraform/` are all `.gitignore`'d at the
repository root — never commit them. State can contain resource
attribute values; treat it as sensitive. This configuration uses local
state by design (it's a short-lived demo environment) — if you need it
to persist across machines or CI runs, add a remote backend block to
`environments/test/main.tf` yourself; none is provided here.

## After deploying: running an actual scan

See `docs/architecture/phase-3-azure.md` for the full command sequence
and `tests/integration/azure/conftest.py` for the exact environment
variables the opt-in integration suite expects.
