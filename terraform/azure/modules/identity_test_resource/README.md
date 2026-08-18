# STEP 8C — Azure identity / RBAC test fixture

Creates the minimum estate that exercises ComplianceIQ's Azure RBAC
collectors end to end:

```
user-assigned managed identity          (the principal)
   ├── Owner  @ /subscriptions/{guid}   (privileged  — the rule FIRES)
   └── Reader @ resource group          (control case — the rule is SILENT)
```

Two assignments, not one. A rule that fired on every assignment would
look correct against a single privileged fixture; the Reader-at-resource-
group pair is what proves both halves of the rule's condition are doing
work.

---

## ⚠️ Read this before applying

**This module grants Owner on your entire subscription.**

Every other module in `terraform/azure/` creates resources inside one
test resource group, so the worst case is a stray resource. This one
reaches outside that boundary by design — subscription scope is exactly
what the rule under test detects, and a fixture scoped to a resource
group would not exercise it.

Consequences, stated plainly:

- The managed identity can read, modify and delete **anything** in the
  subscription, including the diagnostic settings that would record the
  change and the role assignments that would revoke its own access.
- It is a standing, permanent assignment — not time-bound, not
  approval-gated.
- **Do not apply this in a production subscription.** Use a disposable
  or sandbox subscription.

It is therefore **opt-in**. `terraform apply` on the existing
environment will not create it unless you pass the flag.

---

## Required permissions

| Operation | Permission |
|---|---|
| Create the managed identity | `Microsoft.ManagedIdentity/userAssignedIdentities/write` on the resource group |
| Create both role assignments | `Microsoft.Authorization/roleAssignments/write` on the **subscription** |
| Read the built-in role definitions | `Microsoft.Authorization/roleDefinitions/read` |

In practice: **Owner** or **User Access Administrator** on the
subscription. Contributor is *not* enough — it deliberately excludes
`roleAssignments/write`, which is the whole point of this fixture.

The scanner itself needs far less: `Microsoft.Authorization/*/read`,
which the built-in **Reader** role already includes.

---

## Cost

**No billable resource.** User-assigned managed identities and role
assignments are both free in Azure.

The cost of this fixture is **blast radius, not money** — see the
warning above. That is the reason to destroy it, and neither
`terraform plan` nor a billing alert will remind you.

---

## Usage

```bash
cd terraform/azure

terraform init

# Review — confirm the Owner assignment's scope is the subscription you
# intend, and that it is a subscription you are willing to expose.
terraform plan -var="enable_identity_rbac_fixture=true"

terraform apply -var="enable_identity_rbac_fixture=true"
```

### Outputs

```bash
terraform output identity_principal_id              # Entra object id
terraform output identity_role_assignment_id        # privileged assignment
terraform output identity_role_definition_id        # Owner role definition
terraform output identity_assignment_scope          # /subscriptions/{guid}
terraform output identity_benign_role_assignment_id # control case
terraform output subscription_id
```

`identity_principal_id` is the **Entra object id** — the value the
scanner records as the principal's identity. It is *not* the managed
identity's ARM resource id; `identity_principal_resource_id` on the
module carries that separately, because conflating the two is a common
and confusing mistake.

---

## Cleanup

```bash
terraform destroy -var="enable_identity_rbac_fixture=true"
```

**Destroy this as soon as the verification run is done.** The flag must
be passed to `destroy` as well — without it Terraform plans zero
instances of the module and will not remove what a previous apply
created.

Verify the subscription-scope assignment is actually gone:

```bash
az role assignment list \
  --scope "/subscriptions/$(terraform output -raw subscription_id)" \
  --query "[?principalId=='$(terraform output -raw identity_principal_id)']"
```

An empty result is what you want. Deleting the managed identity alone
does **not** always remove its role assignments — Azure can leave an
orphaned assignment pointing at a dead object id, which then shows up
in a scan as an assignment whose principal cannot be resolved.

That orphan case is, incidentally, a real-world source of exactly the
unenumerated-principal condition the collectors are built to report as
INDETERMINATE rather than as a clean answer.
