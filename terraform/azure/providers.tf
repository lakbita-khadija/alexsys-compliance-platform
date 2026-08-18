provider "azurerm" {
  features {
    key_vault {
      # Allow `terraform destroy` to actually remove the test vaults
      # rather than leaving soft-deleted shells behind that block
      # re-applying with the same names. This is appropriate ONLY
      # because this is a disposable test environment — see README.md.
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = false
    }
  }
}
