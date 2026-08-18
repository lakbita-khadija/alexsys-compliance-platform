# Activity Log diagnostic setting. The Azure counterpart of
# ../../../aws/modules/cloudtrail_test_resource, and it carries the
# same single-resource limitation for the same reason: Azure allows a
# limited number of subscription diagnostic settings, and provisioning
# a deliberately-broken second one purely for a demo was judged not
# worth the complexity. Only the compliant configuration is
# provisioned; the failing branches of rules/azure/monitor.yaml are
# proven at the conformance-suite level
# (tests/conformance/scenarios/azure_network_compute.yaml) and at the
# unit-test level
# (tests/unit/infrastructure/test_azure_monitor_collector.py).
#
# This setting is what makes the ACCESSES relationship
# (azure_activity_log_setting -> azure_storage_account) real in a
# deployed environment, so the two cross-resource rules in
# rules/azure/monitor.yaml have genuine graph data to evaluate.

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name               = "${var.name_prefix}-activity-log"
  target_resource_id = "/subscriptions/${var.subscription_id}"
  storage_account_id = var.storage_account_id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "Policy"
  }
}
