provider "azurerm" {
  features {}

  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}

# Creates a WEBHOOK on an EXISTING runbook in an EXISTING Automation account.
# Prerequisite: the runbook (var.runbook_name) and the Automation account already
# exist in your test subscription. This config does NOT create them.
resource "azurerm_automation_webhook" "this" {
  name                    = var.webhook_name
  resource_group_name     = var.resource_group_name
  automation_account_name = var.automation_account_name
  runbook_name            = var.runbook_name
  expiry_time             = var.expiry_time
  enabled                 = true
}
