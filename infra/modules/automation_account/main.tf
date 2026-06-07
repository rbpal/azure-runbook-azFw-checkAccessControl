# Automation account with a SYSTEM-ASSIGNED managed identity (keyless),
# the PowerShell runbook, and a Reader role assignment so the SAMI can read the policy.

resource "azurerm_automation_account" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = "Basic"

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

resource "azurerm_automation_runbook" "this" {
  name                    = var.runbook_name
  location                = var.location
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.this.name
  log_verbose             = true
  log_progress            = true
  description             = "Checks whether a flow is ALLOWED by an Azure Firewall Policy (DNAT/network/application). Read-only."
  runbook_type            = "PowerShell"
  content                 = var.runbook_content
  tags                    = var.tags
}

# Least privilege: Reader on the resource group (covers the policy and any IP groups in it).
resource "azurerm_role_assignment" "reader" {
  scope                = var.reader_scope_id
  role_definition_name = "Reader"
  principal_id         = azurerm_automation_account.this.identity[0].principal_id
}
