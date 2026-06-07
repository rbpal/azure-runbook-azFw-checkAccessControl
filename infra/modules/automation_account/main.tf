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

# ── Optional: webhook-triggered variant (gated by create_webhook) ──────────
# A second runbook that reads the flow from an HTTP POST body, plus a webhook
# that exposes a secret URL. The URL is a sensitive output (shown once, on create).
resource "azurerm_automation_runbook" "webhook" {
  count                   = var.create_webhook ? 1 : 0
  name                    = "${var.runbook_name}-Webhook"
  location                = var.location
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.this.name
  log_verbose             = true
  log_progress            = true
  description             = "Webhook-triggered variant: reads the flow from the HTTP request body. Read-only."
  runbook_type            = "PowerShell"
  content                 = var.webhook_runbook_content
  tags                    = var.tags
}

resource "azurerm_automation_webhook" "this" {
  count                   = var.create_webhook ? 1 : 0
  name                    = "${var.runbook_name}-hook"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.this.name
  expiry_time             = var.webhook_expiry
  enabled                 = true
  runbook_name            = azurerm_automation_runbook.webhook[0].name
}
