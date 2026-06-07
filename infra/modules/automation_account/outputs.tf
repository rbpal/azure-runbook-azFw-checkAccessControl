output "automation_account_name" {
  value = azurerm_automation_account.this.name
}

output "identity_principal_id" {
  value = azurerm_automation_account.this.identity[0].principal_id
}

output "runbook_name" {
  value = azurerm_automation_runbook.this.name
}

output "webhook_uri" {
  description = "Secret webhook URL (populated only on first apply). Treat as a credential."
  value       = try(azurerm_automation_webhook.this[0].uri, null)
  sensitive   = true
}
