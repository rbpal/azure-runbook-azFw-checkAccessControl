output "webhook_uri" {
  description = "Secret webhook URL — shown ONLY on first apply (Azure never re-displays it). Treat as a credential."
  value       = azurerm_automation_webhook.this.uri
  sensitive   = true
}
