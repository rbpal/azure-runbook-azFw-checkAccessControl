output "resource_group_name" {
  value = module.resource_group.name
}

output "firewall_policy_id" {
  value = module.firewall_policy.id
}

output "firewall_policy_name" {
  value = module.firewall_policy.name
}

output "automation_account_name" {
  value = module.automation_account.automation_account_name
}

output "automation_identity_principal_id" {
  description = "SAMI principal ID (granted Reader on the RG)."
  value       = module.automation_account.identity_principal_id
}

output "runbook_name" {
  value = module.automation_account.runbook_name
}

output "webhook_uri" {
  description = "Secret webhook URL (only populated on first apply). Treat as a credential."
  value       = module.automation_account.webhook_uri
  sensitive   = true
}
