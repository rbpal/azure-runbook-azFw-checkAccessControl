# All VALUES live in infra.auto.tfvars (gitignored). This file only DECLARES them.

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID to deploy into (required by azurerm v4)."
}

variable "tenant_id" {
  type        = string
  description = "Azure AD tenant ID."
}

variable "location" {
  type        = string
  description = "Azure region for all resources (set in *.auto.tfvars)."
}

variable "resource_group_name" {
  type        = string
  description = "Name of the resource group to create."
}

variable "firewall_policy_name" {
  type        = string
  description = "Name of the Azure Firewall Policy to create (NOT a firewall)."
}

variable "firewall_policy_sku" {
  type        = string
  description = "Firewall Policy SKU. Standard is free when not attached to a firewall."
  default     = "Standard"

  validation {
    condition     = contains(["Standard", "Premium", "Basic"], var.firewall_policy_sku)
    error_message = "firewall_policy_sku must be Standard, Premium, or Basic."
  }
}

variable "create_seed_rules" {
  type        = bool
  description = "Create a seed rule collection group (network + application allow rules) so the runbook is immediately testable."
  default     = true
}

variable "seed_url_rules" {
  type        = bool
  description = "Add URL-based application rules (needs Premium SKU + TLS inspection — not built here)."
  default     = false
}

variable "automation_account_name" {
  type        = string
  description = "Name of the Automation account (system-assigned managed identity)."
}

variable "runbook_name" {
  type        = string
  description = "Name of the PowerShell runbook deployed into the Automation account."
  default     = "Check-AzFwAccessControl"
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources."
  default     = {}
}
