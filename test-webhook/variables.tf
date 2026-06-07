# Values go in webhook.auto.tfvars (gitignored). This file only DECLARES them.

variable "subscription_id" {
  type        = string
  description = "Test Azure subscription ID."
}

variable "tenant_id" {
  type        = string
  description = "Test Azure AD tenant ID."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group holding the Automation account."
}

variable "automation_account_name" {
  type        = string
  description = "Existing Automation account name."
}

variable "runbook_name" {
  type        = string
  description = "Existing runbook to attach the webhook to."
  default     = "Check-AzFwAccessControl-Webhook"
}

variable "webhook_name" {
  type        = string
  description = "Name for the new webhook."
  default     = "Check-AzFwAccessControl-hook"
}

variable "expiry_time" {
  type        = string
  description = "RFC3339 expiry time for the webhook URL."
  default     = "2030-01-01T00:00:00Z"
}
