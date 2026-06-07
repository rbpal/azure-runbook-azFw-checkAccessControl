variable "name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "runbook_name" {
  type = string
}

variable "runbook_content" {
  type        = string
  description = "PowerShell runbook content (read from file by the root module)."
}

variable "reader_scope_id" {
  type        = string
  description = "Resource ID the SAMI gets the built-in Reader role on (the resource group)."
}

variable "create_webhook" {
  type        = bool
  default     = true
  description = "Also deploy the webhook-triggered runbook variant + its webhook."
}

variable "webhook_runbook_content" {
  type        = string
  default     = ""
  description = "PowerShell content for the webhook runbook variant."
}

variable "webhook_expiry" {
  type        = string
  default     = "2030-01-01T00:00:00Z"
  description = "RFC3339 expiry time for the webhook URL."
}

variable "tags" {
  type    = map(string)
  default = {}
}
