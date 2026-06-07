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

variable "tags" {
  type    = map(string)
  default = {}
}
