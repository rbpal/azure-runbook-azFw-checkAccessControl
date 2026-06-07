variable "name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "sku" {
  type    = string
  default = "Standard"
}

variable "create_seed_rules" {
  type    = bool
  default = true
}

variable "seed_url_rules" {
  type        = bool
  default     = false
  description = "Add URL-based application rules. Requires Premium SKU + TLS inspection (Key Vault CA cert), not built here."
}

variable "network_dest_ip_group_id" {
  type        = string
  default     = null
  description = "IP group ID referenced as a DESTINATION in a seed network rule."
}

variable "app_source_ip_group_id" {
  type        = string
  default     = null
  description = "IP group ID referenced as a SOURCE in a seed application rule."
}

variable "tags" {
  type    = map(string)
  default = {}
}
