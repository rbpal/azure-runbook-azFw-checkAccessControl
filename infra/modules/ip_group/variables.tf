variable "name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "cidrs" {
  type        = list(string)
  description = "Member IP prefixes (CIDR) of the IP group."
}

variable "tags" {
  type    = map(string)
  default = {}
}
