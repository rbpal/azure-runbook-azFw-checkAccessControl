resource "azurerm_ip_group" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  cidrs               = var.cidrs
  tags                = var.tags
}
