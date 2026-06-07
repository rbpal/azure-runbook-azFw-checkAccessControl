# Root composes MODULES only — no bare resources. (Kit rule.)
# Deliberately NO firewall module: we do not create an Azure Firewall (cost + scope).

module "resource_group" {
  source   = "./modules/resource_group"
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# IP groups (separate Azure resources the rules reference by ID).
module "ip_group_onprem" {
  source              = "./modules/ip_group"
  name                = "ipg-onprem"
  location            = var.location
  resource_group_name = module.resource_group.name
  cidrs               = ["10.50.0.0/16", "192.168.100.0/24"]
  tags                = var.tags
}

module "ip_group_appclients" {
  source              = "./modules/ip_group"
  name                = "ipg-appclients"
  location            = var.location
  resource_group_name = module.resource_group.name
  cidrs               = ["10.60.0.0/16"]
  tags                = var.tags
}

module "firewall_policy" {
  source              = "./modules/firewall_policy"
  name                = var.firewall_policy_name
  location            = var.location
  resource_group_name = module.resource_group.name
  sku                 = var.firewall_policy_sku
  create_seed_rules   = var.create_seed_rules
  seed_url_rules      = var.seed_url_rules

  # IP groups referenced by seed rules (network = destination, application = source).
  network_dest_ip_group_id = module.ip_group_onprem.id
  app_source_ip_group_id   = module.ip_group_appclients.id

  tags = var.tags
}

module "automation_account" {
  source              = "./modules/automation_account"
  name                = var.automation_account_name
  location            = var.location
  resource_group_name = module.resource_group.name
  runbook_name        = var.runbook_name
  runbook_content     = file("${path.module}/../runbooks/Check-AzFwAccessControl.ps1")

  # Optional webhook-triggered variant.
  create_webhook          = var.create_webhook
  webhook_runbook_content = var.create_webhook ? file("${path.module}/../runbooks/Check-AzFwAccessControl-Webhook.ps1") : ""
  webhook_expiry          = var.webhook_expiry

  # SAMI gets Reader on the RG so the runbook can read the policy + IP groups.
  reader_scope_id = module.resource_group.id

  tags = var.tags
}
