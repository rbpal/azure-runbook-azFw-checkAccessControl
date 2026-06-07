# Creates an Azure Firewall POLICY only (no firewall). Standard SKU is free when unattached.
# DNS proxy is enabled because FQDN-based NETWORK rules require it on the policy.

resource "azurerm_firewall_policy" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = var.sku
  tags                = var.tags

  dns {
    proxy_enabled = true
  }
}

# ---------------------------------------------------------------------------
# Seed (fictitious) test data so the runbook is immediately verifiable.
# Toggle off with create_seed_rules = false.
#   * DNAT          : CIDR source -> original (pre-NAT) public dest, translated target
#   * Network       : CIDR src/dst rules + an FQDN-destination network rule
#   * Application   : wildcard FQDNs, plain FQDNs, and an FQDN tag
# URL-based app rules are separate (var.seed_url_rules) — they need Premium + TLS inspection.
# ---------------------------------------------------------------------------
resource "azurerm_firewall_policy_rule_collection_group" "seed" {
  count              = var.create_seed_rules ? 1 : 0
  name               = "seed-rcg"
  firewall_policy_id = azurerm_firewall_policy.this.id
  priority           = 300

  # ---- DNAT ----------------------------------------------------------------
  nat_rule_collection {
    name     = "seed-dnat"
    priority = 200
    action   = "Dnat"

    rule {
      name                = "dnat-rdp"
      protocols           = ["TCP"]
      source_addresses    = ["10.20.0.0/16"]
      destination_address = "20.50.60.70" # original / pre-NAT public IP
      destination_ports   = ["3389"]
      translated_address  = "10.30.0.10"
      translated_port     = "3389"
    }

    rule {
      name                = "dnat-https"
      protocols           = ["TCP"]
      source_addresses    = ["0.0.0.0/0"]
      destination_address = "20.50.60.71"
      destination_ports   = ["8443"]
      translated_address  = "10.30.0.20"
      translated_port     = "443"
    }
  }

  # ---- Network -------------------------------------------------------------
  network_rule_collection {
    name     = "seed-net"
    priority = 400
    action   = "Allow"

    # CIDR source + CIDR destination
    rule {
      name                  = "allow-web-cidr"
      protocols             = ["TCP"]
      source_addresses      = ["10.20.0.0/16"]
      destination_addresses = ["10.30.0.0/16"]
      destination_ports     = ["443", "8000-8100"]
    }

    rule {
      name                  = "allow-sql-cidr"
      protocols             = ["TCP"]
      source_addresses      = ["10.21.0.0/16"]
      destination_addresses = ["10.31.5.0/24"]
      destination_ports     = ["1433"]
    }

    rule {
      name                  = "allow-dns-cidr"
      protocols             = ["UDP"]
      source_addresses      = ["10.20.0.0/16"]
      destination_addresses = ["168.63.129.16/32"]
      destination_ports     = ["53"]
    }

    # FQDN destination in a NETWORK rule (requires DNS proxy, enabled above).
    # NOTE: network rules require EXACT FQDNs — no wildcards (wildcards are application-rule only).
    rule {
      name              = "allow-storage-fqdn"
      protocols         = ["TCP"]
      source_addresses  = ["10.20.0.0/16"]
      destination_fqdns = ["blob.core.windows.net", "myserver.database.windows.net"]
      destination_ports = ["443"]
    }

    rule {
      name              = "allow-vendor-fqdn"
      protocols         = ["TCP"]
      source_addresses  = ["10.20.0.0/16"]
      destination_fqdns = ["microsoft.com", "oracle.com"]
      destination_ports = ["443"]
    }

    # IP GROUP referenced as a DESTINATION in a network rule
    dynamic "rule" {
      for_each = var.network_dest_ip_group_id != null ? [1] : []
      content {
        name                  = "allow-onprem-ipgroup"
        protocols             = ["TCP"]
        source_addresses      = ["10.20.0.0/16"]
        destination_ip_groups = [var.network_dest_ip_group_id]
        destination_ports     = ["443"]
      }
    }
  }

  # ---- Application ---------------------------------------------------------
  application_rule_collection {
    name     = "seed-app"
    priority = 500
    action   = "Allow"

    # Wildcard FQDNs
    rule {
      name              = "allow-azure-wild"
      source_addresses  = ["10.20.0.0/16"]
      destination_fqdns = ["*.azure.com", "*.microsoftonline.com"]
      protocols {
        type = "Https"
        port = 443
      }
      protocols {
        type = "Http"
        port = 80
      }
    }

    rule {
      name              = "allow-ubuntu-wild"
      source_addresses  = ["10.21.0.0/16"]
      destination_fqdns = ["*.ubuntu.com"]
      protocols {
        type = "Http"
        port = 80
      }
      protocols {
        type = "Https"
        port = 443
      }
    }

    # Plain (non-wildcard) FQDNs
    rule {
      name              = "allow-github-fqdn"
      source_addresses  = ["10.20.0.0/16"]
      destination_fqdns = ["github.com", "api.github.com"]
      protocols {
        type = "Https"
        port = 443
      }
    }

    # FQDN tag (Microsoft-curated set)
    rule {
      name                  = "allow-windowsupdate-tag"
      source_addresses      = ["10.20.0.0/16"]
      destination_fqdn_tags = ["WindowsUpdate"]
      protocols {
        type = "Https"
        port = 443
      }
    }

    # SQL outbound — Azure Firewall application-rule MSSQL protocol (e.g. Azure SQL DB)
    rule {
      name              = "allow-sql-outbound"
      source_addresses  = ["10.20.0.0/16"]
      destination_fqdns = ["*.database.windows.net", "myserver.database.windows.net"]
      protocols {
        type = "Mssql"
        port = 1433
      }
    }

    # IP GROUP referenced as a SOURCE in an application rule
    dynamic "rule" {
      for_each = var.app_source_ip_group_id != null ? [1] : []
      content {
        name              = "allow-appclients-ipgroup"
        source_ip_groups  = [var.app_source_ip_group_id]
        destination_fqdns = ["*.azureedge.net"]
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }

  # ---- Application: URL rules (OPT-IN) -------------------------------------
  # destination_urls require terminate_tls = true -> TLS inspection -> PREMIUM policy
  # + a CA certificate in Key Vault (not built here). Enable only after that exists.
  dynamic "application_rule_collection" {
    for_each = var.seed_url_rules ? [1] : []
    content {
      name     = "seed-app-urls"
      priority = 600
      action   = "Allow"

      rule {
        name             = "allow-contoso-urls"
        source_addresses = ["10.21.0.0/16"]
        destination_urls = ["www.contoso.com/news", "docs.contoso.com/*"]
        terminate_tls    = true
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }
}
