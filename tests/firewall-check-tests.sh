#!/usr/bin/env bash
# ============================================================================
#  Azure Firewall Policy access-control — 14 copy-paste test commands
# ----------------------------------------------------------------------------
#  Runbook:  Check-AzFwAccessControl   (Automation account: ac-runbook-azfw)
#  Subscription / ResourceGroup / FirewallPolicyName are DEFAULTED in the
#  runbook, so each test only supplies the flow: SourceIp Destination Protocol Port.
#
#  Usage:  az login            # once
#          bash tests/firewall-check-tests.sh        # run all 14
#     or:  paste the check_flow() helper, then copy individual lines below.
# ============================================================================

set -uo pipefail
AA=ac-runbook-azfw
RG=rg-runbook-rbpal
RB=Check-AzFwAccessControl

# --- helper: start a cloud job, wait, print the output ----------------------
check_flow () {
  local label="$1" sip="$2" dst="$3" proto="$4" port="$5" j
  j=$(az automation runbook start \
        --automation-account-name "$AA" -g "$RG" -n "$RB" \
        --parameters SourceIp="$sip" Destination="$dst" Protocol="$proto" DestinationPort="$port" \
        --query id -o tsv)
  printf '\n=== %s : %s -> %s %s/%s ===\n' "$label" "$sip" "$dst" "$proto" "$port"
  printf 'waiting'
  until [ "$(az rest --method get \
        --url "https://management.azure.com${j}?api-version=2019-06-01" \
        --query properties.status -o tsv)" = "Completed" ]; do printf '.'; sleep 5; done
  echo
  az rest --method get \
        --url "https://management.azure.com${j}/output?api-version=2019-06-01" \
        --headers "Accept=text/plain" -o tsv | grep -E "VERDICT|matched:"
}

# ── DNAT (matches the ORIGINAL / pre-NAT destination: public IP + original port)
check_flow "D1 DNAT rdp"        10.20.5.7    20.50.60.70                   TCP   3389   # expect ALLOWED  (dnat-rdp)
check_flow "D2 DNAT https"      203.0.113.9  20.50.60.71                   TCP   8443   # expect ALLOWED  (dnat-https)
check_flow "D3 DNAT wrong port" 10.20.5.7    20.50.60.71                   TCP   443    # expect ACCESS DENIED (443 = translated port)

# ── Network (CIDR containment + port range + IP group)
check_flow "N1 net cidr"        10.20.5.7    10.30.1.4                     TCP   443    # expect ALLOWED  (allow-web-cidr)
check_flow "N2 net port-range"  10.20.5.7    10.30.1.4                     TCP   8080   # expect ALLOWED  (8080 in 8000-8100)
check_flow "N3 net sql cidr"    10.21.9.9    10.31.5.20                    TCP   1433   # expect ALLOWED  (allow-sql-cidr)
check_flow "N4 net ip-group"    10.20.5.7    10.50.7.7                     TCP   443    # expect ALLOWED  (allow-onprem-ipgroup)
check_flow "N5 net bad source"  10.99.0.1    10.30.1.4                     TCP   443    # expect ACCESS DENIED (source not in any rule)
check_flow "N6 net bad port"    10.20.5.7    10.30.1.4                     TCP   9000   # expect ACCESS DENIED (port out of range)

# ── Application (destination is an FQDN, not an IP)
check_flow "A1 app wildcard"    10.20.5.7    api.azure.com                 HTTPS 443    # expect ALLOWED  (allow-azure-wild, *.azure.com)
check_flow "A2 app exact fqdn"  10.20.5.7    api.github.com                HTTPS 443    # expect ALLOWED  (allow-github-fqdn)
check_flow "A3 app mssql"       10.20.5.7    myserver.database.windows.net MSSQL 1433   # expect ALLOWED  (allow-sql-outbound)
check_flow "A4 app src ip-group" 10.60.1.9   cdn.azureedge.net             HTTPS 443    # expect ALLOWED  (allow-appclients-ipgroup)
check_flow "A5 app not covered" 10.20.5.7    www.google.com                HTTPS 443    # expect ACCESS DENIED (no rule covers FQDN)

# ── Input-validation edge cases (optional)
check_flow "V1 ipv6"            2001:db8::1  10.30.1.4                     TCP   443    # expect INPUT_ERROR (IPv6 unsupported in v1)
check_flow "V2 malformed ip"    10.20.300.5  10.30.1.4                     TCP   443    # expect INPUT_ERROR (octet > 255)
