# Demo — exact, reproducible commands (one paste = proof)

A check answers: **"Is this flow allowed by the Azure Firewall Policy?"** across DNAT, network, and
application rule collections. `Subscription / ResourceGroup / FirewallPolicyName` are defaulted in the
runbook, so a demo only needs the **flow**: source IP, destination (IP or FQDN), protocol, port.

## Prereqs

```bash
az login                                  # sign in (tenant: Default Directory)
az account show --query name -o tsv       # confirm the right subscription
# Resources already deployed: rg-runbook-rbpal / ac-runbook-azfw / Check-AzFwAccessControl
```

## Option A — cloud job from the CLI (recommended for the demo)

Paste this helper once, then call `check_flow` for each scenario:

```bash
check_flow () {
  local j
  j=$(az automation runbook start \
        --automation-account-name ac-runbook-azfw -g rg-runbook-rbpal \
        -n Check-AzFwAccessControl \
        --parameters SourceIp="$1" Destination="$2" Protocol="$3" DestinationPort="$4" \
        --query id -o tsv)
  printf 'job started, waiting'
  until [ "$(az rest --method get \
        --url "https://management.azure.com${j}?api-version=2019-06-01" \
        --query properties.status -o tsv)" = "Completed" ]; do printf '.'; sleep 5; done
  echo; echo "----------------------------------------"
  az rest --method get \
        --url "https://management.azure.com${j}/output?api-version=2019-06-01" \
        --headers "Accept=text/plain" -o tsv
}
```

### Demo scenarios

```bash
# ── ALLOWED — one per collection ───────────────────────────────
check_flow 10.20.5.7  10.30.1.4                     TCP   443    # network  → allow-web-cidr
check_flow 10.20.5.7  20.50.60.70                   TCP   3389   # DNAT     → dnat-rdp (pre-NAT dest)
check_flow 10.20.5.7  api.azure.com                 HTTPS 443    # app      → allow-azure-wild (*.azure.com)
check_flow 10.20.5.7  myserver.database.windows.net MSSQL 1433   # app      → allow-sql-outbound (SQL egress)
check_flow 10.20.5.7  10.50.7.7                     TCP   443    # network  → allow-onprem-ipgroup (IP group)

# ── ACCESS DENIED — the negative proof ─────────────────────────
check_flow 10.99.0.1  10.30.1.4                      TCP   443    # source not in any rule
check_flow 10.20.5.7  10.30.1.4                      TCP   9000   # port outside 443 / 8000-8100
check_flow 10.20.5.7  www.google.com                HTTPS 443    # FQDN not covered
```

## Option B — portal (visual)

`ac-runbook-azfw` → **Runbooks** → `Check-AzFwAccessControl` → **Start** → fill SourceIp / Destination /
Protocol / DestinationPort (leave the three context fields blank) → **OK** → open the job → **Output** tab.

## Option C — run locally (fast, no cloud job)

Uses your `az`/`Connect-AzAccount` session instead of the managed identity. Requires `Az.Accounts` +
`Az.Network` installed locally.

```bash
pwsh -File ./runbooks/Check-AzFwAccessControl.ps1 -UseManagedIdentity:$false \
     -SourceIp 10.20.5.7 -Destination 10.30.1.4 -Protocol TCP -DestinationPort 443
```

## Expected output (shape)

```text
Policy 'rg-runbook-azfw-pol' has 1 rule collection group(s).
VERDICT: ALLOWED
  matched: rg-runbook-azfw-pol / seed-net / rule 'allow-web-cidr' [NetworkRule, Allow]
{ "verdict": "ALLOWED", "input": {...}, "provenance": { "rule": "allow-web-cidr", ... }, "notes": [...] }
```

`ACCESS DENIED (implicit)` means no allow rule matched — Azure Firewall's default deny.
