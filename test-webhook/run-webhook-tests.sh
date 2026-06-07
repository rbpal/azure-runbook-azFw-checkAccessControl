#!/usr/bin/env bash
# Self-contained webhook tester bundled with test-webhook/. Sends a set of flows to the webhook
# (DNAT -> Network -> Application + a deny) and reads the verdict for each.
# Fire-and-forget: each POST returns a JobId; we then poll that job's output.
#
# Run from inside test-webhook/ (reads the URL from `terraform output -raw webhook_uri`):
#   az login
#   bash run-webhook-tests.sh
# Override the account/RG via env vars if yours differ:  AA=... RG=... bash run-webhook-tests.sh
set -uo pipefail

WEBHOOK_URI="${WEBHOOK_URI:-$(terraform output -raw webhook_uri 2>/dev/null)}"
[ -z "${WEBHOOK_URI:-}" ] && {
  echo "Set WEBHOOK_URI (or run where 'terraform output webhook_uri' works)." >&2
  exit 1
}
RG="${RG:-rg-runbook-rbpal}"
AA="${AA:-ac-runbook-azfw}"
SUB="${SUB:-$(az account show --query id -o tsv 2>/dev/null)}"

webhook_check () {  # label sip dst proto port
  local label="$1" body resp jid jurl st
  body=$(printf '{"SourceIp":"%s","Destination":"%s","Protocol":"%s","Port":%s}' "$2" "$3" "$4" "$5")
  resp=$(curl -s -X POST "$WEBHOOK_URI" -H 'Content-Type: application/json' -d "$body")
  jid=$(printf '%s' "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin)['JobIds'][0])" 2>/dev/null)
  if [ -z "$jid" ]; then echo "=== $label === POST failed: $resp"; echo; return; fi
  jurl="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AA/jobs/$jid"
  for _ in $(seq 1 40); do
    st=$(az rest --method get --url "$jurl?api-version=2019-06-01" --query properties.status -o tsv 2>/dev/null)
    case "$st" in Completed | Failed | Suspended) break ;; esac
    sleep 4
  done
  echo "=== $label  [job=$st] ==="
  az rest --method get --url "$jurl/output?api-version=2019-06-01" --headers "Accept=text/plain" -o tsv 2>/dev/null | grep -E "VERDICT|matched:|via:"
  echo
}

webhook_check "DNAT (pre-NAT 3389)"  10.20.5.7 20.50.60.70   TCP   3389  # expect ALLOWED
webhook_check "Network CIDR"         10.20.5.7 10.30.1.4     TCP   443   # expect ALLOWED
webhook_check "Network IP-group"     10.20.5.7 10.50.7.7     TCP   443   # expect ALLOWED
webhook_check "Application wildcard" 10.20.5.7 api.azure.com HTTPS 443   # expect ALLOWED
webhook_check "Denied"               10.99.0.1 10.30.1.4     TCP   443   # expect ACCESS DENIED
