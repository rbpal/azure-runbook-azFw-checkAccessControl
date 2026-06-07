#!/usr/bin/env bash
# ============================================================================
#  Trigger the firewall access-control runbook via its WEBHOOK, then read the
#  verdict. Different from firewall-check-tests.sh (which uses the start-job API):
#  here every check is an HTTP POST to the secret webhook URL.
#
#  The webhook is FIRE-AND-FORGET: the POST returns a JobId (HTTP 202), not the
#  verdict — so we poll that job's output afterwards.
#
#  Usage:
#    export WEBHOOK_URI="https://<region>.webhook.azure-automation.net/webhooks?token=..."
#    az login                       # needed only to READ the job output
#    bash tests/webhook-check-tests.sh
#  (If WEBHOOK_URI is unset, it tries:  terraform -chdir=infra output -raw webhook_uri)
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WEBHOOK_URI="${WEBHOOK_URI:-$(terraform -chdir="$HERE/../infra" output -raw webhook_uri 2>/dev/null)}"
if [ -z "${WEBHOOK_URI:-}" ]; then
  echo "Set WEBHOOK_URI to the webhook URL (or run where 'terraform output webhook_uri' works)." >&2
  exit 1
fi
RG="${RG:-rg-runbook-rbpal}"
AA="${AA:-ac-runbook-azfw}"
SUB="${SUB:-$(az account show --query id -o tsv 2>/dev/null)}"

# webhook_check <label> <srcIp> <dst> <proto> <port>
webhook_check () {
  local label="$1" body resp jid jurl st
  body=$(printf '{"SourceIp":"%s","Destination":"%s","Protocol":"%s","Port":%s}' "$2" "$3" "$4" "$5")
  resp=$(curl -s -X POST "$WEBHOOK_URI" -H 'Content-Type: application/json' -d "$body")
  jid=$(printf '%s' "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin)['JobIds'][0])" 2>/dev/null)
  if [ -z "$jid" ]; then echo "=== $label === webhook POST failed: $resp"; echo; return; fi
  jurl="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AA/jobs/$jid"
  for _ in $(seq 1 40); do
    st=$(az rest --method get --url "$jurl?api-version=2019-06-01" --query properties.status -o tsv 2>/dev/null)
    case "$st" in Completed | Failed | Suspended) break ;; esac
    sleep 4
  done
  echo "=== $label  [job=$st]  (JobId $jid) ==="
  az rest --method get --url "$jurl/output?api-version=2019-06-01" --headers "Accept=text/plain" -o tsv 2>/dev/null | grep -E "VERDICT|matched:|via:"
  echo
}

# DNAT -> Network -> Application, plus a deny — all triggered via the webhook
webhook_check "D1 DNAT (pre-NAT 3389)"   10.20.5.7 20.50.60.70   TCP   3389  # expect ALLOWED  (dnat-rdp)
webhook_check "N1 Network CIDR"          10.20.5.7 10.30.1.4     TCP   443   # expect ALLOWED  (allow-web-cidr)
webhook_check "N4 Network IP-group"      10.20.5.7 10.50.7.7     TCP   443   # expect ALLOWED  (allow-onprem-ipgroup)
webhook_check "A1 Application wildcard"  10.20.5.7 api.azure.com HTTPS 443   # expect ALLOWED  (allow-azure-wild)
webhook_check "X1 Denied"                10.99.0.1 10.30.1.4     TCP   443   # expect ACCESS DENIED
