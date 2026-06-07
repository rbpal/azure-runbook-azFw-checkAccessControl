<#
.SYNOPSIS
  Trigger the firewall access-control runbook via its WEBHOOK and read the verdict.
  Different from firewall-check-tests.ps1 (which uses Start-AzAutomationRunbook):
  here every check is an HTTP POST to the secret webhook URL.

.DESCRIPTION
  The webhook is FIRE-AND-FORGET: the POST returns a JobId (HTTP 202), not the verdict,
  so we poll that job's output afterwards.

  Usage:
    $env:WEBHOOK_URI = "https://<region>.webhook.azure-automation.net/webhooks?token=..."
    Connect-AzAccount            # needed only to READ the job output
    ./tests/webhook-check-tests.ps1
  (If -WebhookUri / $env:WEBHOOK_URI is unset, it tries: terraform -chdir=infra output -raw webhook_uri)
#>
param(
  [string] $WebhookUri       = $env:WEBHOOK_URI,
  [string] $ResourceGroup    = 'rg-runbook-rbpal',
  [string] $AutomationAccount = 'ac-runbook-azfw'
)

if (-not $WebhookUri) {
  try { $WebhookUri = (terraform -chdir="$PSScriptRoot/../infra" output -raw webhook_uri 2>$null) } catch {}
}
if (-not $WebhookUri) { throw "Set -WebhookUri or `$env:WEBHOOK_URI to the webhook URL." }

function Invoke-WebhookCheck {
  param(
    [Parameter(Mandatory)] [string] $Label,
    [Parameter(Mandatory)] [string] $SourceIp,
    [Parameter(Mandatory)] [string] $Destination,
    [Parameter(Mandatory)] [string] $Protocol,
    [Parameter(Mandatory)] [int]    $Port
  )
  $body = @{ SourceIp = $SourceIp; Destination = $Destination; Protocol = $Protocol; Port = $Port } | ConvertTo-Json -Compress
  $resp = Invoke-RestMethod -Method Post -Uri $WebhookUri -ContentType 'application/json' -Body $body
  $jobId = $resp.JobIds[0]
  do {
    Start-Sleep -Seconds 5
    $job = Get-AzAutomationJob -Id $jobId -AutomationAccountName $AutomationAccount -ResourceGroupName $ResourceGroup
  } while ($job.Status -notin 'Completed', 'Failed', 'Suspended', 'Stopped')

  $out = Get-AzAutomationJobOutput -Id $jobId -AutomationAccountName $AutomationAccount -ResourceGroupName $ResourceGroup -Stream Output |
  ForEach-Object { (Get-AzAutomationJobOutputRecord -Id $_.StreamRecordId -JobId $jobId -AutomationAccountName $AutomationAccount -ResourceGroupName $ResourceGroup).Value.Values }

  Write-Host "=== $Label  [$($job.Status)]  (JobId $jobId) ==="
  $out | Select-String -Pattern 'VERDICT:|matched:|via:' | ForEach-Object { "  $_" }
}

# DNAT -> Network -> Application, plus a deny — all triggered via the webhook
Invoke-WebhookCheck 'D1 DNAT (pre-NAT 3389)'  '10.20.5.7' '20.50.60.70'   'TCP'   3389  # expect ALLOWED  (dnat-rdp)
Invoke-WebhookCheck 'N1 Network CIDR'         '10.20.5.7' '10.30.1.4'     'TCP'   443   # expect ALLOWED  (allow-web-cidr)
Invoke-WebhookCheck 'N4 Network IP-group'     '10.20.5.7' '10.50.7.7'     'TCP'   443   # expect ALLOWED  (allow-onprem-ipgroup)
Invoke-WebhookCheck 'A1 Application wildcard' '10.20.5.7' 'api.azure.com' 'HTTPS' 443   # expect ALLOWED  (allow-azure-wild)
Invoke-WebhookCheck 'X1 Denied'               '10.99.0.1' '10.30.1.4'     'TCP'   443   # expect ACCESS DENIED
