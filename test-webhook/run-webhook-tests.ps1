<#
.SYNOPSIS
  Self-contained webhook tester bundled with test-webhook/. Sends a set of flows to the webhook
  (DNAT -> Network -> Application + a deny) and reads the verdict back for each.

  The webhook is FIRE-AND-FORGET: the POST returns a JobId; we then poll that job's output.

  Run from inside test-webhook/ (it reads the URL from `terraform output -raw webhook_uri`):
    Connect-AzAccount                                  # needed only to READ the job output
    ./run-webhook-tests.ps1 -AutomationAccount <acct> -ResourceGroup <rg>
#>
param(
  [string] $WebhookUri        = $env:WEBHOOK_URI,
  [string] $AutomationAccount = 'ac-runbook-azfw',
  [string] $ResourceGroup     = 'rg-runbook-rbpal'
)

if (-not $WebhookUri) {
  try { $WebhookUri = (terraform output -raw webhook_uri 2>$null) } catch {}
}
if (-not $WebhookUri) { throw "Set -WebhookUri or `$env:WEBHOOK_URI (or run where 'terraform output webhook_uri' works)." }

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

  Write-Host "=== $Label  [$($job.Status)] ==="
  $out | Select-String -Pattern 'VERDICT:|matched:|via:' | ForEach-Object { "  $_" }
}

# DNAT -> Network -> Application + deny — all via the webhook
Invoke-WebhookCheck 'DNAT (pre-NAT 3389)'  '10.20.5.7' '20.50.60.70'   'TCP'   3389  # expect ALLOWED
Invoke-WebhookCheck 'Network CIDR'         '10.20.5.7' '10.30.1.4'     'TCP'   443   # expect ALLOWED
Invoke-WebhookCheck 'Network IP-group'     '10.20.5.7' '10.50.7.7'     'TCP'   443   # expect ALLOWED
Invoke-WebhookCheck 'Application wildcard' '10.20.5.7' 'api.azure.com' 'HTTPS' 443   # expect ALLOWED
Invoke-WebhookCheck 'Denied'               '10.99.0.1' '10.30.1.4'     'TCP'   443   # expect ACCESS DENIED
