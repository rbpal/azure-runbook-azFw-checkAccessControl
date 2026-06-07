<#
.SYNOPSIS
  14 copy-paste test cases for the Azure Firewall Policy access-control runbook (PowerShell version
  of tests/firewall-check-tests.sh).

.DESCRIPTION
  Each test starts the cloud runbook with a flow (Subscription / ResourceGroup / FirewallPolicyName are
  defaulted in the runbook), waits for completion, and prints the VERDICT + matched line.

  Usage:
    Connect-AzAccount                       # once
    Set-AzContext -Subscription <your-sub>   # if you have multiple
    ./tests/firewall-check-tests.ps1         # run all
  or dot-source and call Invoke-Check individually:
    . ./tests/firewall-check-tests.ps1 -NoRun
    Invoke-Check -Label 'N1' -SourceIp 10.20.5.7 -Destination 10.30.1.4 -Protocol TCP -Port 443
#>

param(
  [string] $AutomationAccount = 'ac-runbook-azfw',
  [string] $ResourceGroup     = 'rg-runbook-rbpal',
  [string] $RunbookName       = 'Check-AzFwAccessControl',
  [switch] $NoRun  # dot-source the function without running the suite
)

function Invoke-Check {
  param(
    [Parameter(Mandatory)] [string] $Label,
    [Parameter(Mandatory)] [string] $SourceIp,
    [Parameter(Mandatory)] [string] $Destination,
    [Parameter(Mandatory)] [string] $Protocol,
    [Parameter(Mandatory)] [int]    $Port,
    [string] $Expect = ''
  )
  $params = @{
    SourceIp        = $SourceIp
    Destination     = $Destination
    Protocol        = $Protocol
    DestinationPort = $Port
  }
  $job = Start-AzAutomationRunbook -AutomationAccountName $AutomationAccount `
           -ResourceGroupName $ResourceGroup -Name $RunbookName -Parameters $params
  do {
    Start-Sleep -Seconds 5
    $job = Get-AzAutomationJob -Id $job.JobId -AutomationAccountName $AutomationAccount -ResourceGroupName $ResourceGroup
  } while ($job.Status -notin 'Completed', 'Failed', 'Suspended', 'Stopped')

  $out = Get-AzAutomationJobOutput -Id $job.JobId -AutomationAccountName $AutomationAccount `
           -ResourceGroupName $ResourceGroup -Stream Output |
         ForEach-Object { (Get-AzAutomationJobOutputRecord -Id $_.StreamRecordId -JobId $job.JobId `
           -AutomationAccountName $AutomationAccount -ResourceGroupName $ResourceGroup).Value.Values }
  $verdict = ($out | Select-String -Pattern 'VERDICT:' | Select-Object -First 1) -replace '.*VERDICT:\s*', ''
  $matched = ($out | Select-String -Pattern 'matched:' | Select-Object -First 1) -replace '^\s*matched:\s*', ''
  '{0,-18} {1,-45} -> {2,-26} {3}' -f $Label, "$SourceIp -> $Destination $Protocol/$Port", $verdict.Trim(),
    ($(if ($Expect) { "(expect $Expect)" } else { '' }))
  if ($matched) { "    $($matched.Trim())" }
}

if ($NoRun) { return }

# ── DNAT (matches the ORIGINAL / pre-NAT destination: public IP + original port)
Invoke-Check 'D1 DNAT rdp'        '10.20.5.7'   '20.50.60.70'                   'TCP'   3389 -Expect 'ALLOWED'
Invoke-Check 'D2 DNAT https'      '203.0.113.9' '20.50.60.71'                   'TCP'   8443 -Expect 'ALLOWED'
Invoke-Check 'D3 DNAT wrong port' '10.20.5.7'   '20.50.60.71'                   'TCP'   443  -Expect 'ACCESS DENIED'

# ── Network (CIDR containment + port range + IP group)
Invoke-Check 'N1 net cidr'        '10.20.5.7'   '10.30.1.4'                     'TCP'   443  -Expect 'ALLOWED'
Invoke-Check 'N2 net port-range'  '10.20.5.7'   '10.30.1.4'                     'TCP'   8080 -Expect 'ALLOWED'
Invoke-Check 'N3 net sql cidr'    '10.21.9.9'   '10.31.5.20'                    'TCP'   1433 -Expect 'ALLOWED'
Invoke-Check 'N4 net ip-group'    '10.20.5.7'   '10.50.7.7'                     'TCP'   443  -Expect 'ALLOWED'
Invoke-Check 'N5 net bad source'  '10.99.0.1'   '10.30.1.4'                     'TCP'   443  -Expect 'ACCESS DENIED'
Invoke-Check 'N6 net bad port'    '10.20.5.7'   '10.30.1.4'                     'TCP'   9000 -Expect 'ACCESS DENIED'

# ── Application (destination is an FQDN, not an IP)
Invoke-Check 'A1 app wildcard'    '10.20.5.7'   'api.azure.com'                 'HTTPS' 443  -Expect 'ALLOWED'
Invoke-Check 'A2 app exact fqdn'  '10.20.5.7'   'api.github.com'                'HTTPS' 443  -Expect 'ALLOWED'
Invoke-Check 'A3 app mssql'       '10.20.5.7'   'myserver.database.windows.net' 'MSSQL' 1433 -Expect 'ALLOWED'
Invoke-Check 'A4 app src ip-group' '10.60.1.9'  'cdn.azureedge.net'             'HTTPS' 443  -Expect 'ALLOWED'
Invoke-Check 'A5 app not covered' '10.20.5.7'   'www.google.com'                'HTTPS' 443  -Expect 'ACCESS DENIED'

# ── Input-validation edge cases (optional)
Invoke-Check 'V1 ipv6'            '2001:db8::1' '10.30.1.4'                     'TCP'   443  -Expect 'INPUT_ERROR'
Invoke-Check 'V2 malformed ip'    '10.20.300.5' '10.30.1.4'                     'TCP'   443  -Expect 'INPUT_ERROR'
