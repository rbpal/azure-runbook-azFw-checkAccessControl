<#
.SYNOPSIS
  WEBHOOK variant of Check-AzFwAccessControl — triggered by an HTTP POST to the webhook URL;
  the flow is read from the JSON request body. Same matching logic as the manual runbook.

  POST body (application/json):
    { "SourceIp":"10.20.5.7", "Destination":"10.30.1.4", "Protocol":"TCP", "Port":443 }
  Optional overrides in the body: "Subscription", "ResourceGroup", "FirewallPolicyName".
  NOTE: webhooks are fire-and-forget (HTTP 202 + JobId) — read the verdict from the job output,
  not the HTTP response.

  Checks whether a flow is ALLOWED by an Azure Firewall POLICY across its DNAT, network,
  and application rule collections. Read-only. Runs as the Automation account's
  system-assigned managed identity (SAMI).

.DESCRIPTION
  v1 scope (see PRD / ADR-0003):
    - IPv4 only. IPv6 input -> clean "unsupported in v1" message.
    - Source is an IP; destination is an IP (DNAT/network) OR an FQDN (application).
    - Matching is CONTAINMENT, not string-equality: host IP matches a rule's CIDR/range;
      port matches a rule's port range/list; FQDN matches a rule's wildcard (no DNS).
    - IP Groups are resolved (Get-AzIpGroup) and expanded to prefixes.
    - Service Tags are NOT evaluated -> reported "not checked" (never silent).
    - Verdict: ALLOWED / DENIED (explicit) / ACCESS DENIED (implicit = Azure default deny).

.OUTPUTS
  Human-readable log lines + a single JSON object (last output) for scripting.
  Exit codes: 0 ALLOWED | 2 ACCESS DENIED (implicit) | 3 DENIED (explicit)
              1 input/validation error | 4 runtime/Azure error
#>

param(
  # Set automatically by Azure when the runbook is triggered via its webhook URL.
  [object] $WebhookData,

  # Used when started directly (not via the webhook) and as context defaults.
  [string] $Subscription       = '00000000-0000-0000-0000-000000000000', # set to your subscription id
  [string] $ResourceGroup      = 'rg-runbook-rbpal',
  [string] $FirewallPolicyName = 'rg-runbook-azfw-pol',
  [string] $SourceIp,
  [string] $Destination,      # IP (DNAT/network) or FQDN (network/application)
  [string] $Protocol,         # TCP/UDP/ICMP or HTTP/HTTPS/MSSQL
  [int]    $DestinationPort,
  [bool]   $UseManagedIdentity = $true
)

# ── webhook input: parse the POSTed JSON body into the flow parameters ──
if ($WebhookData) {
  try { $body = $WebhookData.RequestBody | ConvertFrom-Json }
  catch { Write-Error "Webhook request body is not valid JSON."; exit 1 }
  if ($body.Subscription) { $Subscription = "$($body.Subscription)" }
  if ($body.ResourceGroup) { $ResourceGroup = "$($body.ResourceGroup)" }
  if ($body.FirewallPolicyName) { $FirewallPolicyName = "$($body.FirewallPolicyName)" }
  $SourceIp = "$($body.SourceIp)"
  $Destination = "$($body.Destination)"
  $Protocol = "$($body.Protocol)"
  $DestinationPort = [int]$body.Port
}
if ([string]::IsNullOrWhiteSpace($SourceIp) -or [string]::IsNullOrWhiteSpace($Destination) -or
  [string]::IsNullOrWhiteSpace($Protocol) -or $DestinationPort -le 0) {
  Write-Error "Missing required field(s): provide SourceIp, Destination, Protocol, Port (via webhook JSON body or parameters)."
  exit 1
}

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Get-Prop {
  param($Object, [string]$Name)
  # NOTE: -contains and property access are case-insensitive, so 'Protocols' also matches
  # the lowercase 'protocols' that network rules expose in Az.Network 7.x.
  if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
  return $null
}

# Always returns a clean array (drops $null elements). Guards against PowerShell's
# @($null).Count == 1 quirk, which otherwise fires false "empty FQDN" notes.
function Get-List {
  param($Object, [string]$Name)
  $v = Get-Prop $Object $Name
  if ($null -eq $v) { return @() }
  return @($v) | Where-Object { $null -ne $_ -and "$_" -ne '' }
}

function Test-IsIpv4 {
  param([string]$Value)
  return ($Value -match '^\d{1,3}(\.\d{1,3}){3}$') -and
         (($Value -split '\.') | Where-Object { [int]$_ -gt 255 }).Count -eq 0
}

function Test-LooksIpv6 {
  param([string]$Value)
  return ($Value -match ':')
}

function Convert-IpToUInt32 {
  param([string]$Ip)
  $bytes = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
  [Array]::Reverse($bytes)
  return [System.BitConverter]::ToUInt32($bytes, 0)
}

function Test-Ipv4InCidr {
  param([string]$Ip, [string]$Cidr)
  $addr, $prefixStr = $Cidr -split '/'
  $prefix = [int]$prefixStr
  if ($prefix -le 0) { return $true }
  if ($prefix -gt 32) { return $false }
  # NOTE: in PowerShell 5.1 the hex literal 0xFFFFFFFF is -1 (Int32) -> use the decimal constant.
  $allOnes = [uint64]4294967295
  $mask    = ($allOnes -shl (32 - $prefix)) -band $allOnes
  $ipU  = [uint64](Convert-IpToUInt32 $Ip)
  $netU = [uint64](Convert-IpToUInt32 $addr.Trim())
  return ($ipU -band $mask) -eq ($netU -band $mask)
}

function Test-Ipv4InRange {
  param([string]$Ip, [string]$Range)
  $lo, $hi = $Range -split '-'
  $ipU = Convert-IpToUInt32 $Ip
  return ($ipU -ge (Convert-IpToUInt32 $lo.Trim())) -and ($ipU -le (Convert-IpToUInt32 $hi.Trim()))
}

# Returns: 'match' | 'nomatch' | 'servicetag' | 'skip'
function Get-IpEntryMatch {
  param([string]$Ip, [string]$Entry)
  if ([string]::IsNullOrWhiteSpace($Entry)) { return 'nomatch' }
  $Entry = $Entry.Trim()
  if ($Entry -eq '*') { return 'match' }
  if (Test-LooksIpv6 $Entry) { return 'skip' }
  if ($Entry -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') {
    if (Test-Ipv4InCidr $Ip $Entry) { return 'match' } else { return 'nomatch' }
  }
  if ($Entry -match '^\d{1,3}(\.\d{1,3}){3}\s*-\s*\d{1,3}(\.\d{1,3}){3}$') {
    if (Test-Ipv4InRange $Ip $Entry) { return 'match' } else { return 'nomatch' }
  }
  if (Test-IsIpv4 $Entry) {
    if ((Convert-IpToUInt32 $Ip) -eq (Convert-IpToUInt32 $Entry)) { return 'match' } else { return 'nomatch' }
  }
  return 'servicetag'   # a word like "Sql","Storage","AzureCloud"
}

function Test-PortInSpec {
  param([int]$Port, [string]$Spec)
  if ([string]::IsNullOrWhiteSpace($Spec) -or $Spec -eq '*') { return $true }
  foreach ($p in ($Spec -split ',')) {
    $p = $p.Trim()
    if ($p -eq '*') { return $true }
    if ($p -match '^\d+\s*-\s*\d+$') {
      $lo, $hi = $p -split '-'
      if ($Port -ge [int]$lo.Trim() -and $Port -le [int]$hi.Trim()) { return $true }
    }
    elseif ($p -match '^\d+$') {
      if ([int]$p -eq $Port) { return $true }
    }
  }
  return $false
}

function Test-FqdnMatch {
  param([string]$Fqdn, [string]$Pattern)
  $f = $Fqdn.TrimEnd('.').ToLower()
  $p = $Pattern.TrimEnd('.').ToLower()
  if ($p -eq '*') { return $true }
  $rx = '^' + ([Regex]::Escape($p) -replace '\\\*', '.*') + '$'
  return ($f -match $rx)
}

# ----------------------------------------------------------------------------
# Validation (fail fast — never emit a misleading verdict)
# ----------------------------------------------------------------------------
function Stop-WithInputError {
  param([string]$Message)
  $err = [ordered]@{ verdict = 'INPUT_ERROR'; error = $Message } | ConvertTo-Json -Compress
  Write-Error $Message
  Write-Output $err
  exit 1
}

if (Test-LooksIpv6 $SourceIp)   { Stop-WithInputError "Source IP '$SourceIp' looks like IPv6 — unsupported in v1 (IPv4 only)." }
if (-not (Test-IsIpv4 $SourceIp)) { Stop-WithInputError "Source IP '$SourceIp' is not a valid IPv4 address (expected e.g. 10.20.5.7)." }

$destIsIp = $false
if (Test-LooksIpv6 $Destination) { Stop-WithInputError "Destination '$Destination' looks like IPv6 — unsupported in v1 (IPv4 only)." }
if (Test-IsIpv4 $Destination) { $destIsIp = $true }
elseif ($Destination -match '^\d{1,3}(\.\d{1,3}){3}$') {
  Stop-WithInputError "Destination '$Destination' looks like a malformed IPv4 address (octet > 255)."
}
# else: treated as an FQDN (application-rule check)

if ($DestinationPort -lt 1 -or $DestinationPort -gt 65535) {
  Stop-WithInputError "Destination port '$DestinationPort' is out of range (1-65535)."
}
$protoU = $Protocol.Trim().ToUpper()

# ----------------------------------------------------------------------------
# Authenticate (SAMI) + read the policy
# ----------------------------------------------------------------------------
try {
  if ($UseManagedIdentity) {
    Connect-AzAccount -Identity | Out-Null
  }
  elseif (-not (Get-AzContext)) {
    Connect-AzAccount | Out-Null   # local: interactive sign-in if no context yet
  }
  # Only switch subscription when a real one is supplied; otherwise use the
  # identity's default context (the placeholder means "use my default").
  if ($Subscription -and $Subscription -ne '00000000-0000-0000-0000-000000000000') {
    Set-AzContext -Subscription $Subscription | Out-Null
  }
}
catch {
  Write-Error "Auth / subscription context failed: $($_.Exception.Message)"
  exit 4
}

try {
  $policy = Get-AzFirewallPolicy -ResourceGroupName $ResourceGroup -Name $FirewallPolicyName
}
catch {
  Write-Error "Could not read firewall policy '$FirewallPolicyName' in RG '$ResourceGroup'. Does the SAMI have Reader on the RG? $($_.Exception.Message)"
  exit 4
}

$rcgRefs = @(Get-Prop $policy 'RuleCollectionGroups')
Write-Output "Policy '$FirewallPolicyName' has $($rcgRefs.Count) rule collection group(s)."

# IP Group resolution cache
$ipGroupCache = @{}
function Resolve-IpGroupPrefixes {
  param([string]$ResourceId)
  if ($ipGroupCache.ContainsKey($ResourceId)) { return $ipGroupCache[$ResourceId] }
  $prefixes = @()
  try {
    $parts = $ResourceId -split '/'
    $g = Get-AzIpGroup -ResourceGroupName $parts[4] -Name $parts[-1]
    $prefixes = @(Get-Prop $g 'IpAddresses')
  }
  catch { $prefixes = @() }
  $ipGroupCache[$ResourceId] = $prefixes
  return $prefixes
}

# ----------------------------------------------------------------------------
# Matching engine
# ----------------------------------------------------------------------------
$notes = New-Object System.Collections.Generic.List[string]

function Test-SourceMatch {
  param($Rule)
  $addrs = Get-List $Rule 'SourceAddresses'
  $grps  = Get-List $Rule 'SourceIpGroups'
  foreach ($e in $addrs) {
    switch (Get-IpEntryMatch $script:SourceIp $e) {
      'match'      { $script:sourceVia = "address $e"; return $true }
      'servicetag' { $script:notes.Add("source service tag '$e' not checked") }
      'skip'       { $script:notes.Add("source IPv6 entry '$e' skipped") }
    }
  }
  foreach ($gid in $grps) {
    $gname = ($gid -split '/')[-1]
    foreach ($p in (Resolve-IpGroupPrefixes $gid)) {
      if ((Get-IpEntryMatch $script:SourceIp $p) -eq 'match') {
        $script:sourceVia = "IP group '$gname' (member $p)"; return $true
      }
    }
  }
  return $false
}

function Test-DestIpMatch {
  param($Rule)
  $addrs = Get-List $Rule 'DestinationAddresses'
  $grps  = Get-List $Rule 'DestinationIpGroups'
  $fqdns = Get-List $Rule 'DestinationFqdns'
  if ($fqdns.Count -gt 0) {
    $script:notes.Add("rule references destination FQDN(s) [$($fqdns -join ', ')] — not IP-matched (report only)")
  }
  foreach ($e in $addrs) {
    switch (Get-IpEntryMatch $script:Destination $e) {
      'match'      { $script:destVia = "address $e"; return $true }
      'servicetag' { $script:notes.Add("destination service tag '$e' not checked") }
      'skip'       { $script:notes.Add("destination IPv6 entry '$e' skipped") }
    }
  }
  foreach ($gid in $grps) {
    $gname = ($gid -split '/')[-1]
    foreach ($p in (Resolve-IpGroupPrefixes $gid)) {
      if ((Get-IpEntryMatch $script:Destination $p) -eq 'match') {
        $script:destVia = "IP group '$gname' (member $p)"; return $true
      }
    }
  }
  return $false
}

function Test-NetworkProtocol {
  param($Rule)
  # Network rules expose 'protocols'; NAT rules expose 'Protocols' — both reachable via
  # case-insensitive lookup. (Az.Network < 7 used 'IpProtocols'; handled as a fallback.)
  $raw = Get-List $Rule 'Protocols'
  if (-not $raw) { $raw = Get-List $Rule 'IpProtocols' }
  $protos = $raw | ForEach-Object { "$_".ToUpper() }
  return ($protos -contains 'ANY') -or ($protos -contains $script:protoU)
}

function Test-AppProtocol {
  param($Rule)
  $ok = $false
  foreach ($pr in (Get-List $Rule 'Protocols')) {
    $t = "$(Get-Prop $pr 'ProtocolType')".ToUpper()
    $port = Get-Prop $pr 'Port'
    if ($t -eq $script:protoU -and ($null -eq $port -or [int]$port -eq $script:DestinationPort)) { $ok = $true }
  }
  return $ok
}

$matchedRule = $null
$matchedDeny = $null

foreach ($ref in ($rcgRefs | Sort-Object { Get-Prop $_ 'Priority' })) {
  $rcgName = ($ref.Id -split '/')[-1]
  try {
    $rcg = Get-AzFirewallPolicyRuleCollectionGroup -ResourceGroupName $ResourceGroup `
            -AzureFirewallPolicyName $FirewallPolicyName -Name $rcgName
  }
  catch {
    $notes.Add("could not read collection group '$rcgName': $($_.Exception.Message)")
    continue
  }

  $collections = @(Get-Prop (Get-Prop $rcg 'Properties') 'RuleCollection')
  if (-not $collections) { $collections = @(Get-Prop $rcg 'RuleCollection') }

  foreach ($col in ($collections | Sort-Object { Get-Prop $_ 'Priority' })) {
    $colType = "$(Get-Prop $col 'RuleCollectionType')"
    $action  = "$(Get-Prop (Get-Prop $col 'Action') 'Type')"
    foreach ($rule in @(Get-Prop $col 'Rules')) {
      $ruleType = "$(Get-Prop $rule 'RuleType')"
      $hit = $false
      $script:sourceVia = $null   # how source matched: "address X" / "IP group 'g' (member p)"
      $script:destVia = $null     # how destination matched: address / IP group / FQDN

      if ($destIsIp -and $colType -like '*Nat*' -and $ruleType -like '*Nat*') {
        # DNAT: match on original (pre-translation) destination
        $hit = (Test-SourceMatch $rule) -and (Test-DestIpMatch $rule) -and `
               (Test-NetworkProtocol $rule) -and (Test-PortInSpec $DestinationPort ((Get-List $rule 'DestinationPorts') -join ','))
      }
      elseif ($destIsIp -and $ruleType -eq 'NetworkRule') {
        $hit = (Test-SourceMatch $rule) -and (Test-DestIpMatch $rule) -and `
               (Test-NetworkProtocol $rule) -and (Test-PortInSpec $DestinationPort ((Get-List $rule 'DestinationPorts') -join ','))
      }
      elseif (-not $destIsIp -and $ruleType -eq 'ApplicationRule') {
        $fqdnHit = $false
        foreach ($t in (Get-List $rule 'TargetFqdns')) { if (Test-FqdnMatch $Destination $t) { $fqdnHit = $true; $script:destVia = "FQDN '$t'" } }
        $hit = (Test-SourceMatch $rule) -and $fqdnHit -and (Test-AppProtocol $rule)
      }
      elseif (-not $destIsIp -and $ruleType -eq 'NetworkRule') {
        # FQDN destination against a NETWORK rule's FQDN list — deterministic wildcard match (no DNS).
        # (Matching an *IP* against a network FQDN rule still needs DNS -> remains report-only.)
        $fqdnHit = $false
        foreach ($t in (Get-List $rule 'DestinationFqdns')) { if (Test-FqdnMatch $Destination $t) { $fqdnHit = $true; $script:destVia = "FQDN '$t'" } }
        $hit = (Test-SourceMatch $rule) -and $fqdnHit -and `
               (Test-NetworkProtocol $rule) -and (Test-PortInSpec $DestinationPort ((Get-List $rule 'DestinationPorts') -join ','))
      }

      if ($hit) {
        $provenance = [ordered]@{
          policy           = $FirewallPolicyName
          collectionGroup  = $rcgName
          ruleCollection   = "$(Get-Prop $col 'Name')"
          rule             = "$(Get-Prop $rule 'Name')"
          ruleType         = $ruleType
          action           = $action
          sourceMatchedVia = $script:sourceVia
          destMatchedVia   = $script:destVia
        }
        if ($action -ieq 'Deny') {
          if (-not $matchedDeny) { $matchedDeny = $provenance }
        }
        else {
          if (-not $matchedRule) {
            $matchedRule = $provenance
            if ($script:sourceVia -like 'IP group*') { $notes.Add("source $SourceIp matched via $($script:sourceVia)") }
            if ($script:destVia -like 'IP group*') { $notes.Add("destination $Destination matched via $($script:destVia)") }
          }
        }
      }
    }
  }
}

# ----------------------------------------------------------------------------
# Verdict + output
# ----------------------------------------------------------------------------
if ($matchedRule) {
  $verdict = 'ALLOWED'; $code = 0; $prov = $matchedRule
}
elseif ($matchedDeny) {
  $verdict = 'DENIED (explicit)'; $code = 3; $prov = $matchedDeny
}
else {
  $verdict = 'ACCESS DENIED (implicit)'; $code = 2; $prov = $null
}

$result = [ordered]@{
  verdict   = $verdict
  input     = [ordered]@{ source = $SourceIp; destination = $Destination; protocol = $protoU; port = $DestinationPort }
  provenance = $prov
  notes     = @($notes)
}

Write-Output "VERDICT: $verdict"
if ($prov) {
  Write-Output ("  matched: {0} / {1} / rule '{2}' [{3}, {4}]" -f $prov.policy, $prov.ruleCollection, $prov.rule, $prov.ruleType, $prov.action)
  if ($prov.sourceMatchedVia) { Write-Output ("  source via: {0}" -f $prov.sourceMatchedVia) }
  if ($prov.destMatchedVia) { Write-Output ("  dest via:   {0}" -f $prov.destMatchedVia) }
}
foreach ($n in $notes) { Write-Output "  note: $n" }
Write-Output ($result | ConvertTo-Json -Depth 6)

exit $code
