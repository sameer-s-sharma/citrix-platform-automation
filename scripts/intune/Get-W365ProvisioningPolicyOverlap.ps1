<#
 =====================================================================
  Script Name : Get-W365ProvisioningPolicyOverlap.ps1
  Developer   : Sameer Sharma
  Date        : 2026-01-05

  Description :
     Detects Windows 365 provisioning policy assignment overlaps caused by
     Microsoft Entra ID group membership (direct or transitive).

     Supports:
       1) Single-user analysis (interactive prompt OR -UserPrincipalName)
       2) Tenant report mode (-Report) to enumerate all provisioning-policy
          assignment groups, expand users, and identify overlap users.

     Uses Microsoft Graph:
       - /beta/deviceManagement/virtualEndpoint/provisioningPolicies?$expand=assignments
       - /v1.0/users/{id}/checkMemberGroups   (single-user)
       - /v1.0/groups/{id}/members or /transitiveMembers (report)

     Results:
       - Console: human-readable analysis + group→policy mapping
       - Optional CSV: flattened rows (user, group, policy) for overlap users

  Usage :
     # Single user (prompt)
     PS> ./Get-OverlapUsers.ps1

     # Single user (non-interactive)
     PS> ./Get-OverlapUsers.ps1 -UserPrincipalName john.doe@contoso.com

     # Report mode (direct members only)
     PS> ./Get-OverlapUsers.ps1 -Report

     # Report mode (include nested groups)
     PS> ./Get-OverlapUsers.ps1 -Report -TransitiveMembers

     # Report mode + CSV export
     PS> ./Get-OverlapUsers.ps1 -Report -OutCsv ./w365-overlaps.csv

     # Report mode + nested groups + CSV export
     PS> ./Get-OverlapUsers.ps1 -Report -TransitiveMembers -OutCsv ./w365-overlaps.csv

  Developer Notes :
     - The script does NOT modify Entra / Intune / Windows 365 configuration.
     - “Overlap” means: a user is targeted by >1 provisioning policy via
       provisioning-policy assignment groups.
     - Windows 365 applies only one provisioning policy per user; when multiple
       are targeted, selection is based on Microsoft’s internal precedence logic.
     - Uses Ensure-MgGraphConnection() to reuse an existing Graph session or
       connect interactively (device code) when needed.
     - Paging is handled via @odata.nextLink when enumerating group members.

  Output Interpretation :
     - Single-user mode:
         Lists assignment groups the user belongs to (used by provisioning policy assignments)
         and the corresponding provisioning policies. If >1 policy is listed, overlap exists.

     - Report mode:
         Enumerates all assignment groups referenced by provisioning policies, prints
         group→policy and (optionally) user membership expansion, then summarizes overlap users.

  Version History :
     v1.0 (2026-01-05)
       - Single-user overlap detection + refined console output
       - Report mode (members/transitiveMembers) + overlap summary
       - Optional CSV export (flattened mapping rows)
       - Graph session banner + session reuse detection

  Disclaimer :
     This script is provided "as is" without warranty of any kind,
     express or implied. The developer assumes no liability for any
     damages or losses arising from its use. It is intended solely
     for diagnostic and operational validation purposes.
     Use at your own discretion in compliance with local laws,
     network policies, and organizational security guidelines.
 =====================================================================

.SYNOPSIS
    Windows 365 provisioning policy overlap detection (Entra group-driven).

.DESCRIPTION
    Detects whether a user (or users across assignment groups) is targeted
    by more than one Windows 365 provisioning policy due to Entra ID group
    membership overlaps.

.PARAMETER UserPrincipalName
    Single-user mode: the UPN to analyze (e.g., john.doe@contoso.com).
    If omitted, the script prompts interactively.

.PARAMETER Report
    Enables tenant report mode. Enumerates all provisioning policy assignment
    groups and scans members to find overlap users.

.PARAMETER TransitiveMembers
    Report mode only. If set, uses /transitiveMembers to include nested group
    membership. If not set, uses direct /members only.

.PARAMETER OutCsv
    Report mode only. Exports flattened overlap mapping rows to CSV.

.EXAMPLE
    ./Get-OverlapUsers.ps1
    Prompts for UPN and prints a single-user overlap analysis.

.EXAMPLE
    ./Get-OverlapUsers.ps1 -UserPrincipalName sameer.sharma@contoso.com
    Runs single-user analysis without prompting.

.EXAMPLE
    ./Get-OverlapUsers.ps1 -Report -TransitiveMembers -OutCsv ./w365-overlaps.csv
    Runs tenant overlap report using transitive membership and exports CSV.
#>

[CmdletBinding(DefaultParameterSetName = 'SingleUser')]
param(
  [Parameter(ParameterSetName='SingleUser')]
  [string]$UserPrincipalName,

  [Parameter(Mandatory, ParameterSetName='Report')]
  [switch]$Report,

  [Parameter(ParameterSetName='Report')]
  [switch]$TransitiveMembers,

  [Parameter(ParameterSetName='Report')]
  [string]$OutCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------
# Helper: robust nextLink getter (Hashtable OR PSObject)
# -------------------------
function Get-ODataNextLink {
  [CmdletBinding()]
  param([Parameter(Mandatory)] $Response)

  # Invoke-MgGraphRequest sometimes returns Hashtable-like
  if ($Response -is [System.Collections.IDictionary]) {
    if ($Response.Contains('@odata.nextLink')) { return $Response['@odata.nextLink'] }
    if ($Response.Contains('odata.nextLink'))  { return $Response['odata.nextLink'] }
    return $null
  }

  # Or PSObject-like
  try {
    $nl = $Response.'@odata.nextLink'
    if ($nl) { return $nl }
  } catch { }

  try {
    $nl = $Response.odata_nextLink
    if ($nl) { return $nl }
  } catch { }

  return $null
}

# -------------------------
# Graph connectivity helper (returns $true if it had to connect/reconnect)
# -------------------------
function Ensure-MgGraphConnection {
  [CmdletBinding()]
  param(
    [string[]]$RequiredScopes = @(
      "User.Read.All",
      "Group.Read.All",
      "CloudPC.Read.All",
      "Directory.Read.All"
    )
  )

  $ctx = $null
  try { $ctx = Get-MgContext } catch { $ctx = $null }

  $didConnect  = $false
  $needConnect = $true

  if ($ctx -and $ctx.Account -and $ctx.TenantId) { $needConnect = $false }

  if ($needConnect) {
    Write-Host "Not connected to Microsoft Graph. Connecting now (device code)..." -ForegroundColor Yellow
    try {
      Connect-MgGraph -UseDeviceCode -Scopes $RequiredScopes | Out-Null
      $didConnect = $true
    } catch {
      throw "Connect-MgGraph failed. Error: $($_.Exception.Message)"
    }
  }

  # Re-check context
  $ctx = Get-MgContext
  if (-not $ctx -or -not $ctx.Account -or -not $ctx.TenantId) {
    throw "Graph context missing after connection. Cannot continue."
  }

  # Best-effort scope check (helps when you connected earlier with insufficient scopes)
  $granted = @($ctx.Scopes)
  $missing = @($RequiredScopes | Where-Object { $granted -notcontains $_ })

  if ($missing.Count -gt 0) {
    Write-Host "Connected, but token may be missing required scopes. Reconnecting with required scopes..." -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }

    try { Disconnect-MgGraph | Out-Null } catch {}
    Connect-MgGraph -UseDeviceCode -Scopes $RequiredScopes | Out-Null
    $didConnect = $true
  }

  # Smoke test (fail fast)
  try { Get-MgUser -Top 1 -Property Id | Out-Null } catch {
    throw "Graph permission test failed. Ensure admin consent for: $($RequiredScopes -join ', '). Error: $($_.Exception.Message)"
  }

  return $didConnect
}

# -------------------------
# Graph session banner
# -------------------------
function Show-MgGraphSessionInfo {
  [CmdletBinding()]
  param(
    [string[]]$ExpectedScopes = @("User.Read.All","Group.Read.All","CloudPC.Read.All","Directory.Read.All")
  )

  $ctx = $null
  try { $ctx = Get-MgContext } catch { $ctx = $null }

  if (-not $ctx -or -not $ctx.Account -or -not $ctx.TenantId) {
    Write-Host "MICROSOFT GRAPH SESSION: NOT CONNECTED" -ForegroundColor Yellow
    return
  }

  $account  = $ctx.Account
  $tenantId = $ctx.TenantId
  $envName  = $ctx.Environment
  $scopes   = @($ctx.Scopes)

  $missing = @($ExpectedScopes | Where-Object { $scopes -notcontains $_ })

  Write-Host ""
  Write-Host "MICROSOFT GRAPH SESSION" -ForegroundColor Cyan
  Write-Host ("Status      : Connected")
  Write-Host ("Account     : {0}" -f $account)
  Write-Host ("TenantId    : {0}" -f $tenantId)
  Write-Host ("Environment : {0}" -f $envName)
  Write-Host ("Scopes      : {0}" -f ($scopes -join ", "))

  if ($missing.Count -gt 0) {
    Write-Host ("Scope check : Missing -> {0}" -f ($missing -join ", ")) -ForegroundColor Yellow
  } else {
    Write-Host ("Scope check : OK") -ForegroundColor Green
  }

  # Optional org info (best effort)
  try {
    $org = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/organization?`$select=displayName,verifiedDomains").value | Select-Object -First 1
    if ($org -and $org.displayName) {
      Write-Host ("Org         : {0}" -f $org.displayName)
      $defaultDomain = ($org.verifiedDomains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1).name
      if ($defaultDomain) { Write-Host ("DefaultDomain: {0}" -f $defaultDomain) }
    }
  } catch { }

  Write-Host ""
}

# -------------------------
# Prompt helper (exit-safe)
# -------------------------
function Read-UserUpn {
  while ($true) {
    Write-Host ""
    Write-Host "Enter user UPN (e.g. john.doe@contoso.com) or type 'q' to quit:" -ForegroundColor Cyan

    $raw = $null
    try { $raw = Read-Host } catch {
      Write-Host "Input cancelled. Exiting." -ForegroundColor Yellow
      return $null
    }

    if ($null -eq $raw) {
      Write-Host "No input received (cancelled/EOF). Exiting." -ForegroundColor Yellow
      return $null
    }

    $upn = $raw.Trim()

    if ($upn -in @('q','quit','exit')) {
      Write-Host "Exiting." -ForegroundColor Yellow
      return $null
    }

    if ([string]::IsNullOrWhiteSpace($upn)) {
      Write-Host "UPN cannot be empty. Try again." -ForegroundColor Yellow
      continue
    }

    if ($upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
      Write-Host "Invalid UPN format. Expected john.doe@contoso.com. Try again." -ForegroundColor Yellow
      continue
    }

    # Validate user exists
    $u = Get-MgUser -Filter "userPrincipalName eq '$upn'" -Property Id -All | Select-Object -First 1
    if (-not $u) {
      Write-Host "UPN not found in Entra ID: $upn. Try again." -ForegroundColor Yellow
      continue
    }

    return $upn
  }
}

# -------------------------
# Single-user analysis
# -------------------------
function Get-W365ProvisioningPolicyGroupOverlap {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName
  )

  # Resolve user
  $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -Property Id,DisplayName,UserPrincipalName -All |
          Select-Object -First 1
  if (-not $user) { throw "User not found: $UserPrincipalName" }

  # Policies + assignments (beta)
  $polResp  = Invoke-MgGraphRequest -Method GET -Uri "/beta/deviceManagement/virtualEndpoint/provisioningPolicies?`$select=id,displayName&`$expand=assignments"
  $policies = @($polResp.value)
  if (-not $policies) { throw "No Windows 365 provisioning policies found." }

  $targets = foreach ($p in $policies) {
    foreach ($a in @($p.assignments)) {
      if ($a.target -and $a.target.groupId) {
        [pscustomobject]@{
          ProvisioningPolicyName = $p.displayName
          ProvisioningPolicyId   = $p.id
          GroupId                = $a.target.groupId
        }
      }
    }
  }

  if (-not $targets) {
    Write-Host "No provisioning policy group assignments found (no assignments on any policies)." -ForegroundColor Yellow
    return
  }

  # checkMemberGroups (transitive)
  $uniqueGroupIds = @($targets | Select-Object -ExpandProperty GroupId -Unique)
  $body = @{ groupIds = $uniqueGroupIds } | ConvertTo-Json -Depth 3

  $resp = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/users/$($user.Id)/checkMemberGroups" -Body $body
  $memberGroupIds = @($resp.value)

  $hits = $targets | Where-Object { $memberGroupIds -contains $_.GroupId }

  # Resolve group names
  $groupNameCache = @{}
  foreach ($gid in @($hits | Select-Object -ExpandProperty GroupId -Unique)) {
    try {
      $g = Get-MgGroup -GroupId $gid -Property Id,DisplayName
      $groupNameCache[$gid] = $g.DisplayName
    } catch {
      $groupNameCache[$gid] = $gid
    }
  }

  $hitsDetailed = $hits | ForEach-Object {
    [pscustomobject]@{
      ProvisioningPolicyName = $_.ProvisioningPolicyName
      ProvisioningPolicyId   = $_.ProvisioningPolicyId
      GroupDisplayName       = $groupNameCache[$_.GroupId]
      GroupId                = $_.GroupId
    }
  } | Sort-Object ProvisioningPolicyName, GroupDisplayName

  $distinctPolicies = @($hitsDetailed | Select-Object -ExpandProperty ProvisioningPolicyId -Unique)
  $overlap = ($distinctPolicies.Count -gt 1)

  Write-Host ""
  Write-Host "WINDOWS 365 PROVISIONING POLICY ANALYSIS" -ForegroundColor Cyan
  Write-Host "User: $($user.UserPrincipalName)"
  Write-Host ""

  if (-not $hitsDetailed -or @($hitsDetailed).Count -eq 0) {
    Write-Host "Result: No Windows 365 provisioning policy assignments detected for this user (based on policy assignment groups)." -ForegroundColor Yellow
    return [pscustomobject]@{
      UserDisplayName      = $user.DisplayName
      UserPrincipalName    = $user.UserPrincipalName
      MatchedPoliciesCount = 0
      Overlap              = $false
      Matches              = @()
    }
  }

  $groupList  = $hitsDetailed | Select-Object -ExpandProperty GroupDisplayName -Unique
  $policyList = $hitsDetailed | Select-Object -ExpandProperty ProvisioningPolicyName -Unique

  Write-Host "This user is a member of Microsoft Entra ID groups used for Windows 365 provisioning policy assignments:"
  Write-Host ""
  foreach ($gName in $groupList) { Write-Host "- $gName" }

  Write-Host ""
  Write-Host "As a result, the user is currently targeted by the following Windows 365 provisioning policies:"
  Write-Host ""
  foreach ($pName in $policyList) { Write-Host "- $pName" }

  Write-Host ""
  Write-Host ("Matched policies: {0}" -f $distinctPolicies.Count)
  Write-Host ("Overlap detected: {0}" -f $overlap)
  Write-Host ""
  Write-Host "Microsoft Windows 365 applies only one provisioning policy per user (Enterprise/Reserve)."
  Write-Host "If multiple policies target the user, provisioning honors the first assigned provisioning policy and ignores the others."
  Write-Host "Note: The 'first assigned' precedence cannot be reliably inferred from Graph response ordering."
  Write-Host ""

  Write-Host "GROUP TO PROVISIONING POLICY ASSIGNMENT MAPPING" -ForegroundColor Cyan
  Write-Host ""

  $col1 = 45
  ("{0,-$col1} {1}" -f "Group Name", "Provisioning Policy") | Write-Host
  ("{0,-$col1} {1}" -f ("-" * 10), ("-" * 20))            | Write-Host

  foreach ($row in ($hitsDetailed | Sort-Object GroupDisplayName, ProvisioningPolicyName)) {
    ("{0,-$col1} {1}" -f $row.GroupDisplayName, $row.ProvisioningPolicyName) | Write-Host
  }

  Write-Host ""
  Write-Host "RECOMMENDATION:" -ForegroundColor Cyan
  Write-Host "To ensure predictable provisioning outcomes, ensure the user belongs to exactly one provisioning-policy assignment group."
  Write-Host ""

  [pscustomobject]@{
    UserDisplayName      = $user.DisplayName
    UserPrincipalName    = $user.UserPrincipalName
    MatchedPoliciesCount = $distinctPolicies.Count
    Overlap              = $overlap
    Matches              = $hitsDetailed
  }
}

# -------------------------
# Report mode: tenant-wide overlap detection + per-group expansion
# -------------------------
function Get-W365ProvisioningPolicyOverlapReport {
  [CmdletBinding()]
  param(
    [switch]$TransitiveMembers,
    [string]$OutCsv
  )

  # Policies + assignments (beta)
  $polResp  = Invoke-MgGraphRequest -Method GET -Uri "/beta/deviceManagement/virtualEndpoint/provisioningPolicies?`$select=id,displayName&`$expand=assignments"
  $policies = @($polResp.value)
  if (-not $policies) { throw "No Windows 365 provisioning policies found." }

  # Policy <-> GroupId rows
  $assignments = foreach ($p in $policies) {
    foreach ($a in @($p.assignments)) {
      if ($a.target -and $a.target.groupId) {
        [pscustomobject]@{
          ProvisioningPolicyName = $p.displayName
          ProvisioningPolicyId   = $p.id
          GroupId                = $a.target.groupId
        }
      }
    }
  }
  if (-not $assignments) { throw "No provisioning policy group assignments found." }

  # Resolve group names once
  $groupCache = @{}
  $allAssignmentGroupIds = @($assignments | Select-Object -ExpandProperty GroupId -Unique)

  foreach ($gid in $allAssignmentGroupIds) {
    try {
      $g = Get-MgGroup -GroupId $gid -Property Id,DisplayName
      $groupCache[$gid] = $g.DisplayName
    } catch {
      $groupCache[$gid] = $gid
    }
  }

  # Members vs transitiveMembers
  $memberEndpointSuffix = "members"
  $memberMode = "members (direct only)"
  if ($TransitiveMembers) {
    $memberEndpointSuffix = "transitiveMembers"
    $memberMode = "transitiveMembers (nested groups included)"
  }

  Write-Host ""
  Write-Host "WINDOWS 365 OVERLAP REPORT MODE" -ForegroundColor Cyan
  Write-Host ("Assignment groups: {0}" -f $allAssignmentGroupIds.Count)
  Write-Host ("Member mode      : {0}" -f $memberMode)
  Write-Host ""

  # userId -> aggregation
  $userMap = @{}

  foreach ($gid in $allAssignmentGroupIds) {
    $groupName = $groupCache[$gid]

    # Which policies does THIS group assign?
    $rowsForGroup = @($assignments | Where-Object GroupId -eq $gid)
    $polsForGroup = @($rowsForGroup | Select-Object -ExpandProperty ProvisioningPolicyName -Unique | Sort-Object)

    Write-Host ("Scanning group: {0}" -f $groupName) -ForegroundColor Gray
    Write-Host ("  Assigns policy: {0}" -f ($polsForGroup -join "; ")) -ForegroundColor DarkGray

    # Print group members (expanded)
    Write-Host "  Members:" -ForegroundColor DarkGray

    $uri = "/v1.0/groups/$gid/$($memberEndpointSuffix)?`$select=id,displayName,userPrincipalName"

    $memberCount = 0
    while ($true) {
      $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
      $vals = @($resp.value)

      foreach ($m in $vals) {
        if (-not $m.userPrincipalName) { continue } # skip non-user directoryObjects
        $memberCount++

        # Print each UPN + the policy/policies assigned via this group
        Write-Host ("   - {0}  ->  {1}" -f $m.userPrincipalName, ($polsForGroup -join "; ")) -ForegroundColor DarkGray

        if (-not $userMap.ContainsKey($m.id)) {
          $userMap[$m.id] = @{
            UserId      = $m.id
            Upn         = $m.userPrincipalName
            DisplayName = $m.displayName
            Policies    = New-Object 'System.Collections.Generic.HashSet[string]'
            Groups      = New-Object 'System.Collections.Generic.HashSet[string]'
            Rows        = @()
          }
        }

        foreach ($r in $rowsForGroup) {
          [void]$userMap[$m.id].Policies.Add($r.ProvisioningPolicyName)
          [void]$userMap[$m.id].Groups.Add($groupName)

          $userMap[$m.id].Rows += [pscustomobject]@{
            UserPrincipalName      = $m.userPrincipalName
            UserDisplayName        = $m.displayName
            GroupDisplayName       = $groupName
            GroupId                = $gid
            ProvisioningPolicyName = $r.ProvisioningPolicyName
            ProvisioningPolicyId   = $r.ProvisioningPolicyId
          }
        }
      }

      $next = Get-ODataNextLink -Response $resp
      if (-not $next) { break }
      $uri = $next
    }

    if ($memberCount -eq 0) {
      Write-Host "   (no user members found in this group)" -ForegroundColor DarkGray
    }

    Write-Host ""
  }

  # Build report (overlaps only)
  $report = foreach ($kvp in $userMap.GetEnumerator()) {
    $u = $kvp.Value
    $policyList = @($u.Policies)

    if ($policyList.Count -gt 1) {
      [pscustomobject]@{
        UserPrincipalName    = $u.Upn
        UserDisplayName      = $u.DisplayName
        MatchedPoliciesCount = $policyList.Count
        Policies             = ($policyList | Sort-Object) -join "; "
        Groups               = (@($u.Groups) | Sort-Object) -join "; "
        MappingRows          = $u.Rows
      }
    }
  }

  # Normalize to array (important: single overlap user still becomes a 1-item array)
  $report = @($report)

  Write-Host ""
  Write-Host "WINDOWS 365 PROVISIONING POLICY OVERLAP REPORT" -ForegroundColor Cyan
  Write-Host ("Users with overlap: {0}" -f $report.Count)
  Write-Host ""

  if ($report.Count -gt 0) {

    # Summary table
    $report |
      Select-Object UserPrincipalName, MatchedPoliciesCount, Policies |
      Sort-Object MatchedPoliciesCount -Descending |
      Format-Table -AutoSize |
      Out-String | Write-Host

    # Expanded per-user overlap detail
    Write-Host ""
    Write-Host "OVERLAP DETAILS (expanded per user)" -ForegroundColor Cyan
    Write-Host ""

    foreach ($u in ($report | Sort-Object MatchedPoliciesCount -Descending)) {

      Write-Host ("User: {0}  (policies={1})" -f $u.UserPrincipalName, $u.MatchedPoliciesCount) -ForegroundColor Yellow

      $pols = @(
        $u.MappingRows |
          Select-Object -ExpandProperty ProvisioningPolicyName -Unique |
          Sort-Object
      )
      Write-Host ("Policies: {0}" -f ($pols -join "; "))

      Write-Host "Group -> Policy:"
      $u.MappingRows |
        Sort-Object GroupDisplayName, ProvisioningPolicyName |
        Select-Object GroupDisplayName, ProvisioningPolicyName |
        Format-Table -AutoSize |
        Out-String | Write-Host

      Write-Host ""
    }

  } else {

    Write-Host "No provisioning policy overlaps detected." -ForegroundColor Green
    Write-Host "All evaluated users are targeted by exactly one Windows 365 provisioning policy." -ForegroundColor Green

  }

  if ($OutCsv -and $report.Count -gt 0) {
    $flat = foreach ($r in $report) { $r.MappingRows }
    $flat | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "CSV exported: $OutCsv" -ForegroundColor Green
  }

  return $report
}

# -------------------------
# Entrypoint (only when executed, not when dot-sourced)
# -------------------------
if ($MyInvocation.InvocationName -ne '.') {

  $didConnect = Ensure-MgGraphConnection
  Show-MgGraphSessionInfo

  if ($didConnect) {
    Write-Host "Graph authentication completed successfully for this run." -ForegroundColor Green
  } else {
    Write-Host "Reusing existing Microsoft Graph session." -ForegroundColor Green
  }
  Write-Host ""

  if ($Report) {
    Get-W365ProvisioningPolicyOverlapReport -TransitiveMembers:$TransitiveMembers -OutCsv $OutCsv | Out-Null
    return
  }

  if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $UserPrincipalName = Read-UserUpn
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) { return }
  } else {
    $UserPrincipalName = $UserPrincipalName.Trim()
    if ($UserPrincipalName -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
      throw "Invalid UPN format: '$UserPrincipalName'. Expected john.doe@contoso.com"
    }
    $u = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -Property Id -All | Select-Object -First 1
    if (-not $u) { throw "UPN not found in Entra ID: $UserPrincipalName" }
  }

  Get-W365ProvisioningPolicyGroupOverlap -UserPrincipalName $UserPrincipalName | Out-Null
}