<#
  Script Name : Citrix Pop Extractor
  Developer   : Sameer Sharma (sameer.sharma@citrix.com)
  Version     : 1.1
  Date        : 2025-12-19

.SYNOPSIS
  Citrix Allowlist / PoP Region Extractor (Baseline + Region)

.DESCRIPTION
  Downloads one or more Citrix allowlist.json files, extracts all FQDNs from all sections,
  deduplicates, classifies each FQDN into:
    - Category: Baseline or Regional
    - Region: EU/AMER/APAC/MiddleEast/UK/UNKNOWN (for Regional endpoints)

  Filtering is applied ONLY to Category=Regional.
  Category=Baseline is ALWAYS included in the output.

  Adds -Explain <FQDN|ALL>:
    -Explain <FQDN>  : explains a single hostname and whether it is included
    -Explain ALL     : outputs explanation rows for all hostnames

.EXAMPLE
  # Return ALL FQDNs (Baseline + all Regional endpoints across all regions)
  .\Get-CitrixPopExtractor.ps1

  This is the default behavior when no RegionInclude or RegionExclude
  parameters are specified.

.EXAMPLE
  # Return Baseline + EU Regional endpoints only
  .\Get-CitrixPopExtractor.ps1 -RegionInclude EU

.EXAMPLE
  # Return Baseline + US/AMER Regional endpoints only
  .\Get-CitrixPopExtractor.ps1 -RegionInclude AMER

.EXAMPLE
  # Explain why a specific FQDN is included or excluded
  .\Get-CitrixPopExtractor.ps1 -RegionInclude EU -Explain aws-eu-w.g.nssvc.net

.EXAMPLE
  # Explain ALL FQDNs (audit / CAB mode)
  .\Get-CitrixPopExtractor.ps1 -RegionInclude EU -Explain ALL -OutputFormat CSV -OutputPath .\explain-eu

.EXAMPLE
  # Export ALL FQDNs to a file (no region filtering)
  .\Get-CitrixPopExtractor.ps1 -OutputFormat TXT -OutputPath .\allowlist-all

.EXAMPLE
  # Explain why a single FQDN is included or excluded (decision trace)
  .\Get-CitrixPopExtractor.ps1 -RegionInclude AMER -Explain aws-us-e.g.nssvc.net

  Output shows:
   - Category (Baseline or Regional)
   - Region classification
   - Whether the FQDN is included
   - The exact rule path that led to the decision

.PARAMETER Url
  One or more allowlist.json URLs.

.PARAMETER RegionInclude
  Include ONLY these regions for Category=Regional. Baseline is always included.
  Mutually exclusive with RegionExclude.

.PARAMETER RegionExclude
  Exclude these regions for Category=Regional. Baseline is always included.
  Mutually exclusive with RegionInclude.

.PARAMETER OutputFormat
  JSON, CSV, or TXT.

.PARAMETER OutputPath
  File path to write results. If omitted, outputs to pipeline.
  If no extension is provided, it is auto-appended based on OutputFormat.

.PARAMETER ExportUnknownRegionalPath
  Optional path to export Regional endpoints whose region is UNKNOWN (same format rules as OutputPath).
  If no extension is provided, it is auto-appended based on OutputFormat.

.PARAMETER Explain
  Provide a single FQDN to explain, or 'ALL' to explain all FQDNs.

.PARAMETER PassThru
  Also output objects to the pipeline even when OutputPath is set.
#>

[CmdletBinding(DefaultParameterSetName = "NoFilter")]
param(
  [Parameter()]
  [string[]] $Url = @(
    "https://fqdnallowlistsa.blob.core.windows.net/fqdnallowlist-commercial/allowlist.json"
  ),

  [Parameter(ParameterSetName="Include")]
  [ValidateSet("EU","AMER","APAC","MiddleEast","UK","UNKNOWN")]
  [string[]] $RegionInclude,

  [Parameter(ParameterSetName="Exclude")]
  [ValidateSet("EU","AMER","APAC","MiddleEast","UK","UNKNOWN")]
  [string[]] $RegionExclude,

  [Parameter()]
  [ValidateSet("JSON","CSV","TXT")]
  [string] $OutputFormat = "TXT",

  [Parameter()]
  [string] $OutputPath,

  [Parameter()]
  [string] $ExportUnknownRegionalPath,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string] $Explain,

  [Parameter()]
  [switch] $PassThru
)

begin {
  # Ensure TLS 1.2+
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

  function Resolve-OutputPath {
    param(
      [Parameter(Mandatory)][string] $Path,
      [Parameter(Mandatory)][ValidateSet("JSON","CSV","TXT")][string] $Format
    )
    if ([System.IO.Path]::GetExtension($Path)) { return $Path }
    $ext = switch ($Format) { "JSON" { ".json" } "CSV" { ".csv" } "TXT" { ".txt" } }
    return "$Path$ext"
  }

  function Ensure-ParentDir {
    param([string] $Path)
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  }

  function Export-Data {
    param(
      [Parameter(Mandatory)] $Data,
      [Parameter(Mandatory)][ValidateSet("JSON","CSV","TXT")] [string] $Fmt,
      [Parameter(Mandatory)] [string] $Path
    )
    Ensure-ParentDir -Path $Path
    switch ($Fmt) {
      "JSON" { $Data | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8 }
      "CSV"  { $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 }
      "TXT"  { $Data.Fqdn | Sort-Object -Unique | Set-Content -Path $Path -Encoding UTF8 }
    }
  }

  function Get-AllowlistJson {
    param([Parameter(Mandatory)][string] $Uri)
    Write-Verbose "Downloading: $Uri"
    try { Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction Stop }
    catch { throw "Failed to download allowlist.json from [$Uri]. Error: $($_.Exception.Message)" }
  }

  # --- Region detection (regex-based) ---
  # Fix: add nssvc short-codes so they don't get misclassified as Baseline:
  #   aus -> APAC, bz -> AMER (Brazil), nw -> EU (Norway)
  $RegionRegex = [ordered]@{
    EU   = @(
      '(^|[.-])eu([.-]|$)',
      '(^|-)nw(-|[.-])',            # az-nw-e / aws-nw-* (Norway)
      'westeurope', 'northeurope', 'swedencentral'
    )
    UK   = @(
      '(^|[.-])uk([.-]|$)', 'uksouth', 'ukwest'
    )
    AMER = @(
      '(^|[.-])us([.-]|$)', '(^|[.-])ca([.-]|$)',
      'eastus', 'westus', 'centralus', 'northcentralus', 'southcentralus',
      'brazilsouth', '(^|-)bz(-|[.-])', '(^|[.-])br([.-]|$)', '(^|[.-])mx([.-]|$)'
    )
    APAC = @(
      '(^|[.-])ap([.-]|$)', '(^|[.-])ap-s([.-]|$)', '(^|[.-])aps([.-]|$)',
      'asia', 'australiaeast', 'australiasoutheast',
      '(^|-)aus(-|[.-])',           # aws-aus-e / az-aus-e
      '(^|[.-])in([.-]|$)', '(^|[.-])jp([.-]|$)', '(^|[.-])sg([.-]|$)',
      '(^|[.-])hk([.-]|$)', '(^|[.-])kr([.-]|$)'
    )
    MiddleEast = @(
      '(^|[.-])uae([.-]|$)', 'uaenorth',
      '(^|[.-])sa([.-]|$)', '(^|[.-])za([.-]|$)', 'southafrica'
    )
  }

  function Get-RegionFromFqdn {
    param([Parameter(Mandatory)][string] $Fqdn)

    $f = $Fqdn.ToLowerInvariant()
    foreach ($region in $RegionRegex.Keys) {
      foreach ($rx in $RegionRegex[$region]) {
        if ($f -match $rx) { return $region }
      }
    }
    return "UNKNOWN"
  }

  function Get-CategoryFromFqdn {
    param([Parameter(Mandatory)][string] $Fqdn)

    $f = $Fqdn.ToLowerInvariant()

    if ($f -match '\.nssvc\.net$') { return "Regional" }

    foreach ($region in $RegionRegex.Keys) {
      foreach ($rx in $RegionRegex[$region]) {
        if ($f -match $rx) { return "Regional" }
      }
    }

    return "Baseline"
  }

  function Extract-FqdnsFromAllowlist {
    param(
      [Parameter(Mandatory)][object] $Json,
      [Parameter(Mandatory)][string] $SourceUrl
    )

    $out = New-Object System.Collections.Generic.List[object]

    foreach ($prop in $Json.PSObject.Properties) {
      $sectionName = $prop.Name
      $allow = $prop.Value.AllowList
      if ($null -eq $allow) { continue }

      foreach ($item in $allow) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        $fqdn = $item.ToString().Trim()

        $category = Get-CategoryFromFqdn -Fqdn $fqdn
        $region   = if ($category -eq "Regional") { Get-RegionFromFqdn -Fqdn $fqdn } else { "" }

        $out.Add([pscustomobject]@{
          Fqdn      = $fqdn
          Section   = $sectionName
          Category  = $category       # Baseline / Regional
          Region    = $region         # only for Regional
          SourceUrl = $SourceUrl
        })
      }
    }

    return $out
  }

  function Get-FqdnExplanation {
    param(
      [Parameter(Mandatory)] $Item,
      [Parameter(Mandatory)] [bool] $Included,
      [string[]] $RegionInclude,
      [string[]] $RegionExclude
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    if ($Item.Category -eq "Regional") {
      if ($Item.Fqdn.ToLowerInvariant() -match '\.nssvc\.net$') {
        $reasons.Add("Matches *.nssvc.net → PoP / Rendezvous endpoint (Regional)")
      } else {
        $reasons.Add("Matches region marker → Regional endpoint")
      }

      if ($Item.Region -and $Item.Region -ne "UNKNOWN") {
        $reasons.Add("Region detected as [$($Item.Region)]")
      } else {
        $reasons.Add("Region could not be determined → marked UNKNOWN")
      }

      if ($RegionInclude) {
        if ($RegionInclude -contains $Item.Region) {
          $reasons.Add("Included because RegionInclude = $($RegionInclude -join ',')")
        } else {
          $reasons.Add("Excluded because RegionInclude = $($RegionInclude -join ',')")
        }
      }
      elseif ($RegionExclude) {
        if ($RegionExclude -contains $Item.Region) {
          $reasons.Add("Excluded because RegionExclude = $($RegionExclude -join ',')")
        } else {
          $reasons.Add("Included because RegionExclude does not contain region")
        }
      } else {
        $reasons.Add("No region filter specified → included")
      }
    }
    else {
      $reasons.Add("Classified as Baseline (control-plane / global service)")
      $reasons.Add("Baseline endpoints are always included regardless of region filter")
    }

    return ($reasons -join "; ")
  }
}

process {
  $all = New-Object System.Collections.Generic.List[object]

  foreach ($u in $Url) {
    $json  = Get-AllowlistJson -Uri $u
    $items = Extract-FqdnsFromAllowlist -Json $json -SourceUrl $u
    foreach ($i in $items) { $all.Add($i) }
  }

  # Deduplicate by FQDN; preserve traceability (sections/sources)
  $unique = $all |
    Group-Object -Property Fqdn |
    ForEach-Object {
      $fqdn = $_.Name
      $sections = ($_.Group.Section | Sort-Object -Unique) -join ";"
      $sources  = ($_.Group.SourceUrl | Sort-Object -Unique) -join ";"

      # prefer Regional if any entry classifies as Regional
      $category = if ($_.Group.Category -contains "Regional") { "Regional" } else { "Baseline" }
      $region   = if ($category -eq "Regional") { Get-RegionFromFqdn -Fqdn $fqdn } else { "" }

      [pscustomobject]@{
        Fqdn       = $fqdn
        Category   = $category
        Region     = $region
        Sections   = $sections
        SourceUrls = $sources
      }
    } |
    Sort-Object -Property Fqdn

  # Split
  $baseline = $unique | Where-Object { $_.Category -eq "Baseline" }
  $regional = $unique | Where-Object { $_.Category -eq "Regional" }

  # Apply region filter ONLY to regional
  $regionalFiltered = $regional
  if ($PSCmdlet.ParameterSetName -eq "Include") {
    $regionalFiltered = $regional | Where-Object { $RegionInclude -contains $_.Region }
  }
  elseif ($PSCmdlet.ParameterSetName -eq "Exclude") {
    $regionalFiltered = $regional | Where-Object { $RegionExclude -notcontains $_.Region }
  }

  # Final output = baseline + regionalFiltered
  $filtered = @($baseline + $regionalFiltered) | Sort-Object Fqdn -Unique

  # Optional: export regional-UNKNOWN review set
  $regionalUnknown = $regional | Where-Object { $_.Region -eq "UNKNOWN" }
  if ($ExportUnknownRegionalPath) {
    $resolvedUnknownPath = Resolve-OutputPath -Path $ExportUnknownRegionalPath -Format $OutputFormat
    Export-Data -Data $regionalUnknown -Fmt $OutputFormat -Path $resolvedUnknownPath
    Write-Host "Exported Regional UNKNOWN entries ($($regionalUnknown.Count)) to: $resolvedUnknownPath"
  }

  # Build explanation rows (for -Explain)
  $filteredFqdns = @{}
  foreach ($f in $filtered.Fqdn) { $filteredFqdns[$f] = $true }

  $withExplain = $unique | ForEach-Object {
    $included = $filteredFqdns.ContainsKey($_.Fqdn)
    [pscustomobject]@{
      Fqdn     = $_.Fqdn
      Category = $_.Category
      Region   = $_.Region
      Sections = $_.Sections
      Included = $included
      Reason   = Get-FqdnExplanation -Item $_ -Included $included -RegionInclude $RegionInclude -RegionExclude $RegionExclude
    }
  }

  # If Explain is requested, return explanation objects instead of normal output
  if ($Explain) {
    if ($Explain.ToUpperInvariant() -eq "ALL") {
      $explainOut = $withExplain
    } else {
      $explainOut = $withExplain | Where-Object { $_.Fqdn -ieq $Explain }
      if (-not $explainOut) {
        throw "FQDN '$Explain' not found in allowlist data."
      }
    }

    if ($OutputPath) {
      $resolvedOutputPath = Resolve-OutputPath -Path $OutputPath -Format $OutputFormat
      Export-Data -Data $explainOut -Fmt $OutputFormat -Path $resolvedOutputPath
      Write-Host "Explanation written to: $resolvedOutputPath"
      if ($PassThru) { $explainOut }
    }
    else {
      $explainOut | Format-List
    }

    return
  }

  # Summary
  Write-Host ""
  Write-Host "===== Citrix Allowlist Extractor Summary (Baseline + Region) ====="
  Write-Host "Sources                 : $($Url.Count)"
  Write-Host "Total unique FQDNs       : $($unique.Count)"
  Write-Host "Baseline FQDNs           : $($baseline.Count)"
  Write-Host "Regional FQDNs (total)   : $($regional.Count)"
  Write-Host "Regional FQDNs (filtered): $($regionalFiltered.Count)"
  Write-Host "Output total             : $($filtered.Count)"
  Write-Host "Filter Mode              : $($PSCmdlet.ParameterSetName)"
  if ($RegionInclude) { Write-Host "RegionInclude            : $($RegionInclude -join ',')" }
  if ($RegionExclude) { Write-Host "RegionExclude            : $($RegionExclude -join ',')" }

  $byRegion = $regionalFiltered | Group-Object Region | Sort-Object Name
  Write-Host "Regional counts by Region:"
  foreach ($g in $byRegion) { Write-Host ("  {0,-12} {1,6}" -f $g.Name, $g.Count) }
  Write-Host "==============================================================="
  Write-Host ""

  # Output handling
  $outputObj = $filtered

  if ($OutputPath) {
    $resolvedOutputPath = Resolve-OutputPath -Path $OutputPath -Format $OutputFormat
    Export-Data -Data $outputObj -Fmt $OutputFormat -Path $resolvedOutputPath
    Write-Host "Wrote $($outputObj.Count) entries to: $resolvedOutputPath"
    if ($PassThru) { $outputObj }
  }
  else {
    # Pipeline output
    switch ($OutputFormat) {
      "TXT" { $outputObj.Fqdn | Sort-Object -Unique }
      default { $outputObj }
    }
  }
}