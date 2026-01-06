<#
 =====================================================================
  Script Name : Citrix Akamai GTM PoP Probe
  Developer   : Sameer Sharma (sameer.sharma@citrix.com)
  Date        : 2025-10-10

  Description :
     Performs automated network probes to determine which Akamai GTM
     Point of Presence (PoP) is selected for Citrix Gateway Service
     (global-all.g.nssvc.net) from a given client environment.

     Collects:
        - Local & public DNS resolver info
        - Public IP & geographic location
        - DNS resolution chain for Akamai GTM record
        - Upstream Akamai resolver diagnostics (whoami.ds.akahelp.net)
        - Local time zone & UTC offset

     Results are displayed in console output and saved to CSV.
     This GTM-only version is the future-state tool for Citrix Support.

  Usage :
     PS> .\Get-GatewayPoP.ps1 -Once -Persona "on-premises"
     PS> .\Get-GatewayPoP.ps1 -Iterations 200 -IntervalSeconds 30 -CaseId "123456" -Persona "VPN"
     PS> .\Get-GatewayPoP.ps1 -DurationMinutes 15 -JsonOutput -Customer "Acme" -Persona "remote"

  Developer Notes :
     - nslookup is used for consistent DNS output across environments.
     - The script does not alter system configuration.
     - External lookups use public APIs (ipinfo.io, ifconfig.co, etc.).
     - Data is stored locally; no data is sent to Citrix or Akamai.
     - DNS queries are performed against both the local resolver and
       a public DNS resolver (8.8.8.8). The public resolver is used as
       a neutral reference point to compare Akamai resolver behavior
       and help isolate DNS-driven routing differences without changing
       the client’s production DNS configuration.

  Version History :
     v1.0
        - Initial ITM + GTM probe implementation.
     v1.1
        - Added local time zone & UTC offset capture.
        - Displayed time zone/offset in console and CSV.
        - Increased interval from 10s to 30s (DNS cache expiry).
        - Minor reliability improvements.
     v1.2
        - Transitioned to GTM-only (ITM decommissioned).
        - Removed Cedexis and ITM-specific logic.
        - Added PoP→Location static mapping with GeoIP fallback.
     v1.3
        - Added parameters: Iterations, IntervalSeconds, OutputFolder.
        - Added tagging: CaseId, Customer, ProfileName.
        - Added -Once and -DurationMinutes modes.
        - Added optional JSON output (-JsonOutput).
        - Added self-test mode (-SelfTest) and dependency checks.
        - Added per-run PoP summary at the end.
        - Improved comment-based help / usability for Support.
     v1.4
        - Replaced ProfileName with Persona.
        - Restricted Persona to supported values only: on-premises, remote, VPN, MPLS, Mobile.
        - Updated console output, CSV schema, and output filename tagging to use Persona.
        - Improved data consistency by normalizing Persona to the canonical casing.

  Disclaimer :
     This script is provided "as is" without warranty of any kind,
     express or implied. The developer assumes no liability for any
     damages or losses arising from its use. It is intended solely
     for diagnostic, educational, and non-commercial purposes.
     Use at your own discretion in compliance with local laws,
     network policies, and organizational security guidelines.
 =====================================================================

.SYNOPSIS
    Citrix Akamai GTM PoP Probe for Citrix Gateway Service.

.DESCRIPTION
    Runs repeated DNS and Akamai whoami checks to see which GTM PoP
    a client is routed to, plus resolver and public IP information.
    Includes comparison against a public DNS resolver for diagnostics.

.PARAMETER Persona
    Optional scenario label. Allowed values only:
    on-premises, remote, VPN, MPLS, Mobile

.EXAMPLE
    .\Get-GatewayPoP.ps1 -Once -Persona "VPN"
#>

[CmdletBinding()]
param(
    [int]$HttpTimeoutSec = 5,
    [int]$RetryCount     = 2,
    [switch]$VerboseMode,
    [switch]$RedactPublicIP,

    [ValidateRange(1,10000)]
    [int]$Iterations = 50,

    [ValidateRange(1,600)]
    [int]$IntervalSeconds = 30,

    [ValidateRange(0,100000)]
    [int]$DurationMinutes = 0,

    [switch]$Once,

    [string]$OutputFolder,
    [string]$CaseId,
    [string]$Customer,

    # Persona 
    [ValidateSet('on-premises','remote','VPN','MPLS','Mobile', IgnoreCase=$true)]
    [string]$Persona,

    [switch]$JsonOutput,
    [switch]$SelfTest,
    [switch]$Version
)
$Script:GatewayPoPVersion = '1.4'

# Normalize Persona to canonical casing (so output is consistent)

if ($Persona) {
    switch ($Persona.ToLowerInvariant()) {
        'on-premises' { $Persona = 'on-premises' }
        'remote'      { $Persona = 'remote' }
        'vpn'         { $Persona = 'VPN' }
        'mpls'        { $Persona = 'MPLS' }
        'mobile'      { $Persona = 'Mobile' }
    }
}

# ---------------- TLS SETTINGS ----------------
try {
    $current = [System.Net.ServicePointManager]::SecurityProtocol
    $tls12   = [System.Net.SecurityProtocolType]::Tls12
    try {
        $tls13 = [System.Net.SecurityProtocolType]::Tls13
        [System.Net.ServicePointManager]::SecurityProtocol = $current -bor $tls12 -bor $tls13
    } catch {
        [System.Net.ServicePointManager]::SecurityProtocol = $current -bor $tls12
    }
}
catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

# ---------------------- Helper Functions ----------------------
if ($Version) {
    Write-Host "Citrix Akamai GTM PoP Probe Version $Script:GatewayPoPVersion" -ForegroundColor Cyan
    return
}
function Write-Status {
    param([string]$Msg,[string]$Type = "INFO")
    $ts = (Get-Date).ToString("HH:mm:ss")
    switch ($Type.ToUpper()) {
        "INFO"  { $c = "White" }
        "OK"    { $c = "Green" }
        "WARN"  { $c = "Yellow" }
        "ERROR" { $c = "Red" }
        default { $c = "Gray" }
    }
    Write-Host ("[{0}] [{1}] {2}" -f $ts, $Type, $Msg) -ForegroundColor $c
}

function Invoke-HttpJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Url)

    $attempt = 0
    do {
        try {
            $attempt++
            if ($VerboseMode) { Write-Status "Fetching $Url (attempt $attempt)" "INFO" }
            return Invoke-RestMethod -UseBasicParsing -Uri $Url -TimeoutSec $HttpTimeoutSec -ErrorAction Stop
        } catch {
            if ($attempt -lt $RetryCount) {
                if ($VerboseMode) { Write-Status "Retrying $Url..." "WARN" }
                Start-Sleep -Seconds 1
            } else {
                if ($VerboseMode) {
                    Write-Status "Skipping unreachable URL after $RetryCount retries: $Url" "WARN"
                }
                return $null
            }
        }
    } while ($attempt -lt $RetryCount)
}

function Get-LocalDnsServers {
    [CmdletBinding()]
    param()
    try {
        $ips = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
               ForEach-Object { $_.ServerAddresses } |
               Where-Object { $_ } | Select-Object -Unique
        if (-not $ips) {
            $ips = ipconfig /all | Select-String -Pattern 'DNS Servers' -Context 0,2 |
                   ForEach-Object { $_.ToString() -replace '.*?:\s*','' } |
                   Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -Unique
        }
        return ($ips -join ';')
    } catch {
        Write-Status "Failed to detect local DNS servers ($_)" "WARN"
        return ""
    }
}

function Get-PublicIpInfo {
    [CmdletBinding()]
    param()
    $candidates = @(
        @{ url='https://ipinfo.io/json';      parse={param($j) if($j -and $j.ip){[pscustomobject]@{IP=$j.ip;City=$j.city;Region=$j.region;Country=$j.country;ASN=$j.org}}}} ,
        @{ url='https://ifconfig.co/json';   parse={param($j) if($j -and $j.ip){[pscustomobject]@{IP=$j.ip;City=$j.city;Region=$j.region;Country=$j.country;ASN=$j.asn_org}}}} ,
        @{ url='https://api.ipify.org?format=json'; parse={param($j) if($j -and $j.ip){[pscustomobject]@{IP=$j.ip}}}}
    )
    foreach($c in $candidates){
        $j = Invoke-HttpJson -Url $c.url
        if($j){
            $o = & $c.parse $j
            if($o -and $o.IP){ return $o }
        }
    }
    return [pscustomobject]@{IP='';City='';Region='';Country='';ASN='' }
}

function Resolve-HostDeep {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TargetHost)

    $out = [ordered]@{ Query=$TargetHost; ARecord=''; CNAMEs=@(); PoP=''; Raw='' }

    $rawLines = & cmd /c "nslookup $TargetHost" 2>$null
    $raw = ($rawLines -join "`n").Trim()
    $out.Raw = $raw

    $addresses = @()
    foreach ($line in $rawLines) {
        if ($line -match 'Address:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})') {
            $addresses += $matches[1]
        }
    }
    if ($addresses.Count -gt 0) { $out.ARecord = $addresses[-1] }

    $aliases = @()
    $collect = $false
    foreach ($line in $rawLines) {
        if ($line -match '^Aliases?:\s*(.+)?$') {
            $collect = $true
            if ($matches[1]) { $aliases += $matches[1].Trim() }
            continue
        }
        if ($collect) {
            if ($line -match '^\s+(\S+)') {
                $aliases += $matches[1].Trim()
            } elseif ($line -match '^\s*$') {
                break
            }
        }
    }

    $out.CNAMEs = $aliases
    if ($aliases.Count -gt 0) {
        $popCandidate = $aliases[-1]
        if ($popCandidate) {
            $out.PoP = ($popCandidate.ToString().Trim().TrimEnd('.').ToLowerInvariant())
        }
    }
    return $out
}

function Write-ColoredLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$label,
        [Parameter(Mandatory)][AllowEmptyString()][string]$value,
        [string]$color = 'White'
    )
    if ($null -eq $value) { $value = '' }
    Write-Host (" {0,-17}: {1}" -f $label, $value) -ForegroundColor $color
}

function Parse-Akamai {
    [CmdletBinding()]
    param([string]$raw)

    if(-not $raw){ return [pscustomobject]@{ Resolver=''; ECS=''; IP=''; NS='' } }
    $flat     = ($raw -replace '[\r\n\t]+',' | ')
    $resolver = if ($flat -match 'Address:\s*([^\s\|]+)') { $matches[1].Trim() } else { '' }
    if ($resolver -match '^(192\.168|10\.|172\.|fd|fe80)') { $resolver += ' (local forwarder)' }
    $ecs=''; $ip=''; $ns=''
    if ($flat -match '"ecs"\s*\|\s*"([^"]+)"') { $ecs = $matches[1].Trim() }
    if ($flat -match '"ip"\s*\|\s*"([^"]+)"')  { $ip  = $matches[1].Trim() }
    if ($flat -match '"ns"\s*\|\s*"([^"]+)"')  { $ns  = $matches[1].Trim() }
    [pscustomobject]@{ Resolver=$resolver; ECS=$ecs; IP=$ip; NS=$ns }
}

function Get-PoPLocationByFQDN {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PoPFQDN)

    $key = $PoPFQDN.Trim().TrimEnd('.').ToLowerInvariant()

    $popTable = @(
        @{ "PoP FQDN" = "az-asia-hk.g.nssvc.net";  "Country" = "Hong Kong";      "Location" = "Hong Kong" },
        @{ "PoP FQDN" = "az-asia-se.g.nssvc.net";  "Country" = "Singapore";      "Location" = "Singapore" },
        @{ "PoP FQDN" = "az-aus-e.g.nssvc.net";    "Country" = "Australia";      "Location" = "New South Wales" },
        @{ "PoP FQDN" = "az-bz-s.g.nssvc.net";     "Country" = "Brazil";         "Location" = "Sao Paulo" },
        @{ "PoP FQDN" = "az-ca-c.g.nssvc.net";     "Country" = "Canada";         "Location" = "Toronto" },
        @{ "PoP FQDN" = "az-eu-n.g.nssvc.net";     "Country" = "Ireland";        "Location" = "Dublin" },
        @{ "PoP FQDN" = "az-eu-w.g.nssvc.net";     "Country" = "Netherlands";    "Location" = "Amsterdam" },
        @{ "PoP FQDN" = "az-in-s.g.nssvc.net";     "Country" = "India";          "Location" = "Chennai" },
        @{ "PoP FQDN" = "az-jp-e.g.nssvc.net";     "Country" = "Japan";          "Location" = "Tokyo" },
        @{ "PoP FQDN" = "az-nw-e.g.nssvc.net";     "Country" = "Norway";         "Location" = "Oslo" },
        @{ "PoP FQDN" = "az-uae-n.g.nssvc.net";    "Country" = "UAE";            "Location" = "Dubai" },
        @{ "PoP FQDN" = "az-us-e.g.nssvc.net";     "Country" = "USA";            "Location" = "Virginia" },
        @{ "PoP FQDN" = "az-us-e2.g.nssvc.net";    "Country" = "USA";            "Location" = "Virginia" },
        @{ "PoP FQDN" = "az-us-sc.g.nssvc.net";    "Country" = "USA";            "Location" = "Texas" },
        @{ "PoP FQDN" = "az-us-w.g.nssvc.net";     "Country" = "USA";            "Location" = "California" },
        @{ "PoP FQDN" = "az-za-n.g.nssvc.net";     "Country" = "South Africa";   "Location" = "Johannesburg" },
        @{ "PoP FQDN" = "aws-aus-e.g.nssvc.net";   "Country" = "Australia";      "Location" = "Sydney" },
        @{ "PoP FQDN" = "aws-asia-se.g.nssvc.net"; "Country" = "Singapore";      "Location" = "Singapore" },
        @{ "PoP FQDN" = "aws-asia-tw.g.nssvc.net"; "Country" = "Taiwan";         "Location" = "Taipei" },
        @{ "PoP FQDN" = "aws-bz-s.g.nssvc.net";    "Country" = "Brazil";         "Location" = "Sao Paulo" },
        @{ "PoP FQDN" = "aws-ca-e.g.nssvc.net";    "Country" = "Canada";         "Location" = "Montreal" },
        @{ "PoP FQDN" = "aws-eu-c.g.nssvc.net";    "Country" = "Germany";        "Location" = "Frankfurt" },
        @{ "PoP FQDN" = "aws-eu-w.g.nssvc.net";    "Country" = "France";         "Location" = "Paris" },
        @{ "PoP FQDN" = "aws-in-sc.g.nssvc.net";   "Country" = "India";          "Location" = "Hyderabad" },
        @{ "PoP FQDN" = "aws-in-w.g.nssvc.net";    "Country" = "India";          "Location" = "Mumbai" },
        @{ "PoP FQDN" = "aws-jp-w.g.nssvc.net";    "Country" = "Japan";          "Location" = "Osaka" },
        @{ "PoP FQDN" = "aws-uk-se.g.nssvc.net";   "Country" = "UK";             "Location" = "London" },
        @{ "PoP FQDN" = "aws-us-e.g.nssvc.net";    "Country" = "USA";            "Location" = "North Virginia" },
        @{ "PoP FQDN" = "aws-us-nc.g.nssvc.net";   "Country" = "USA";            "Location" = "Ohio" },
        @{ "PoP FQDN" = "aws-us-w.g.nssvc.net";    "Country" = "USA";            "Location" = "North California" }
    )

    $result = $popTable | Where-Object {
        $fqdn = $_."PoP FQDN"
        if (-not $fqdn) { return $false }
        ($fqdn.ToString().Trim().TrimEnd('.').ToLowerInvariant()) -eq $key
    } | Select-Object -First 1

    if ($result) {
        return [PSCustomObject]@{ City = $result.Location; Country = $result.Country }
    }
    return [PSCustomObject]@{ City=''; Country='' }
}

function Get-GeoForIP {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IP)

    $candidates = @(
        "https://ipinfo.io/$IP/json",
        "https://ifconfig.co/json?ip=$IP"
    )

    foreach ($url in $candidates) {
        $j = Invoke-HttpJson -Url $url
        if ($j) {
            $city    = $j.city
            $country = $j.country
            if ($city -or $country) {
                return [pscustomobject]@{ City=$city; Country=$country }
            }
        }
    }
    return [pscustomobject]@{ City=''; Country='' }
}

function Get-LocalTimeInfo {
    [CmdletBinding()]
    param()
    try {
        $tz        = Get-TimeZone
        $localTime = (Get-Date).ToLocalTime()
        return [pscustomobject]@{
            LocalTime   = $localTime.ToString("yyyy-MM-dd HH:mm:ss")
            TimeZone    = $tz.DisplayName
            TimeZoneId  = $tz.Id
            UtcOffset   = $tz.BaseUtcOffset.TotalHours
        }
    } catch {
        return [pscustomobject]@{
            LocalTime   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            TimeZone    = "Unknown"
            TimeZoneId  = "Unknown"
            UtcOffset   = 0
        }
    }
}

function Test-Dependencies {
    [CmdletBinding()]
    param()
    if (-not (Get-Command nslookup -ErrorAction SilentlyContinue)) {
        Write-Status "Missing required tool: nslookup" "ERROR"
        throw "Missing dependency: nslookup"
    }
}

# ---------------------- MAIN EXECUTION ----------------------

if ($Once) {
    $Iterations = 1
} elseif ($DurationMinutes -gt 0) {
    $Iterations = [math]::Max(1,[int]([TimeSpan]::FromMinutes($DurationMinutes).TotalSeconds / $IntervalSeconds))
}

$scriptDir = if ($OutputFolder) { $OutputFolder }
elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
else { (Get-Location).Path }

if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$base  = "Citrix_PoP_Probe"
if ($CaseId)  { $base += "_Case-$CaseId" }
if ($Persona) { $base += "_Persona-$Persona" }

$outFile = Join-Path $scriptDir ("{0}_{1}.csv" -f $base, $stamp)

Test-Dependencies

if ($SelfTest) {
    Write-Status "Running self-test..." "INFO"
    $gtm = Resolve-HostDeep -TargetHost "global-all.g.nssvc.net"
    if (-not $gtm.ARecord) { throw "Self-test failed: cannot resolve global-all.g.nssvc.net" }

    $akaRaw = (& cmd /c "nslookup -type=txt whoami.ds.akahelp.net" 2>$null | Out-String).Trim()
    if (-not $akaRaw) { throw "Self-test failed: Akamai whoami lookup failed" }

    Write-Status "Self-test succeeded." "OK"
    return
}

Write-Status "Starting Citrix Akamai GTM PoP Probe with $Iterations iterations..." "INFO"
Write-Host "Output file (CSV): $outFile" -ForegroundColor Yellow
if ($JsonOutput) {
    $jsonFilePreview = [System.IO.Path]::ChangeExtension($outFile, '.json')
    Write-Host "JSON output will be written to: $jsonFilePreview" -ForegroundColor Yellow
}

$allResults = @()

for ($i = 1; $i -le $Iterations; $i++) {
    Write-Host "`n=== Iteration $i of $Iterations ===" -ForegroundColor Cyan

    $timeInfo   = Get-LocalTimeInfo
    $timestamp  = $timeInfo.LocalTime
    $timeZone   = $timeInfo.TimeZone
    $computer   = $env:COMPUTERNAME
    $user       = $env:USERNAME
    $localDns   = Get-LocalDnsServers
    $pub        = Get-PublicIpInfo
    $publicIP   = if ($RedactPublicIP) { "<redacted>" } else { $pub.IP }
    $publicGeo  = "$($pub.City), $($pub.Region), $($pub.Country)"

    $gtm = Resolve-HostDeep -TargetHost "global-all.g.nssvc.net"

    $gtmGeo = if ($gtm.PoP) {
        $g = Get-PoPLocationByFQDN -PoPFQDN $gtm.PoP
        if ($g.City -or $g.Country) { $g }
        elseif ($gtm.ARecord) { Get-GeoForIP -IP $gtm.ARecord }
        else { [pscustomobject]@{City='';Country=''} }
    } else { [pscustomobject]@{City='';Country=''} }

    $akamaiLocalRaw  = (& cmd /c "nslookup -type=txt whoami.ds.akahelp.net" 2>$null | Out-String).Trim()
    $akamaiPublicRaw = (& cmd /c "nslookup -type=txt whoami.ds.akahelp.net 8.8.8.8" 2>$null | Out-String).Trim()

    $akaLocal = Parse-Akamai $akamaiLocalRaw
    $akaPub   = Parse-Akamai $akamaiPublicRaw

    if ($CaseId)   { Write-ColoredLine "Case Id"   $CaseId }
    if ($Customer) { Write-ColoredLine "Customer"  $Customer }
    if ($Persona)  { Write-ColoredLine "Persona"   $Persona }

    Write-ColoredLine "Timestamp"  $timestamp
    Write-ColoredLine "Time Zone"  $timeZone
    Write-ColoredLine "UTC Offset" ("UTC {0:+#;-#;0}" -f $timeInfo.UtcOffset)
    Write-ColoredLine "Computer"   $computer
    Write-ColoredLine "User"       $user
    Write-ColoredLine "Local DNS"  $localDns
    Write-ColoredLine "Public IP"  $publicIP
    Write-ColoredLine "Public Geo" $publicGeo
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray

    Write-ColoredLine "GTM PoP Selected" $gtm.PoP 'Green'
    Write-ColoredLine "GTM Geo"          ("{0}, {1}" -f $gtmGeo.City,$gtmGeo.Country) 'Green'
    Write-ColoredLine "Upstream Akamai (Local)" ("Resolver: {0} | ECS: {1} | IP: {2} | NS: {3}" -f $akaLocal.Resolver, $akaLocal.ECS, $akaLocal.IP, $akaLocal.NS)
    Write-ColoredLine "Upstream Akamai"        ("Resolver: {0} | ECS: {1} | IP: {2} | NS: {3}" -f $akaPub.Resolver, $akaPub.ECS, $akaPub.IP, $akaPub.NS)
    Write-Host "-----------------------------------------" -ForegroundColor DarkGray

    $csvObj = [pscustomobject]@{
        CaseId        = $CaseId
        Customer      = $Customer
        Persona       = $Persona
        Timestamp     = $timestamp
        TimeZone      = $timeZone
        UtcOffset     = $timeInfo.UtcOffset
        Computer      = $computer
        User          = $user
        LocalDNS      = $localDns
        PublicIP      = $publicIP
        PublicGeo     = $publicGeo
        GTM_PoP       = $gtm.PoP
        GTM_Geo       = "$($gtmGeo.City), $($gtmGeo.Country)"
        Akamai_Local  = "Resolver: $($akaLocal.Resolver) | ECS: $($akaLocal.ECS) | IP: $($akaLocal.IP) | NS: $($akaLocal.NS)"
        Akamai_Public = "Resolver: $($akaPub.Resolver) | ECS: $($akaPub.ECS) | IP: $($akaPub.IP) | NS: $($akaPub.NS)"
    }

    if (Test-Path $outFile) { $csvObj | Export-Csv -Path $outFile -Append -NoTypeInformation }
    else { $csvObj | Export-Csv -Path $outFile -NoTypeInformation }

    $allResults += $csvObj

    Write-Status "[Iteration $i] Results appended to: $outFile" "OK"
    if ($i -lt $Iterations) {
        Write-Status "Sleeping for $IntervalSeconds seconds..." "INFO"
        Start-Sleep -Seconds $IntervalSeconds
    }
}

if ($JsonOutput -and $allResults.Count -gt 0) {
    $jsonFile = [System.IO.Path]::ChangeExtension($outFile, '.json')
    $allResults | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonFile -Encoding UTF8
    Write-Status "JSON results written to: $jsonFile" "OK"
}

if ($allResults.Count -gt 0) {
    $summary = $allResults | Group-Object GTM_PoP | Select-Object Name, Count
    Write-Host "`n=== GTM PoP Summary (by occurrence) ===" -ForegroundColor Cyan
    $summary | Sort-Object Count -Descending | Format-Table -AutoSize
}

Write-Host "`nCompleted $Iterations iterations." -ForegroundColor Cyan
Write-Host "Final CSV results available at: $outFile" -ForegroundColor Yellow
if ($JsonOutput) { Write-Host "JSON results also generated." -ForegroundColor Yellow }
Write-Host "=========================================" -ForegroundColor DarkGray