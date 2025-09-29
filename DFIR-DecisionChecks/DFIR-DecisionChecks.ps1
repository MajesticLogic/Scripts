<#
.SYNOPSIS
  Remote, read-only Windows DFIR survey over WinRM HTTP (no SSL/TLS).

.DESCRIPTION
  Connects to a target over PowerShell Remoting on TCP 5985 (HTTP) and collects:
    - UTC time & w32tm status
    - OS/build, last boot, uptime
    - RAM (physical & visible) with expected dump size
    - Volumes (Size/Free)
    - Physical disks (allocated vs unallocated)
    - VSS snapshots (text)
  Writes THREE local files with the same basename:
    <OutputPath>\<Computer>_decision_report_<UTC>.json
    <OutputPath>\<Computer>_decision_report_<UTC>.html
    <OutputPath>\<Computer>_decision_report_<UTC>.csv
  Appends one custody-record line (paths + SHA-256).

  Note: Even over HTTP, WinRM encrypts the message content with Kerberos/NTLM
  as long as AllowUnencrypted is FALSE (default). This script does NOT change that.

.PARAMETER ComputerName
  Target host (DNS or IP). WinRM/HTTP must be reachable.

.PARAMETER OutputPath
  Local folder for outputs. Defaults to ".\Reports" under the current directory.

.PARAMETER Credential
  Optional credential to authenticate to the target.

.PARAMETER Port
  Optional HTTP port override (default is 5985). Do NOT use 5986 here.

.PARAMETER CustodyRecordPath
  Optional local path for custody_record.txt. Defaults to <OutputPath>\custody_record.txt.

.PARAMETER Help
  Show usage and examples.

.EXAMPLE
  .\DFIR-RemoteDecisionChecks-HTTP.ps1 -ComputerName WS17

.EXAMPLE
  $cred = Get-Credential
  .\DFIR-RemoteDecisionChecks-HTTP.ps1 -ComputerName 10.10.20.30 -Credential $cred -OutputPath "D:\DFIR\Reports"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)][switch]$Help,
  [Parameter(Mandatory=$true,  Position=0)][string]$ComputerName,
  [Parameter(Mandatory=$false)][string]$OutputPath = (Join-Path (Get-Location) 'Reports'),
  [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
  [Parameter(Mandatory=$false)][int]$Port,
  [Parameter(Mandatory=$false)][string]$CustodyRecordPath
)

if ($Help) {
@"
DFIR-RemoteDecisionChecks-HTTP.ps1  (HTTP 5985 only, no SSL/TLS)

Quick examples:
  .\DFIR-RemoteDecisionChecks-HTTP.ps1 -ComputerName WS17
  $cred = Get-Credential
  .\DFIR-RemoteDecisionChecks-HTTP.ps1 -ComputerName 10.10.20.30 -Credential $cred

If using IP or workgroup/cross-domain, add TrustedHosts on the ANALYST box:
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.10.20.30" -Force
  # multiple: "WS17,10.10.20.30"

Outputs (local):
  <OutputPath>\<Computer>_decision_report_<UTC>.json / .html / .csv
  + custody_record.txt with a single line (paths + SHA-256)
"@ | Write-Host; return
}

$ErrorActionPreference = 'Stop'
try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}

# Output prep
if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
if (-not $CustodyRecordPath) { $CustodyRecordPath = Join-Path $OutputPath 'custody_record.txt' }
$startUtc = (Get-Date).ToUniversalTime()
$stamp    = $startUtc.ToString('yyyyMMddTHHmmssZ')
$base     = Join-Path $OutputPath ("{0}_decision_report_{1}" -f $ComputerName,$stamp)
$jsonPath = "$base.json"; $htmlPath = "$base.html"; $csvPath = "$base.csv"

# Build one scriptblock to minimize remoting overhead
$sb = {
  $res = [ordered]@{}
  $res.GeneratedUTC = (Get-Date).ToUniversalTime().ToString('o')
  $res.Target       = $env:COMPUTERNAME
  try { $res.RemoteUTC = (Get-Date).ToUniversalTime().ToString('o') } catch { $res.RemoteUTC = $null }
  try { $res.TimeService = (w32tm /query /status 2>&1) -join "`r`n" } catch { $res.TimeService = $_ | Out-String }

  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $last = $os.LastBootUpTime.ToUniversalTime()
    $up   = New-TimeSpan -Start $last -End (Get-Date).ToUniversalTime()
    $res.OS = [pscustomobject]@{
      ComputerName = $env:COMPUTERNAME
      Caption      = $os.Caption
      Version      = $os.Version
      Build        = $os.BuildNumber
      LastBootUTC  = $last.ToString('o')
      UptimeDays   = $up.Days
      UptimeHours  = $up.Hours
      UptimeMins   = $up.Minutes
    }
  } catch { $res.OS = $null }

  try {
    $o  = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $res.RAM = [pscustomobject]@{
      PhysicalBytes       = [int64]$cs.TotalPhysicalMemory
      PhysicalGB          = [math]::Round($cs.TotalPhysicalMemory/1GB,2)
      VisibleTotalBytes   = [int64]($o.TotalVisibleMemorySize*1KB)
      VisibleTotalGB      = [math]::Round(($o.TotalVisibleMemorySize*1KB)/1GB,2)
      VisibleFreeBytes    = [int64]($o.FreePhysicalMemory*1KB)
      VisibleFreeGB       = [math]::Round(($o.FreePhysicalMemory*1KB)/1GB,2)
      ExpectedDumpBytes   = [int64]$cs.TotalPhysicalMemory
    }
  } catch { $res.RAM = $null }

  try {
    $res.Volumes = @( Get-Volume | Where-Object DriveLetter | Select-Object `
      DriveLetter, FileSystemLabel, FileSystem,
      @{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}},
      @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,2)}} )
  } catch { $res.Volumes = @() }

  try {
    $disks = @()
    foreach ($d in (Get-Disk -ErrorAction SilentlyContinue)) {
      try {
        $sizeB = [double]$d.Size
        $hasAlloc = $d.PSObject.Properties.Name -contains 'AllocatedSize'
        $allocB = if ($hasAlloc -and $d.AllocatedSize -ne $null) { [double]$d.AllocatedSize }
                  else { [double](@(Get-Partition -DiskNumber $d.Number -ea SilentlyContinue | Measure-Object Size -Sum).Sum) }
        $unallocB = [math]::Max(0, $sizeB - $allocB)
        $disks += [pscustomobject]@{
          DiskNumber       = $d.Number
          FriendlyName     = $d.FriendlyName
          PartitionStyle   = $d.PartitionStyle
          HealthStatus     = $d.HealthStatus
          BusType          = $d.BusType
          IsBoot           = $d.IsBoot
          IsSystem         = $d.IsSystem
          SizeBytes        = [int64]$sizeB
          AllocatedBytes   = [int64]$allocB
          UnallocatedBytes = [int64]$unallocB
          SizeGB           = [math]::Round($sizeB/1GB,2)
          AllocatedGB      = [math]::Round($allocB/1GB,2)
          UnallocatedGB    = [math]::Round($unallocB/1GB,2)
        }
      } catch {
        $disks += [pscustomobject]@{ DiskNumber=$d.Number; FriendlyName=$d.FriendlyName; Error=$_.Exception.Message }
      }
    }
    $res.Disks = $disks
    if ($disks.Count -gt 0) {
      $res.DiskTotals = [pscustomobject]@{
        SizeGB        = [math]::Round((($disks | Measure-Object SizeGB -Sum).Sum),2)
        AllocatedGB   = [math]::Round((($disks | Measure-Object AllocatedGB -Sum).Sum),2)
        UnallocatedGB = [math]::Round((($disks | Measure-Object UnallocatedGB -Sum).Sum),2)
      }
    } else { $res.DiskTotals = $null }
  } catch { $res.Disks = @(); $res.DiskTotals = $null }

  try { $res.VSS = (vssadmin list shadows 2>&1) -join "`r`n" } catch { $res.VSS = $_ | Out-String }

  [pscustomobject]$res
}

# Create session and invoke once over HTTP
$sessionParams = @{ ComputerName = $ComputerName }
if ($Credential) { $sessionParams.Credential = $Credential }
if ($PSBoundParameters.ContainsKey('Port')) { $sessionParams.Port = $Port }  # default 5985
try {
  $sess   = New-PSSession @sessionParams
} catch {
  throw ("Failed to create PSSession to {0}: {1}" -f $ComputerName, $_.Exception.Message)
}

try {
  $report = Invoke-Command -Session $sess -ScriptBlock $sb
} finally {
  Remove-PSSession -Session $sess -ErrorAction SilentlyContinue
}

# Write JSON
$report | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 -FilePath $jsonPath

# Write HTML
$enc = { param($t) try { [System.Web.HttpUtility]::HtmlEncode($t) } catch { $t } }
function TableHtml { param($title,$data)
  if (-not $data) { return "" }
  $frag = $data | ConvertTo-Html -Fragment
  "<h2>$title</h2>`n$frag"
}
$body = @()
$body += "<h1>DFIR Remote Decision Report — $($report.Target) — $($report.GeneratedUTC)</h1>"
$body += TableHtml "OS & Uptime"    $report.OS
$body += TableHtml "RAM Summary"     $report.RAM
$body += TableHtml "Volumes"         $report.Volumes
if ($report.Disks) {
  $diskTable = $report.Disks | Select-Object DiskNumber,FriendlyName,PartitionStyle,HealthStatus,BusType,IsBoot,IsSystem,SizeGB,AllocatedGB,UnallocatedGB
  $body += TableHtml "Disks (Allocated vs Unallocated)" $diskTable
  $body += TableHtml "Disk Totals (GB)" $report.DiskTotals
}
$body += "<h2>Time Service (w32tm)</h2><pre style='white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px;'>$(& $enc $report.TimeService)</pre>"
$body += "<h2>VSS Snapshots</h2><pre style='white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px;'>$(& $enc $report.VSS)</pre>"
$style = "<style>body{font-family:Segoe UI,Arial,Helvetica,sans-serif;margin:20px}table{border-collapse:collapse;margin-bottom:16px}th,td{border:1px solid #ccc;padding:6px 10px}th{background:#f2f2f2}h1{margin-top:0}</style>"
(ConvertTo-Html -Head $style -Body ($body -join "`n")) | Out-File -Encoding UTF8 -FilePath $htmlPath

# Write CSV (flattened)
$rows = @()
if ($report.OS) {
  $rows += [pscustomobject]@{Section='OS';Name='ComputerName';Value=$report.OS.ComputerName}
  $rows += [pscustomobject]@{Section='OS';Name='Caption';Value=$report.OS.Caption}
  $rows += [pscustomobject]@{Section='OS';Name='Version';Value=$report.OS.Version}
  $rows += [pscustomobject]@{Section='OS';Name='Build';Value=$report.OS.Build}
  $rows += [pscustomobject]@{Section='OS';Name='LastBootUTC';Value=$report.OS.LastBootUTC}
  $rows += [pscustomobject]@{Section='OS';Name='UptimeDays';Value=$report.OS.UptimeDays}
  $rows += [pscustomobject]@{Section='OS';Name='UptimeHours';Value=$report.OS.UptimeHours}
  $rows += [pscustomobject]@{Section='OS';Name='UptimeMins';Value=$report.OS.UptimeMins}
}
if ($report.RAM) {
  $rows += [pscustomobject]@{Section='RAM';Name='PhysicalGB';Value=$report.RAM.PhysicalGB}
  $rows += [pscustomobject]@{Section='RAM';Name='VisibleTotalGB';Value=$report.RAM.VisibleTotalGB}
  $rows += [pscustomobject]@{Section='RAM';Name='VisibleFreeGB';Value=$report.RAM.VisibleFreeGB}
  $rows += [pscustomobject]@{Section='RAM';Name='ExpectedDumpBytes';Value=$report.RAM.ExpectedDumpBytes}
}
foreach ($v in ($report.Volumes | ForEach-Object { $_ })) {
  $rows += [pscustomobject]@{Section='Volumes';Name="$($v.DriveLetter): $($v.FileSystemLabel)";Value=("FS={0}; SizeGB={1}; FreeGB={2}" -f $v.FileSystem,$v.SizeGB,$v.FreeGB)}
}
foreach ($d in ($report.Disks | ForEach-Object { $_ })) {
  $rows += [pscustomobject]@{Section='Disks';Name="Disk $($d.DiskNumber) $($d.FriendlyName)";Value=("Style={0}; SizeGB={1}; AllocGB={2}; UnallocGB={3}; Health={4}; Bus={5}; Boot={6}; System={7}" -f $d.PartitionStyle,$d.SizeGB,$d.AllocatedGB,$d.UnallocatedGB,$d.HealthStatus,$d.BusType,$d.IsBoot,$d.IsSystem)}
}
if ($report.TimeService) { $rows += [pscustomobject]@{Section='TimeService';Name='w32tm_first_line';Value=(($report.TimeService -split "`r?`n")[0])} }
if ($report.VSS)         { $rows += [pscustomobject]@{Section='VSS';Name='vssadmin_first_line';Value=(($report.VSS -split "`r?`n")[0])} }
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

# Custody append (local)
$endUtc = (Get-Date).ToUniversalTime()
try { $hJ=(Get-FileHash $jsonPath -Algorithm SHA256).Hash; $hH=(Get-FileHash $htmlPath -Algorithm SHA256).Hash; $hC=(Get-FileHash $csvPath -Algorithm SHA256).Hash } catch { $hJ=$null;$hH=$null;$hC=$null }
$line = "StartUTC={0} | EndUTC={1} | Action=Remote decision survey (HTTP) | Target={2} | OutputsJSON={3} | SHA256_JSON={4} | OutputsHTML={5} | SHA256_HTML={6} | OutputsCSV={7} | SHA256_CSV={8}" -f $startUtc.ToString('o'),$endUtc.ToString('o'),$ComputerName,$jsonPath,$hJ,$htmlPath,$hH,$csvPath,$hC
$line | Out-File -Append -Encoding UTF8 -FilePath $CustodyRecordPath

Write-Host "Created:`n  JSON: $jsonPath`n  HTML: $htmlPath`n  CSV : $csvPath`nAppended custody line to: $CustodyRecordPath"
