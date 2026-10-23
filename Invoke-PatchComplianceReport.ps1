#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a patch-compliance dashboard from WSUS (or a CSV export) and highlights critical gaps.

.DESCRIPTION
    Collects per-server update status and produces a dashboard that shows compliance by server
    group, the servers furthest behind, and any missing updates that address known-critical CVEs.
    Read-only against WSUS.

    Data sources (in order of preference):
      -WsusServer       : query a WSUS server directly (needs the WSUS admin console / API on the host)
      -InputCsv         : a CSV export (columns: Server, Group, OS, MissingUpdates, MissingCritical,
                          LastReportStatusTime, optionally KBs and CVEs) - works anywhere, including
                          SCCM/Intune exports reshaped to these columns
      -Demo             : built-in sample data

.PARAMETER WsusServer
    WSUS server FQDN. Uses the UpdateServices module / assembly on this host.

.PARAMETER WsusPort
    WSUS port (default 8530; 8531 for SSL).

.PARAMETER UseSsl
    Connect to WSUS over SSL.

.PARAMETER InputCsv
    Path to a CSV export to report on instead of querying WSUS.

.PARAMETER CriticalCVEs
    Optional path to a JSON list of {KB, CVE, Title} to highlight. A starter list ships in critical_cves.json.

.PARAMETER StaleReportDays
    Flag servers that have not reported to WSUS in this many days. Default 7.

.PARAMETER OutputPath
    Folder for the dashboard. Default .\PatchReport

.PARAMETER Demo
    Use built-in sample data.

.EXAMPLE
    .\Invoke-PatchComplianceReport.ps1 -Demo

.EXAMPLE
    .\Invoke-PatchComplianceReport.ps1 -WsusServer wsus01.corp.local -UseSsl

.EXAMPLE
    .\Invoke-PatchComplianceReport.ps1 -InputCsv .\wsus-export.csv

.NOTES
    Author : Akhilesh Ayyagari (github.com/aayyagar)
    Version: 1.0.0
    Safe   : read-only; it reports status and never approves or installs updates.
#>
[CmdletBinding()]
param(
    [string]$WsusServer,
    [int]$WsusPort = 8530,
    [switch]$UseSsl,
    [string]$InputCsv,
    [string]$CriticalCVEs = (Join-Path $PSScriptRoot 'critical_cves.json'),
    [int]$StaleReportDays = 7,
    [string]$OutputPath = (Join-Path (Get-Location) 'PatchReport'),
    [switch]$Demo
)

$ErrorActionPreference = 'Stop'
$Script:Version = '1.0.0'
$Script:Now = Get-Date
$Script:Servers = New-Object System.Collections.Generic.List[object]

function Write-Step { param($m) Write-Host "  > $m" -ForegroundColor Cyan }

function New-Server {
    param($Name, $Group, $OS, [int]$Missing, [int]$Critical, $LastReport, $KBs = @(), $CVEs = @())
    $stale = $LastReport -and ($LastReport -lt $Script:Now.AddDays( - $StaleReportDays))
    $state = if ($stale) { 'Stale' } elseif ($Critical -gt 0) { 'Critical' } elseif ($Missing -gt 10) { 'Behind' } elseif ($Missing -gt 0) { 'Minor' } else { 'Compliant' }
    [pscustomobject]@{
        Name = $Name; Group = $Group; OS = $OS
        MissingUpdates = $Missing; MissingCritical = $Critical
        LastReport = $LastReport; Stale = $stale; State = $state
        MissingKBs = @($KBs); CriticalCVEs = @($CVEs)
    }
}

# ---------------------------------------------------------------------------------------------
#  WSUS collection
# ---------------------------------------------------------------------------------------------
function Get-FromWsus {
    [void][reflection.assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration')
    $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WsusServer, $UseSsl.IsPresent, $WsusPort)
    $computers = $wsus.GetComputerTargets()
    foreach ($c in $computers) {
        $summary = $c.GetUpdateInstallationSummary()
        $missing = $summary.NotInstalledCount + $summary.DownloadedCount + $summary.FailedCount
        # Count critical/security updates still needed
        $scope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
        $scope.IncludedInstallationStates = 'NotInstalled', 'Downloaded', 'Failed'
        $needed = $c.GetUpdateInstallationInfoPerUpdate($scope)
        $critCount = 0; $kbs = @(); $cves = @()
        foreach ($u in $needed) {
            try {
                $upd = $wsus.GetUpdate($u.GetUpdate().Id)
                if ($upd.UpdateClassificationTitle -in 'Critical Updates', 'Security Updates') {
                    $critCount++
                    if ($upd.KnowledgebaseArticles) { $kbs += ($upd.KnowledgebaseArticles | ForEach-Object { "KB$_" }) }
                    if ($upd.SecurityBulletins) { $cves += $upd.SecurityBulletins }
                }
            } catch {}
        }
        $grp = ($c.GetComputerTargetGroups() | Select-Object -First 1).Name
        $Script:Servers.Add((New-Server -Name $c.FullDomainName -Group $grp -OS $c.OSDescription `
                    -Missing $missing -Critical $critCount -LastReport $c.LastReportedStatusTime -KBs ($kbs | Select-Object -Unique) -CVEs ($cves | Select-Object -Unique)))
    }
}

# ---------------------------------------------------------------------------------------------
#  CSV collection
# ---------------------------------------------------------------------------------------------
function Get-FromCsv {
    param($Path)
    if (-not (Test-Path $Path)) { throw "CSV not found: $Path" }
    foreach ($row in (Import-Csv $Path)) {
        $lr = $null; if ($row.LastReportStatusTime) { try { $lr = [datetime]$row.LastReportStatusTime } catch {} }
        $kbs = if ($row.KBs) { $row.KBs -split '[;,]' | ForEach-Object { $_.Trim() } } else { @() }
        $cves = if ($row.CVEs) { $row.CVEs -split '[;,]' | ForEach-Object { $_.Trim() } } else { @() }
        $Script:Servers.Add((New-Server -Name $row.Server -Group $row.Group -OS $row.OS `
                    -Missing ([int]$row.MissingUpdates) -Critical ([int]$row.MissingCritical) -LastReport $lr -KBs $kbs -CVEs $cves))
    }
}

# ---------------------------------------------------------------------------------------------
#  Demo
# ---------------------------------------------------------------------------------------------
function Get-DemoData {
    $now = $Script:Now
    $rows = @(
        @('DC01', 'Domain Controllers', 'Windows Server 2019', 0, 0, -1, @(), @()),
        @('DC02', 'Domain Controllers', 'Windows Server 2019', 2, 1, -1, @('KB5062561'), @('CVE-2026-37218')),
        @('DNS01', 'Infrastructure', 'Windows Server 2022', 1, 0, -2, @('KB5062560'), @()),
        @('WSUS01', 'Infrastructure', 'Windows Server 2019', 4, 1, -1, @('KB5062561'), @('CVE-2026-37218')),
        @('WEB01', 'Web Tier', 'Windows Server 2022', 14, 3, -3, @('KB5062561', 'KB5061010', 'KB5060842'), @('CVE-2026-37218', 'CVE-2026-33890')),
        @('WEB02', 'Web Tier', 'Windows Server 2022', 2, 0, -1, @('KB5060842'), @()),
        @('SQL01', 'Database', 'Windows Server 2019', 8, 2, -2, @('KB5062561', 'KB5061010'), @('CVE-2026-37218')),
        @('SQL02', 'Database', 'Windows Server 2019', 0, 0, -1, @(), @()),
        @('APP01', 'App Tier', 'Windows Server 2016', 22, 5, -1, @('KB5062561', 'KB5061010', 'KB5060842', 'KB5059091'), @('CVE-2026-37218', 'CVE-2026-33890', 'CVE-2026-29812')),
        @('APP02', 'App Tier', 'Windows Server 2016', 0, 0, -19, @(), @()),   # stale: not reporting
        @('FILE01', 'File & Print', 'Windows Server 2022', 3, 0, -4, @('KB5060842'), @()),
        @('RDS01', 'Remote Desktop', 'Windows Server 2019', 11, 2, -2, @('KB5062561', 'KB5061010'), @('CVE-2026-37218'))
    )
    foreach ($r in $rows) {
        $Script:Servers.Add((New-Server -Name $r[0] -Group $r[1] -OS $r[2] -Missing $r[3] -Critical $r[4] `
                    -LastReport $now.AddDays($r[5]) -KBs $r[6] -CVEs $r[7]))
    }
}

# ---------------------------------------------------------------------------------------------
#  Dashboard
# ---------------------------------------------------------------------------------------------
function ConvertTo-HtmlSafe { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

function New-Dashboard {
    param([string]$OutFile)
    $e = { param($s) ConvertTo-HtmlSafe $s }
    $total = $Script:Servers.Count
    $compliant = @($Script:Servers | Where-Object State -eq 'Compliant').Count
    $critServers = @($Script:Servers | Where-Object { $_.MissingCritical -gt 0 }).Count
    $staleServers = @($Script:Servers | Where-Object Stale).Count
    $totalCrit = ($Script:Servers | Measure-Object MissingCritical -Sum).Sum
    $pct = if ($total) { [math]::Round(($compliant / $total) * 100) } else { 100 }
    $ring = if ($pct -ge 90) { 'var(--ok)' } elseif ($pct -ge 70) { 'var(--warn)' } else { 'var(--crit)' }
    $dash = [math]::Round(2 * [math]::PI * 52 * $pct / 100, 1)

    # By group
    $groups = $Script:Servers | Group-Object Group | ForEach-Object {
        $g = $_.Group
        $c = @($g | Where-Object State -eq 'Compliant').Count
        $gp = [math]::Round(($c / $_.Count) * 100)
        $crit = ($g | Measure-Object MissingCritical -Sum).Sum
        [pscustomobject]@{ Name = $_.Name; Total = $_.Count; Compliant = $c; Pct = $gp; Critical = $crit }
    } | Sort-Object Pct
    $groupCards = foreach ($g in $groups) {
        $cls = if ($g.Pct -ge 90) { 'ok' } elseif ($g.Pct -ge 70) { 'warn' } else { 'bad' }
        $critTxt = if ($g.Critical -gt 0) { "<span class='gcrit'>$($g.Critical) critical</span>" } else { '' }
        "<div class='gcard $cls'><div class='gh'><b>$(& $e $g.Name)</b><span>$($g.Pct)%</span></div><div class='trk'><div style='width:$($g.Pct)%'></div></div><small>$($g.Compliant)/$($g.Total) compliant $critTxt</small></div>"
    }

    # Critical CVE rollup
    $cveRollup = $Script:Servers | Where-Object { $_.CriticalCVEs.Count } | ForEach-Object {
        $s = $_; $_.CriticalCVEs | ForEach-Object { [pscustomobject]@{ CVE = $_; Server = $s.Name } }
    } | Group-Object CVE | Sort-Object Count -Descending | ForEach-Object {
        "<tr><td class='mono'>$(& $e $_.Name)</td><td>$($_.Count)</td><td class='mut'>$(& $e (($_.Group.Server | Select-Object -First 8) -join ', '))</td></tr>"
    }

    $stateOrder = @{ Critical = 0; Stale = 1; Behind = 2; Minor = 3; Compliant = 4 }
    $rows = foreach ($s in ($Script:Servers | Sort-Object @{e = { $stateOrder[$_.State] } }, @{e = { - $_.MissingCritical } }, @{e = { - $_.MissingUpdates } })) {
        $last = if ($s.LastReport) { $s.LastReport.ToString('yyyy-MM-dd') } else { 'never' }
        $lastCls = if ($s.Stale) { "class='mut warnx'" } else { "class='mut'" }
        $kbs = if ($s.MissingKBs.Count) { (& $e (($s.MissingKBs | Select-Object -First 6) -join ', ')) } else { '-' }
        @"
<tr class='st-$($s.State.ToLower())'>
<td><span class='pill $($s.State.ToLower())'>$($s.State)</span></td>
<td>$(& $e $s.Name)<div class='sub'>$(& $e $s.OS)</div></td>
<td>$(& $e $s.Group)</td>
<td class='num'>$($s.MissingUpdates)</td>
<td class='num crit'>$($s.MissingCritical)</td>
<td $lastCls>$last</td>
<td class='mono kb'>$kbs</td>
</tr>
"@
    }

    $css = @'
:root{--bg:#f3f4f7;--card:#fff;--ink:#151a2c;--mut:#5b6278;--line:#dcdfe7;--soft:#eef0f4;--ok:#17865f;--warn:#b07a00;--bad:#c2691b;--crit:#c8432b;--stale:#6b46c1}
@media (prefers-color-scheme:dark){:root{--bg:#0f1220;--card:#181c2e;--ink:#e9ecf4;--mut:#9ca3ba;--line:#2a3048;--soft:#1f2438;--ok:#3fc48d;--warn:#e7b43b;--bad:#f0a05f;--crit:#f07a62;--stale:#a78bfa;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.w{max-width:1120px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-end;margin-bottom:18px}
h1{margin:0;font-size:1.7rem;letter-spacing:-.02em}.sub{color:var(--mut);font-size:.76rem;font-family:Consolas,ui-monospace,monospace}.mono{font-family:Consolas,ui-monospace,monospace;font-size:.82rem}.mut{color:var(--mut)}
.top{display:grid;grid-template-columns:210px 1fr;gap:16px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}
.score{display:flex;flex-direction:column;align-items:center;gap:4px;text-align:center}.score svg{width:140px;height:140px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.kpi{background:var(--soft);border-radius:10px;padding:13px}.kpi b{display:block;font-size:1.6rem;font-variant-numeric:tabular-nums}.kpi span{font-size:.74rem;color:var(--mut)}
.kpi.crit b{color:var(--crit)}.kpi.stale b{color:var(--stale)}.kpi.ok b{color:var(--ok)}
h2{font-size:1.15rem;margin:22px 0 10px}
.groups{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.gcard{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;border-left:4px solid var(--ok)}.gcard.warn{border-left-color:var(--warn)}.gcard.bad{border-left-color:var(--crit)}
.gh{display:flex;justify-content:space-between;font-weight:600}.gcard small{color:var(--mut);font-size:.76rem}.gcrit{color:var(--crit);font-weight:600;margin-left:6px}
.trk{height:7px;background:var(--soft);border-radius:4px;margin:7px 0 5px;overflow:hidden}.trk div{height:100%;background:var(--ok)}
.gcard.warn .trk div{background:var(--warn)}.gcard.bad .trk div{background:var(--crit)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:10px 13px;border-bottom:1px solid var(--line);font-size:.88rem;vertical-align:top}
th{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);background:var(--soft)}
tr:last-child td{border-bottom:0}.num{text-align:right;font-variant-numeric:tabular-nums}.num.crit{color:var(--crit);font-weight:600}
.sub{color:var(--mut);font-size:.74rem}.kb{font-size:.76rem;color:var(--mut)}.warnx{color:var(--stale)!important}
.pill{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:3px 8px;border-radius:999px;white-space:nowrap;color:#fff}
.pill.critical{background:var(--crit)}.pill.stale{background:var(--stale)}.pill.behind{background:var(--bad)}.pill.minor{background:var(--warn);color:#1a1a1a}.pill.compliant{background:var(--soft);color:var(--ok)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media (max-width:820px){.top{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}.groups{grid-template-columns:1fr}.two{grid-template-columns:1fr}.kb,th:nth-child(7),td:nth-child(7){display:none}}
'@
    @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Patch Compliance Dashboard</title><style>$css</style></head><body><div class="w">
<header><div><div class="mono mut">WSUS / PATCH COMPLIANCE</div><h1>Patch Compliance</h1><div class="sub">$($Script:Now.ToString('yyyy-MM-dd HH:mm')) &middot; $total servers &middot; stale threshold $StaleReportDays days</div></div><div class="mono mut">Patch Compliance Dashboard v$Script:Version</div></header>
<div class="top">
<div class="card score"><svg viewBox="0 0 120 120" role="img" aria-label="Compliance $pct%"><circle cx="60" cy="60" r="52" fill="none" stroke="var(--soft)" stroke-width="10"/><circle cx="60" cy="60" r="52" fill="none" stroke="$ring" stroke-width="10" stroke-linecap="round" stroke-dasharray="$dash 400" transform="rotate(-90 60 60)"/><text x="60" y="56" text-anchor="middle" font-size="26" font-weight="700" fill="var(--ink)">$pct%</text><text x="60" y="76" text-anchor="middle" font-size="10" fill="var(--mut)">compliant</text></svg></div>
<div class="card"><div class="kpis">
<div class="kpi crit"><b>$totalCrit</b><span>Missing critical updates</span></div>
<div class="kpi crit"><b>$critServers</b><span>Servers with critical gaps</span></div>
<div class="kpi stale"><b>$staleServers</b><span>Not reporting ($StaleReportDays+ d)</span></div>
<div class="kpi ok"><b>$compliant / $total</b><span>Fully compliant</span></div>
</div></div></div>
<h2>Compliance by group</h2>
<div class="groups">$($groupCards -join '')</div>
<div class="two">
<div><h2>Servers</h2>
<table><thead><tr><th>State</th><th>Server</th><th>Group</th><th>Missing</th><th>Critical</th><th>Last report</th><th>Missing KBs</th></tr></thead>
<tbody>$($rows -join "`n")</tbody></table></div>
</div>
<h2>Critical CVEs still open</h2>
<table><thead><tr><th>CVE</th><th>Servers affected</th><th>Which</th></tr></thead><tbody>$(if($cveRollup){$cveRollup -join "`n"}else{'<tr><td colspan=3 class=mut>No open critical CVEs mapped.</td></tr>'})</tbody></table>
<p class="sub" style="margin-top:14px">Read-only report. State: Critical (missing security updates), Stale (not reporting), Behind (&gt;10 missing), Minor (1-10), Compliant. Generated by Patch Compliance Dashboard &middot; github.com/aayyagar/patch-compliance-dashboard</p>
</div></body></html>
"@ | Set-Content -Path $OutFile -Encoding UTF8
}

# ---------------------------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host "  Patch Compliance Dashboard v$Script:Version" -ForegroundColor White
Write-Host '  Read-only patch status from WSUS / CSV export' -ForegroundColor DarkGray
Write-Host ''

if ($Demo) { Write-Step 'Demo mode (sample data)'; Get-DemoData }
elseif ($InputCsv) { Write-Step "CSV: $InputCsv"; Get-FromCsv -Path $InputCsv }
elseif ($WsusServer) { Write-Step "WSUS: $WsusServer`:$WsusPort"; Get-FromWsus }
else { throw 'Provide -WsusServer, -InputCsv, or -Demo.' }

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$base = Join-Path $OutputPath ("PatchCompliance_{0}" -f $Script:Now.ToString('yyyyMMdd_HHmm'))
New-Dashboard -OutFile "$base.html"
$Script:Servers | Select-Object Name, Group, OS, State, MissingUpdates, MissingCritical, Stale, @{n = 'LastReport'; e = { if ($_.LastReport) { $_.LastReport.ToString('yyyy-MM-dd') } } }, @{n = 'MissingKBs'; e = { $_.MissingKBs -join ' ' } }, @{n = 'CriticalCVEs'; e = { $_.CriticalCVEs -join ' ' } } |
    Export-Csv "$base.csv" -NoTypeInformation -Encoding UTF8
$Script:Servers | ConvertTo-Json -Depth 4 | Set-Content "$base.json" -Encoding UTF8

$total = $Script:Servers.Count
$compliant = @($Script:Servers | Where-Object State -eq 'Compliant').Count
$pct = if ($total) { [math]::Round(($compliant / $total) * 100) } else { 100 }
Write-Host ''
$col = if ($pct -ge 90) { 'Green' } elseif ($pct -ge 70) { 'Yellow' } else { 'Red' }
Write-Host ("  Compliance: {0}% ({1}/{2} servers)" -f $pct, $compliant, $total) -ForegroundColor $col
foreach ($s in ($Script:Servers | Where-Object { $_.State -ne 'Compliant' } | Sort-Object MissingCritical -Descending)) {
    $c = switch ($s.State) { 'Critical' { 'Red' } 'Stale' { 'Magenta' } 'Behind' { 'DarkYellow' } default { 'Yellow' } }
    Write-Host ("  [{0,-9}] {1,-10} {2} missing ({3} critical)" -f $s.State, $s.Name, $s.MissingUpdates, $s.MissingCritical) -ForegroundColor $c
}
Write-Host ''
Write-Host "  Dashboard: $base.html" -ForegroundColor White
Write-Host ''
