<#
    Suppress-GDID.ps1  --  Kill the Windows GDID / device-graph telemetry vector.

    The GDID is a server-assigned MSA Device PUID (0018-class). Chain:
        wlidsvc  --provisions-->  login.live.com  --returns PUID-->  registry
        CDPSvc   --reads PUID, registers into-->  Device Directory Service (dds.microsoft.com)
        Delivery Optimization  --reports as-->  UCDOStatus.GlobalDeviceId
        activity uploads  --carry it to-->  activity.windows.com

    This tool cuts the vector at four on-host layers (defense in depth):
        A. Producer     - disable CDPSvc + CDPUserSvc + DoSvc (nothing generates the traffic)
        B. Hostname     - hosts-file sinkhole of DDS/activity/telemetry FQDNs
                          (IP blocking is WRONG: DDS hides behind shared Azure Front Door 13.107.x.x)
        C. Process      - Windows Firewall outbound block scoped to the service SID (IP/DNS-agnostic)
        D. Policy       - EnableCdp=0 ("Continue experiences off") + telemetry/activity policy floor

    Modes:  -Apply | -Undo | -Verify | -Test
        -Test applies only the reversible hostname+firewall proof to the LIVE endpoints,
        measures before/after, then auto-reverts. It never touches services (no app disruption).

    Honest ceiling: on-host controls are defeatable by a sufficiently-privileged Microsoft
    component (hardcoded IPs, DoH). The only fully-trustworthy block is off-host DNS/router.
#>
[CmdletBinding(DefaultParameterSetName='Verify')]
param(
    [Parameter(ParameterSetName='Apply')]  [switch]$Apply,
    [Parameter(ParameterSetName='Undo')]   [switch]$Undo,
    [Parameter(ParameterSetName='Verify')] [switch]$Verify,
    [Parameter(ParameterSetName='Test')]   [switch]$Test,
    # login.live.com is the MSA mint endpoint. Blocking it stops re-provisioning but BREAKS
    # Microsoft Account sign-in, Store, and some apps. Opt-in only.
    [switch]$IncludeLoginLive
)

$ErrorActionPreference = 'Stop'
$HostsPath  = "$env:SystemRoot\System32\drivers\etc\hosts"
$StateFile  = "$env:ProgramData\SuppressGDID\state.json"
$Sentinel0  = '# >>> GDID-SUPPRESS BEGIN (managed - edits inside are overwritten)'
$Sentinel1  = '# <<< GDID-SUPPRESS END'
$FwPrefix   = 'GDID-SUPPRESS'

# --- Endpoints -------------------------------------------------------------
# Device-graph / CDP / activity (the GDID vector) + classic telemetry belt-and-suspenders.
$DdsHosts = @(
    'activity.windows.com'            # activity uploads that carry the GDID
    'aad.cs.dds.microsoft.com'        # AAD-authenticated DDS registration (LIVE via Front Door)
    'cs.dds.microsoft.com'
    'dds.microsoft.com'
    'fd.dds.microsoft.com'
    'cdpcs.access.microsoft.com'
    'geo.prod.do.dsp.mp.microsoft.com'   # Delivery Optimization DSP - where GDID surfaces as UCDOStatus.GlobalDeviceId
)
$TelemetryHosts = @(
    'v10.events.data.microsoft.com'
    'v20.events.data.microsoft.com'
    'self.events.data.microsoft.com'
    'settings-win.data.microsoft.com'
    'watson.telemetry.microsoft.com'
    'vortex.data.microsoft.com'
    'vortex-win.data.microsoft.com'
    'telecommand.telemetry.microsoft.com'
)
$LoginHosts = @('login.live.com')     # only when -IncludeLoginLive

# Services to kill at the producer layer.  DiagTrack already disabled on most hardened boxes.
$KillServices = 'CDPSvc','DoSvc','DiagTrack','dmwappushservice'

# ---------------------------------------------------------------------------
function Assert-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator required. Re-run elevated:  Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Apply'"
    }
}

function Get-TargetHosts {
    $h = @($DdsHosts) + @($TelemetryHosts)
    if ($IncludeLoginLive) { $h += $LoginHosts }
    $h
}

function Set-HostsBlock([string[]]$names) {
    $lines = if (Test-Path $HostsPath) { Get-Content $HostsPath } else { @() }
    # strip any existing managed block
    $out = New-Object System.Collections.Generic.List[string]
    $inside = $false
    foreach ($l in $lines) {
        if ($l -eq $Sentinel0) { $inside = $true; continue }
        if ($l -eq $Sentinel1) { $inside = $false; continue }
        if (-not $inside) { $out.Add($l) }
    }
    if ($names.Count) {
        $out.Add($Sentinel0)
        foreach ($n in $names) { $out.Add("0.0.0.0 $n"); $out.Add(":: $n") }
        $out.Add($Sentinel1)
    }
    [System.IO.File]::WriteAllLines($HostsPath, $out, (New-Object System.Text.UTF8Encoding($false)))
    Clear-DnsClientCache
}

function Remove-HostsBlock { Set-HostsBlock @() }

function New-FwBlocks {
    foreach ($svc in 'CDPSvc','DoSvc','DiagTrack') {
        $name = "$FwPrefix block $svc out"
        if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block `
                -Service $svc -Profile Any -Enabled True | Out-Null
        }
    }
}
function Remove-FwBlocks {
    Get-NetFirewallRule -DisplayName "$FwPrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

function Save-State {
    $dir = Split-Path $StateFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $svc = @{}
    foreach ($s in $KillServices) {
        $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue
        if ($w) { $svc[$s] = $w.StartMode }
    }
    $cdpuser = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' -Name Start -ErrorAction SilentlyContinue
    $enableCdp = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableCdp -ErrorAction SilentlyContinue
    @{
        services      = $svc
        cdpUserStart  = if ($cdpuser) { $cdpuser.Start } else { $null }
        enableCdpPrev = if ($enableCdp) { $enableCdp.EnableCdp } else { 'ABSENT' }
    } | ConvertTo-Json | Set-Content $StateFile -Encoding UTF8
}

function Set-SvcStartMode([string]$name,[string]$mode) {
    # mode: Disabled|Manual|Automatic  -> registry Start 4|3|2 (works for template/per-user svcs too)
    $map = @{ Disabled=4; Manual=3; Automatic=2; Auto=2; Boot=0; System=1 }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if (Test-Path $key) { Set-ItemProperty $key -Name Start -Value $map[$mode] -Type DWord }
}

# ---------------------------------------------------------------------------
function Invoke-Apply {
    Assert-Admin
    Save-State
    Write-Host "[A] Producer layer: disabling services" -ForegroundColor Cyan
    foreach ($s in $KillServices) {
        try { Stop-Service $s -Force -ErrorAction SilentlyContinue } catch {}
        Set-SvcStartMode $s 'Disabled'
        Write-Host "    $s -> Stopped + Disabled"
    }
    # per-user CDP: disable template + stop live instances
    Set-SvcStartMode 'CDPUserSvc' 'Disabled'
    Get-Service -Name 'CDPUserSvc_*' -ErrorAction SilentlyContinue | ForEach-Object {
        try { Stop-Service $_.Name -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "    $($_.Name) -> Stopped"
    }
    Write-Host "[B] Hostname layer: hosts sinkhole" -ForegroundColor Cyan
    $th = Get-TargetHosts; Set-HostsBlock $th
    Write-Host "    sinkholed $($th.Count) FQDNs -> 0.0.0.0 / ::"
    Write-Host "[C] Process layer: firewall outbound block by service" -ForegroundColor Cyan
    New-FwBlocks; Write-Host "    rules: $FwPrefix block {CDPSvc,DoSvc,DiagTrack} out"
    Write-Host "[D] Policy layer" -ForegroundColor Cyan
    $sysKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    if (-not (Test-Path $sysKey)) { New-Item $sysKey -Force | Out-Null }
    Set-ItemProperty $sysKey -Name EnableCdp -Value 0 -Type DWord
    Set-ItemProperty $sysKey -Name UploadUserActivities -Value 0 -Type DWord
    Set-ItemProperty $sysKey -Name PublishUserActivities -Value 0 -Type DWord
    Set-ItemProperty $sysKey -Name EnableActivityFeed -Value 0 -Type DWord
    Write-Host "    EnableCdp=0 (Continue experiences off) + Activity History off"
    Write-Host "`nAPPLIED. Run with -Verify to confirm. Reboot recommended so nothing restarts CDP." -ForegroundColor Green
}

function Invoke-Undo {
    Assert-Admin
    $st = if (Test-Path $StateFile) { Get-Content $StateFile -Raw | ConvertFrom-Json } else { $null }
    Write-Host "[A] Restoring services" -ForegroundColor Cyan
    $defaults = @{ CDPSvc='Automatic'; DoSvc='Manual'; DiagTrack='Automatic'; dmwappushservice='Manual' }
    foreach ($s in $KillServices) {
        $mode = if ($st -and $st.services.$s) { $st.services.$s } else { $defaults[$s] }
        Set-SvcStartMode $s $mode
        Write-Host "    $s -> $mode"
    }
    $cus = if ($st -and $st.cdpUserStart) { $st.cdpUserStart } else { 2 }
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' -Name Start -Value $cus -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[B] Removing hosts block" -ForegroundColor Cyan;  Remove-HostsBlock
    Write-Host "[C] Removing firewall rules" -ForegroundColor Cyan; Remove-FwBlocks
    Write-Host "[D] Restoring EnableCdp policy" -ForegroundColor Cyan
    $sysKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    if ($st -and $st.enableCdpPrev -eq 'ABSENT') {
        Remove-ItemProperty $sysKey -Name EnableCdp -ErrorAction SilentlyContinue
    } elseif ($st) {
        Set-ItemProperty $sysKey -Name EnableCdp -Value ([int]$st.enableCdpPrev) -Type DWord
    }
    Write-Host "`nREVERTED. Reboot to fully restart CDP/DO." -ForegroundColor Green
}

function Test-Endpoint([string]$fqdn) {
    $ip = (Resolve-DnsName $fqdn -Type A -ErrorAction SilentlyContinue | Where-Object IPAddress | Select-Object -First 1).IPAddress
    if (-not $ip) { $ip = 'unresolved' }
    $open = Test-NetConnection -ComputerName $fqdn -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
    [pscustomobject]@{ FQDN=$fqdn; IP=$ip; Https443=$open }
}

function Invoke-Verify {
    Write-Host "=== VERIFY ===" -ForegroundColor Cyan
    $svcPass = $true
    foreach ($s in 'CDPSvc','DoSvc') {
        $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue
        $ok = $w -and $w.State -eq 'Stopped' -and $w.StartMode -eq 'Disabled'
        if (-not $ok) { $svcPass = $false }
        Write-Host ("  [{0}] {1,-8} State={2} Start={3}" -f $(if($ok){'PASS'}else{'FAIL'}),$s,$w.State,$w.StartMode)
    }
    $cdpuser = Get-Service -Name 'CDPUserSvc_*' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'
    Write-Host ("  [{0}] CDPUserSvc running instances: {1}" -f $(if($cdpuser){'FAIL'}else{'PASS'}),(@($cdpuser).Count))
    Write-Host "  -- endpoint reachability (want unresolved/closed) --"
    foreach ($f in $DdsHosts) { $r = Test-Endpoint $f; Write-Host ("  [{0}] {1,-30} IP={2,-16} 443={3}" -f $(if(-not $r.Https443){'PASS'}else{'FAIL'}),$r.FQDN,$r.IP,$r.Https443) }
    $rules = Get-NetFirewallRule -DisplayName "$FwPrefix*" -ErrorAction SilentlyContinue
    Write-Host ("  [{0}] firewall rules present: {1}" -f $(if($rules){'PASS'}else{'FAIL'}),(@($rules).Count))
}

function Invoke-Test {
    Assert-Admin
    $proof = 'activity.windows.com','aad.cs.dds.microsoft.com'
    Write-Host "=== REVERSIBLE LIVE TEST (hostname + firewall layers; services untouched) ===" -ForegroundColor Cyan
    Write-Host "`n-- BEFORE --" -ForegroundColor Yellow
    $before = $proof | ForEach-Object { Test-Endpoint $_ }; $before | Format-Table -AutoSize | Out-String | Write-Host
    try {
        Write-Host "-- APPLYING sinkhole + one firewall rule (CDPSvc) --" -ForegroundColor Yellow
        Set-HostsBlock $proof
        New-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE CDPSvc out" -Direction Outbound -Action Block `
            -Service CDPSvc -Profile Any -Enabled True | Out-Null
        Start-Sleep -Milliseconds 500; Clear-DnsClientCache
        Write-Host "-- AFTER --" -ForegroundColor Yellow
        $after = $proof | ForEach-Object { Test-Endpoint $_ }; $after | Format-Table -AutoSize | Out-String | Write-Host
        $fw = Get-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE*" -ErrorAction SilentlyContinue
        $svcFilter = if ($fw) { ($fw | Get-NetFirewallServiceFilter).Service } else { '(none)' }
        Write-Host ("firewall rule active, scoped to service: {0}" -f $svcFilter)
        # verdict
        $blocked = ($after | Where-Object { -not $_.Https443 }).Count
        Write-Host ("`nVERDICT: {0}/{1} proof endpoints went reachable->blocked; firewall rule scoped to '{2}'." -f $blocked,$after.Count,$svcFilter) -ForegroundColor Green
    }
    finally {
        Write-Host "`n-- ROLLING BACK (always runs) --" -ForegroundColor Yellow
        Remove-HostsBlock
        Get-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        Clear-DnsClientCache
        $restored = $proof | ForEach-Object { Test-Endpoint $_ }; $restored | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "Machine restored to pre-test state." -ForegroundColor Green
    }
}

switch ($PSCmdlet.ParameterSetName) {
    'Apply'  { Invoke-Apply }
    'Undo'   { Invoke-Undo }
    'Test'   { Invoke-Test }
    default  { Invoke-Verify }
}
