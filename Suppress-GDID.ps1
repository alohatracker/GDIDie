<#
    Suppress-GDID.ps1  --  Kill the Windows GDID / device-graph telemetry vector.
    Version 1.2.0

    The GDID is a server-assigned MSA Device PUID (0018-class). Chain:
        wlidsvc  --provisions-->  login.live.com  --returns PUID-->  registry
        CDPSvc   --reads PUID, registers into-->  Device Directory Service (dds.microsoft.com)
        Delivery Optimization  --reports as-->  UCDOStatus.GlobalDeviceId
        activity uploads  --carry it to-->  activity.windows.com

    Four on-host layers (defense in depth):
        A. Producer  - disable CDPSvc + CDPUserSvc + DoSvc (nothing generates the traffic)
        B. Hostname  - hosts-file sinkhole of DDS/activity/telemetry FQDNs
                       (IP blocking is WRONG: DDS hides behind shared Azure Front Door 13.107.x.x)
        C. Process   - Windows Firewall outbound block scoped to the service SID (IP/DNS-agnostic)
        D. Policy    - EnableCdp=0 ("Continue experiences off") + activity policy floor
    Plus durability: a SYSTEM scheduled task re-applies after Windows servicing re-enables CDP.

    Modes:  -Apply | -Undo | -Verify | -Test        (add -IncludeLoginLive / -NoPersist to -Apply)
    Exit codes: 0 = success/all-pass, 1 = verification failure, 2 = not elevated / fatal.

    Honest ceiling: on-host controls are defeatable by a sufficiently-privileged Microsoft
    component (hardcoded IPs, DoH). The fully-trustworthy block is off-host DNS/router.

    Testability: pure helpers are dot-source safe (Tests/Run-Tests.ps1 loads this with `. ` and
    the dispatcher at the bottom does not fire).
#>
[CmdletBinding(DefaultParameterSetName='Verify')]
param(
    [Parameter(ParameterSetName='Apply')]  [switch]$Apply,
    [Parameter(ParameterSetName='Undo')]   [switch]$Undo,
    [Parameter(ParameterSetName='Verify')] [switch]$Verify,
    [Parameter(ParameterSetName='Test')]   [switch]$Test,
    [switch]$IncludeLoginLive,   # also sinkhole login.live.com (breaks MSA sign-in / Store). Opt-in.
    [switch]$NoPersist           # -Apply: skip the re-apply scheduled task (used by the task itself)
)

$ErrorActionPreference = 'Stop'
$Version    = '1.2.0'
$HostsPath  = "$env:SystemRoot\System32\drivers\etc\hosts"
$InstallDir = "$env:ProgramData\SuppressGDID"
$StateFile  = "$InstallDir\state.json"
$LogDir     = "$InstallDir\logs"
$InstalledScript = "$InstallDir\Suppress-GDID.ps1"
$TaskName   = 'GDIDie-Enforce'
$Sentinel0  = '# >>> GDID-SUPPRESS BEGIN (managed - edits inside are overwritten)'
$Sentinel1  = '# <<< GDID-SUPPRESS END'
$FwPrefix   = 'GDID-SUPPRESS'
$script:Fail = 0

# --- Endpoints -------------------------------------------------------------
$DdsHosts = @(
    'activity.windows.com'               # activity uploads that carry the GDID
    'aad.cs.dds.microsoft.com'           # AAD-authenticated DDS registration (LIVE via Front Door)
    'cs.dds.microsoft.com'
    'dds.microsoft.com'
    'fd.dds.microsoft.com'
    'cdpcs.access.microsoft.com'
    'geo.prod.do.dsp.mp.microsoft.com'   # Delivery Optimization DSP - GDID surfaces as UCDOStatus.GlobalDeviceId
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
$LoginHosts   = @('login.live.com')
$KillServices = 'CDPSvc','DoSvc','DiagTrack','dmwappushservice'

# --- pure, dot-source-testable helpers -------------------------------------
function Remove-ManagedBlock([string[]]$lines) {
    # strip everything between the sentinels (inclusive). Pure: returns lines.
    $out = New-Object System.Collections.Generic.List[string]
    $inside = $false
    foreach ($l in $lines) {
        if ($l -eq $Sentinel0) { $inside = $true; continue }
        if ($l -eq $Sentinel1) { $inside = $false; continue }
        if (-not $inside) { $out.Add($l) }
    }
    ,$out.ToArray()
}
function Add-ManagedBlock([string[]]$lines,[string[]]$names) {
    # append a fresh managed block for $names. Pure: returns lines.
    $out = New-Object System.Collections.Generic.List[string]
    (Remove-ManagedBlock $lines) | ForEach-Object { $out.Add($_) }
    if ($names.Count) {
        $out.Add($Sentinel0)
        foreach ($n in $names) { $out.Add("0.0.0.0 $n"); $out.Add(":: $n") }
        $out.Add($Sentinel1)
    }
    ,$out.ToArray()
}
function Update-SavedOriginal([hashtable]$saved,[string]$key,$current,$disabledValue) {
    # Record the ORIGINAL exactly once (first-write-wins), and never record an
    # already-disabled state as the original (would make -Undo restore Disabled).
    if (-not $saved.ContainsKey($key) -and "$current" -ne "$disabledValue") { $saved[$key] = $current }
    $saved
}

# --- environment helpers ---------------------------------------------------
function Assert-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Administrator required. Re-run elevated:" -ForegroundColor Red
        Write-Host "  Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Apply'"
        exit 2
    }
}
function Initialize-Dir([string]$d) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }

function New-HardenedAcl {
    # Explicit DACL for the install dir: SYSTEM/Administrators full, standard Users read-only,
    # inheritance disabled. Closes the writable-directory-feeding-a-SYSTEM-task weakness so a
    # standard user cannot place files in the folder the GDIDie-Enforce SYSTEM task runs from.
    # Pure (no filesystem) so it is unit-testable.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)   # protect from inheritance; drop inherited ACEs
    $inh   = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $none  = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $full  = [System.Security.AccessControl.FileSystemRights]::FullControl
    $rx    = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    foreach ($r in @(@{Sid='S-1-5-18';R=$full}, @{Sid='S-1-5-32-544';R=$full}, @{Sid='S-1-5-32-545';R=$rx})) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($r.Sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$r.R,$inh,$none,$allow)))
    }
    $acl
}
function Protect-InstallDir {
    Initialize-Dir $InstallDir
    try { Set-Acl -Path $InstallDir -AclObject (New-HardenedAcl) } catch { Write-Verbose $_.Exception.Message }
}
function Start-AuditLog([string]$mode) {
    Initialize-Dir $LogDir
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $log = "$LogDir\gdid-$mode-$stamp.log"
    try { Start-Transcript -Path $log -Force | Out-Null } catch { Write-Verbose $_.Exception.Message }
    return $log
}

function Set-HostsBlock([string[]]$names) {
    $lines = if (Test-Path $HostsPath) { Get-Content $HostsPath } else { @() }
    $new = Add-ManagedBlock $lines $names
    [System.IO.File]::WriteAllLines($HostsPath, $new, (New-Object System.Text.UTF8Encoding($false)))
    Clear-DnsClientCache
}
function Remove-HostsBlock {
    $lines = if (Test-Path $HostsPath) { Get-Content $HostsPath } else { @() }
    $new = Remove-ManagedBlock $lines
    [System.IO.File]::WriteAllLines($HostsPath, $new, (New-Object System.Text.UTF8Encoding($false)))
    Clear-DnsClientCache
}
function Test-HostsBlockPresent {
    if (-not (Test-Path $HostsPath)) { return $false }
    [bool]((Get-Content $HostsPath) -contains $Sentinel0)
}

function New-FwBlock {
    foreach ($svc in 'CDPSvc','DoSvc','DiagTrack') {
        $name = "$FwPrefix block $svc out"
        if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block `
                -Service $svc -Profile Any -Enabled True | Out-Null
        }
    }
}
function Remove-FwBlock { Get-NetFirewallRule -DisplayName "$FwPrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule }

function Set-SvcStartMode([string]$name,[string]$mode) {
    $map = @{ Disabled=4; Manual=3; Automatic=2; Auto=2; Boot=0; System=1 }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if (Test-Path $key) { Set-ItemProperty $key -Name Start -Value $map[$mode] -Type DWord }
}

function Save-State {
    Protect-InstallDir
    # Load existing so a re-Apply NEVER clobbers the true pre-mitigation originals.
    $saved = @{}
    if (Test-Path $StateFile) {
        try { (Get-Content $StateFile -Raw | ConvertFrom-Json).psobject.Properties |
              ForEach-Object { $saved[$_.Name] = $_.Value } } catch { Write-Verbose $_.Exception.Message }
    }
    $svc = @{}
    if ($saved.ContainsKey('services') -and $saved.services) {
        $saved.services.psobject.Properties | ForEach-Object { $svc[$_.Name] = $_.Value }
    }
    foreach ($s in $KillServices) {
        $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue
        if ($w) { Update-SavedOriginal $svc $s $w.StartMode 'Disabled' | Out-Null }
    }
    $cu = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' -Name Start -ErrorAction SilentlyContinue
    if ($cu -and -not $saved.ContainsKey('cdpUserStart') -and "$($cu.Start)" -ne '4') { $saved['cdpUserStart'] = $cu.Start }
    if (-not $saved.ContainsKey('enableCdpPrev')) {
        $ec = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableCdp -ErrorAction SilentlyContinue
        $saved['enableCdpPrev'] = if ($ec) { $ec.EnableCdp } else { 'ABSENT' }
    }
    $saved['services'] = $svc
    $saved['version']  = $Version
    ($saved | ConvertTo-Json -Depth 5) | Set-Content $StateFile -Encoding ASCII
}

function Install-Persistence {
    Protect-InstallDir
    Copy-Item $PSCommandPath $InstalledScript -Force
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$InstalledScript`" -Apply -NoPersist"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
    $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $princ `
        -Settings $set -Description "Re-apply GDID suppression after Windows servicing" -Force | Out-Null
}
function Remove-Persistence {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

# --- modes -----------------------------------------------------------------
function Invoke-Apply {
    Assert-Admin
    Protect-InstallDir                 # lock the install dir BEFORE writing anything into it
    $log = Start-AuditLog 'apply'
    try {
        Save-State
        Write-Host "[A] Producer layer: disabling services" -ForegroundColor Cyan
        foreach ($s in $KillServices) {
            try { Stop-Service $s -Force -ErrorAction SilentlyContinue } catch { Write-Verbose $_.Exception.Message }
            Set-SvcStartMode $s 'Disabled'
            Write-Host "    $s -> Stopped + Disabled"
        }
        Set-SvcStartMode 'CDPUserSvc' 'Disabled'
        Get-Service -Name 'CDPUserSvc_*' -ErrorAction SilentlyContinue | ForEach-Object {
            try { Stop-Service $_.Name -Force -ErrorAction SilentlyContinue } catch { Write-Verbose $_.Exception.Message }
            Write-Host "    $($_.Name) -> Stopped"
        }
        Write-Host "[B] Hostname layer: hosts sinkhole" -ForegroundColor Cyan
        $th = @($DdsHosts) + @($TelemetryHosts); if ($IncludeLoginLive) { $th += $LoginHosts }
        Set-HostsBlock $th
        Write-Host "    sinkholed $($th.Count) FQDNs -> 0.0.0.0 / ::"
        Write-Host "[C] Process layer: firewall outbound block by service" -ForegroundColor Cyan
        New-FwBlock; Write-Host "    rules: $FwPrefix block {CDPSvc,DoSvc,DiagTrack} out"
        Write-Host "[D] Policy layer" -ForegroundColor Cyan
        $sysKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        if (-not (Test-Path $sysKey)) { New-Item $sysKey -Force | Out-Null }
        Set-ItemProperty $sysKey -Name EnableCdp -Value 0 -Type DWord
        Set-ItemProperty $sysKey -Name UploadUserActivities -Value 0 -Type DWord
        Set-ItemProperty $sysKey -Name PublishUserActivities -Value 0 -Type DWord
        Set-ItemProperty $sysKey -Name EnableActivityFeed -Value 0 -Type DWord
        Write-Host "    EnableCdp=0 + Activity History off"
        if (-not $NoPersist) {
            Write-Host "[E] Durability: SYSTEM scheduled task '$TaskName' (re-apply at startup)" -ForegroundColor Cyan
            Install-Persistence
        }
        Write-Host "`nAPPLIED (v$Version). Log: $log" -ForegroundColor Green
    } finally { try { Stop-Transcript | Out-Null } catch { Write-Verbose $_.Exception.Message } }
    exit 0
}

function Invoke-Undo {
    Assert-Admin
    $log = Start-AuditLog 'undo'
    try {
        $st = if (Test-Path $StateFile) { Get-Content $StateFile -Raw | ConvertFrom-Json } else { $null }
        Write-Host "[E] Removing persistence task" -ForegroundColor Cyan; Remove-Persistence
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
        Write-Host "[C] Removing firewall rules" -ForegroundColor Cyan; Remove-FwBlock
        Write-Host "[D] Restoring EnableCdp policy" -ForegroundColor Cyan
        $sysKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        if ($st -and "$($st.enableCdpPrev)" -eq 'ABSENT') { Remove-ItemProperty $sysKey -Name EnableCdp -ErrorAction SilentlyContinue }
        elseif ($st) { Set-ItemProperty $sysKey -Name EnableCdp -Value ([int]$st.enableCdpPrev) -Type DWord }
        Write-Host "`nREVERTED. Reboot to fully restart CDP/DO. Log: $log" -ForegroundColor Green
    } finally { try { Stop-Transcript | Out-Null } catch { Write-Verbose $_.Exception.Message } }
    exit 0
}

function Test-Endpoint([string]$fqdn) {
    $ip = (Resolve-DnsName $fqdn -Type A -ErrorAction SilentlyContinue | Where-Object IPAddress | Select-Object -First 1).IPAddress
    if (-not $ip) { $ip = 'unresolved' }
    $open = Test-NetConnection -ComputerName $fqdn -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
    [pscustomobject]@{ FQDN=$fqdn; IP=$ip; Https443=$open }
}
function Check([bool]$ok,[string]$label) {
    if (-not $ok) { $script:Fail++ }
    Write-Host ("  [{0}] {1}" -f $(if($ok){'PASS'}else{'FAIL'}),$label)
}

function Invoke-Verify {
    Write-Host "=== VERIFY (v$Version) ===" -ForegroundColor Cyan
    foreach ($s in 'CDPSvc','DoSvc') {
        $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue
        Check ($w -and $w.State -eq 'Stopped' -and $w.StartMode -eq 'Disabled') ("{0,-8} State={1} Start={2}" -f $s,$w.State,$w.StartMode)
    }
    $cdpuser = Get-Service -Name 'CDPUserSvc_*' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'
    Check (-not $cdpuser) ("CDPUserSvc running instances: {0}" -f (@($cdpuser).Count))
    Check (Test-HostsBlockPresent) "hosts managed block present"
    $ec = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableCdp -ErrorAction SilentlyContinue).EnableCdp
    Check ($ec -eq 0) ("EnableCdp policy = {0} (want 0)" -f $(if($null -ne $ec){$ec}else{'unset'}))
    $rules = Get-NetFirewallRule -DisplayName "$FwPrefix*" -ErrorAction SilentlyContinue
    Check (@($rules).Count -ge 3) ("firewall rules present: {0}" -f (@($rules).Count))
    if (Test-Path $InstallDir) {
        $wr = (Get-Acl $InstallDir).Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -match '\\Users$|Everyone|Authenticated Users' -and
            ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) }
        Check (-not $wr) "install dir not writable by standard users"
    }
    # The task runs as SYSTEM and is not readable by a standard user, so only check it when elevated.
    $amAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($amAdmin) { Check ([bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) "persistence task registered" }
    else { Write-Host "  [SKIP] persistence task (SYSTEM-owned; re-run elevated to verify)" -ForegroundColor DarkGray }
    Write-Host "  -- endpoint reachability (want closed) --"
    foreach ($f in $DdsHosts) { $r = Test-Endpoint $f; Check (-not $r.Https443) ("{0,-32} IP={1,-16} 443={2}" -f $r.FQDN,$r.IP,$r.Https443) }
    if ($script:Fail -eq 0) { Write-Host "`nALL PASS" -ForegroundColor Green; exit 0 }
    else { Write-Host "`n$($script:Fail) FAILED CHECK(S)" -ForegroundColor Red; exit 1 }
}

function Invoke-Test {
    Assert-Admin
    $proof = 'activity.windows.com','aad.cs.dds.microsoft.com'
    Write-Host "=== REVERSIBLE LIVE TEST (hostname + firewall; services untouched) ===" -ForegroundColor Cyan
    Write-Host "`n-- BEFORE --" -ForegroundColor Yellow
    ($proof | ForEach-Object { Test-Endpoint $_ }) | Format-Table -AutoSize | Out-String | Write-Host
    $blocked = 0; $svcFilter = '(none)'
    try {
        Write-Host "-- APPLYING sinkhole + one firewall rule (CDPSvc) --" -ForegroundColor Yellow
        Set-HostsBlock $proof
        New-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE CDPSvc out" -Direction Outbound -Action Block `
            -Service CDPSvc -Profile Any -Enabled True | Out-Null
        Start-Sleep -Milliseconds 500; Clear-DnsClientCache
        Write-Host "-- AFTER --" -ForegroundColor Yellow
        $after = $proof | ForEach-Object { Test-Endpoint $_ }; $after | Format-Table -AutoSize | Out-String | Write-Host
        $fw = Get-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE*" -ErrorAction SilentlyContinue
        if ($fw) { $svcFilter = ($fw | Get-NetFirewallServiceFilter).Service }
        $blocked = ($after | Where-Object { -not $_.Https443 }).Count
        Write-Host ("`nVERDICT: {0}/{1} endpoints reachable->blocked; firewall rule scoped to '{2}'." -f $blocked,$after.Count,$svcFilter) -ForegroundColor Green
    } finally {
        Write-Host "`n-- ROLLING BACK (always runs) --" -ForegroundColor Yellow
        Remove-HostsBlock
        Get-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        Clear-DnsClientCache
        ($proof | ForEach-Object { Test-Endpoint $_ }) | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "Machine restored to pre-test state." -ForegroundColor Green
    }
    if ($blocked -eq $proof.Count) { exit 0 } else { exit 1 }
}

# --- dispatcher (skipped when dot-sourced for tests) -----------------------
if ($MyInvocation.InvocationName -ne '.') {
    switch ($PSCmdlet.ParameterSetName) {
        'Apply'  { Invoke-Apply }
        'Undo'   { Invoke-Undo }
        'Test'   { Invoke-Test }
        default  { Invoke-Verify }
    }
}
