<#
    Suppress-GDID.ps1  --  Kill the Windows GDID / device-graph telemetry vector.
    Version 1.5.0

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

    Modes:  -Apply | -Undo | -Verify | -Test
        -Apply  : -IncludeLoginLive, -IncludeClassicTelemetry, -NoPersist
        -Undo   : -Force  (restore documented Microsoft defaults when state.json is gone)
        -Verify : -IncludeReachability  (advisory network probe; never gates the exit code)
        -Test   : -Force  (run even though suppression is currently applied)

    Exit codes:
        0 = success / all configuration checks pass / -Test proved the block
        1 = verification failure / -Test did not block a reachable endpoint
        2 = not elevated, or fatal error
        3 = -Test inconclusive (endpoints were already unreachable, so nothing was proved)
        4 = refused, nothing changed (-Undo without trustworthy state and without -Force,
            or -Test while suppression is applied and without -Force)

    Honest ceiling: on-host controls are defeatable by a sufficiently-privileged Microsoft
    component (hardcoded IPs, DoH). The fully-trustworthy block is off-host DNS/router. This
    reduces GDID egress; it does not make you anonymous. The tool says so at runtime.

    Testability: pure helpers are dot-source safe (Tests/*.ps1 load this with `. ` and the
    dispatcher at the bottom does not fire). Every finding fixed here is pinned by an assertion
    in Tests/Audit-Findings.ps1 and registered in Tests/findings.psd1.
#>
[CmdletBinding(DefaultParameterSetName='Verify')]
param(
    [Parameter(ParameterSetName='Apply')]  [switch]$Apply,
    [Parameter(ParameterSetName='Undo')]   [switch]$Undo,
    [Parameter(ParameterSetName='Verify')] [switch]$Verify,
    [Parameter(ParameterSetName='Test')]   [switch]$Test,
    # Modifiers stay parameter-set-agnostic on purpose: binding them to the Apply set would make a
    # bare `-IncludeLoginLive` resolve to the Apply set and silently APPLY. The dispatcher switches
    # on the mode switches themselves, not on ParameterSetName.
    [switch]$IncludeLoginLive,          # also sinkhole login.live.com (breaks MSA sign-in / Store). Opt-in.
    [switch]$IncludeClassicTelemetry,   # M-C: also disable DiagTrack + dmwappushservice. Opt-in.
    [switch]$NoPersist,                 # -Apply: skip the re-apply scheduled task (used by the task itself)
    [switch]$IncludeReachability,       # -Verify: also probe the endpoints (advisory, slow, network-dependent)
    [switch]$Force                      # -Undo: accept documented defaults; -Test: run while applied
)

$ErrorActionPreference = 'Stop'
$Version    = '1.5.0'
$HostsPath  = "$env:SystemRoot\System32\drivers\etc\hosts"
$InstallDir = "$env:ProgramData\SuppressGDID"
$StateFile  = "$InstallDir\state.json"
$LogDir     = "$InstallDir\logs"
$InstalledScript = "$InstallDir\Suppress-GDID.ps1"
$TaskName   = 'GDIDie-Enforce'
$Sentinel0  = '# >>> GDID-SUPPRESS BEGIN (managed - edits inside are overwritten)'
$Sentinel1  = '# <<< GDID-SUPPRESS END'
$FwPrefix   = 'GDID-SUPPRESS'
$LogKeep    = 30            # L-A: transcripts kept per install; older ones are pruned
$script:Fail = 0
$script:Ceiling = @(
    'This reduces GDID egress. It does NOT make you anonymous, and a sufficiently privileged'
    'Microsoft component can bypass hosts/firewall via hardcoded IPs or DNS-over-HTTPS.'
    'The durable block is off-host (Pi-hole / router DNS). For genuinely sensitive work, the'
    'only solid answer is not doing it on Windows at all.'
)

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
$LoginHosts = @('login.live.com')

# Producer layer. M-C: the GDID chain runs through CDPSvc/CDPUserSvc/DoSvc; DiagTrack and
# dmwappushservice are classic-telemetry belt-and-suspenders with real functional side effects,
# so they are opt-in rather than bundled into the default blast radius.
$CoreKillServices    = @('CDPSvc','DoSvc')
$ClassicKillServices = @('DiagTrack','dmwappushservice')
$AllKillServices     = @($CoreKillServices) + @($ClassicKillServices)
$UserKillServices    = @('CDPUserSvc')          # per-user service: registry Start only, plus live instances
$PolicyKey   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$PolicyNames = @('EnableCdp','UploadUserActivities','PublishUserActivities','EnableActivityFeed')
# H-C: used ONLY when state.json is gone AND the operator passed -Force. Documented Microsoft
# defaults, not a silent assumption - see Get-ServiceRestorePlan.
$ServiceDefaults = @{ CDPSvc='Automatic'; DoSvc='Manual'; DiagTrack='Automatic'; dmwappushservice='Manual'; CDPUserSvc='Automatic' }

# --- pure, dot-source-testable helpers -------------------------------------
function Get-PropValue($obj,[string]$name) {
    # Pure: read one member from a hashtable OR a ConvertFrom-Json PSCustomObject. $null if absent.
    if ($null -eq $obj) { return $null }
    if ($obj -is [hashtable]) {
        if ($obj.ContainsKey($name)) { return $obj[$name] }
        return $null
    }
    $p = $obj.psobject.Properties[$name]
    if ($p) { return $p.Value }
    $null
}
# NOTE on array returns: these emit their elements normally (no `,$array` wrapper) so that a caller
# writing @(Get-...) gets a flat list. The `,$array` idiom below in Add/Remove-ManagedBlock is
# deliberate and load-bearing there (it preserves a 0/1-line hosts file), but it nests under @(),
# so those two are always consumed bare. Every call site of the functions here wraps with @().
function Get-KillServiceList([bool]$includeClassic) {
    # Pure (M-C): the services in scope for a given apply. Single source of truth for apply,
    # state capture, firewall rules and verify - so -Verify can never check less than -Apply changed.
    if ($includeClassic) { return (@($CoreKillServices) + @($ClassicKillServices)) }
    @($CoreKillServices)
}
function Get-ExpectedHostList([bool]$includeLogin) {
    # Pure (H-A): the exact FQDN set the managed hosts block should contain for a given scope.
    $h = @($DdsHosts) + @($TelemetryHosts)
    if ($includeLogin) { $h += $LoginHosts }
    $h
}
function Test-ManagedBlockCorrupt([string[]]$lines) {
    # true if the managed sentinels are malformed: begin-without-end, end-without-begin,
    # nested begin, or more than one block. A clean file has 0 or 1 balanced block. Pure.
    $depth = 0; $begins = 0
    foreach ($l in $lines) {
        if ($l -eq $Sentinel0)     { if ($depth -ne 0) { return $true }; $depth++; $begins++ }
        elseif ($l -eq $Sentinel1) { if ($depth -eq 0) { return $true }; $depth-- }
    }
    ($depth -ne 0) -or ($begins -gt 1)
}
function Remove-ManagedBlock([string[]]$lines) {
    # strip the one balanced managed block. Pure. On corruption return input UNCHANGED - never
    # silently delete the tail or rewrite an ambiguous file.
    if (Test-ManagedBlockCorrupt $lines) { return ,$lines }
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
    # replace the managed block with a fresh one. Pure. REFUSE to append onto a corrupt block.
    if (Test-ManagedBlockCorrupt $lines) { throw "SECURITY: hosts managed block is corrupt (unbalanced/duplicate/nested sentinels) - refusing to rewrite." }
    $out = New-Object System.Collections.Generic.List[string]
    (Remove-ManagedBlock $lines) | ForEach-Object { $out.Add($_) }
    if ($names.Count) {
        $out.Add($Sentinel0)
        foreach ($n in $names) { $out.Add("0.0.0.0 $n"); $out.Add(":: $n") }
        $out.Add($Sentinel1)
    }
    ,$out.ToArray()
}
function Get-ManagedBlockFqdn([string[]]$lines) {
    # Pure (H-A): the FQDNs actually inside the managed block. Lets -Verify compare block CONTENTS
    # against Get-ExpectedHostList instead of merely asserting the sentinel exists.
    if (Test-ManagedBlockCorrupt $lines) { return @() }
    $names = New-Object System.Collections.Generic.List[string]
    $inside = $false
    foreach ($l in $lines) {
        if ($l -eq $Sentinel0) { $inside = $true; continue }
        if ($l -eq $Sentinel1) { $inside = $false; continue }
        if ($inside -and $l -match '^\s*0\.0\.0\.0\s+(\S+)\s*$') { $names.Add($Matches[1]) }
    }
    $names.ToArray()
}
function Update-SavedOriginal([hashtable]$saved,[string]$key,$current,$disabledValue) {
    # Record the ORIGINAL exactly once (first-write-wins), and never record an
    # already-disabled state as the original (would make -Undo restore Disabled).
    if (-not $saved.ContainsKey($key) -and "$current" -ne "$disabledValue") { $saved[$key] = $current }
    $saved
}
function Get-SvcStartValue([string]$mode) {
    # Pure (A-1): validated mode -> registry Start value. THROWS on anything unrecognised so a
    # corrupt/hostile state.json can never coax a service into Start=0 (boot-start) or a null write.
    $map = @{ Disabled=4; Manual=3; Automatic=2; Auto=2; AutomaticDelayedStart=2; 'Auto (Delayed)'=2; Boot=0; System=1 }
    $k = "$mode"
    if (-not $map.ContainsKey($k)) { throw "Unrecognised service start mode '$mode' - refusing to write a Start value." }
    $map[$k]
}
function Select-PruneTarget([string[]]$namesNewestFirst,[int]$keep) {
    # Pure (L-A): given transcript names sorted newest-first, which to delete.
    if ($keep -lt 0) { $keep = 0 }
    $n = @($namesNewestFirst)
    if ($n.Count -le $keep) { return @() }
    $n[$keep..($n.Count-1)]
}
function Get-ServiceRestorePlan($state,[string[]]$services,[bool]$allowDefaults) {
    # Pure (H-C/A-1). Turn saved state into an explicit per-service action. The contract:
    #   set-raw  - a raw registry original was recorded; restore it byte-for-byte (exact undo)
    #   set-mode - only a friendly StartMode was recorded (legacy state.json); restore that
    #   skip     - state exists but recorded no original for this service, which means it was
    #              ALREADY disabled before -Apply (Update-SavedOriginal refuses to record that)
    #              or we never touched it. Leaving it alone is the correct restore.
    #   default  - no state at all AND the operator passed -Force: documented Microsoft default
    #   refuse   - no state and no -Force: we do NOT guess. Caller must abort.
    $plan = @{}
    $raw = Get-PropValue $state 'servicesRaw'
    $friendly = Get-PropValue $state 'services'
    foreach ($s in $services) {
        $r = Get-PropValue $raw $s
        $f = Get-PropValue $friendly $s
        if ($null -ne $r) {
            $plan[$s] = @{ Action='set-raw'; Start=[int](Get-PropValue $r 'Start'); DelayedAutostart=(Get-PropValue $r 'DelayedAutostart') }
        }
        elseif ($null -ne $f -and "$f" -ne '') {
            $plan[$s] = @{ Action='set-mode'; Mode="$f" }
        }
        elseif ($s -eq 'CDPUserSvc' -and $null -ne (Get-PropValue $state 'cdpUserStart')) {
            # legacy v1.4.0 state.json kept CDPUserSvc's raw Start at the top level
            $plan[$s] = @{ Action='set-raw'; Start=[int](Get-PropValue $state 'cdpUserStart'); DelayedAutostart='ABSENT' }
        }
        elseif ($state) {
            $plan[$s] = @{ Action='skip'; Reason='no original recorded (already disabled before -Apply, or never modified)' }
        }
        elseif ($allowDefaults -and $ServiceDefaults.ContainsKey($s)) {
            $plan[$s] = @{ Action='default'; Mode=$ServiceDefaults[$s] }
        }
        else {
            $plan[$s] = @{ Action='refuse'; Reason='no trustworthy state file and -Force was not supplied' }
        }
    }
    $plan
}
function Get-PolicyRestorePlan($policyPrev) {
    # F7 pure: saved policyPrev (hashtable/PSObject) -> @{ Name = @{Action='remove'|'set'; Value=int} }
    $plan = @{}
    if (-not $policyPrev) { return $plan }
    $names = if ($policyPrev -is [hashtable]) { $policyPrev.Keys } else { $policyPrev.psobject.Properties.Name }
    foreach ($n in $names) {
        $v = Get-PropValue $policyPrev $n
        if ("$v" -eq 'ABSENT') { $plan[$n] = @{ Action = 'remove' } }
        else                   { $plan[$n] = @{ Action = 'set'; Value = [int]$v } }
    }
    $plan
}
function Get-PolicyRestorePlanOrDefault($policyPrev,[bool]$allowDefaults) {
    # Pure (A-8): the old code produced an EMPTY plan with no saved policy, so -Undo printed
    # REVERTED while leaving all four policy values at 0 - the policy layer stayed applied.
    # Absent is the default-Windows state for these policy values, so -Force removes them.
    if ($policyPrev) { return Get-PolicyRestorePlan $policyPrev }
    $plan = @{}
    if (-not $allowDefaults) { return $plan }
    foreach ($n in $PolicyNames) { $plan[$n] = @{ Action = 'remove' } }
    $plan
}
function Get-TestVerdict($before,$after) {
    # Pure (A-4). -Test only proves something for an endpoint that was REACHABLE before and
    # BLOCKED after. If nothing was reachable to begin with (already applied, offline, corporate
    # proxy) the run proves nothing and must not exit 0.
    $b = @($before); $a = @($after)
    $reachable = @($b | Where-Object { $_.Https443 })
    $names = @($reachable | ForEach-Object { $_.FQDN })
    $stillOpen = @($a | Where-Object { $_.Https443 -and ($names -contains $_.FQDN) } | ForEach-Object { $_.FQDN })
    $proved = $names.Count - $stillOpen.Count
    if ($names.Count -eq 0) {
        return @{ Verdict='INCONCLUSIVE'; Exit=3; Proved=0; ReachableBefore=0; StillOpen=@()
                  Detail='no probe endpoint was reachable before the test, so the sinkhole proved nothing' }
    }
    if ($stillOpen.Count -gt 0) {
        return @{ Verdict='FAILED'; Exit=1; Proved=$proved; ReachableBefore=$names.Count; StillOpen=$stillOpen
                  Detail=("still reachable after the sinkhole: {0}" -f ($stillOpen -join ', ')) }
    }
    @{ Verdict='PROVED'; Exit=0; Proved=$proved; ReachableBefore=$names.Count; StillOpen=@()
       Detail='every endpoint that was reachable became unreachable' }
}
function Get-PersistenceArgument([bool]$includeLogin,[bool]$includeClassic) {
    # Args the boot task re-applies with. MUST carry every scope switch the user chose, otherwise
    # the enforcer silently narrows the mitigation on the next reboot. Pure/testable.
    $a = "-NoProfile -ExecutionPolicy Bypass -File `"$InstalledScript`" -Apply -NoPersist"
    if ($includeLogin)   { $a += ' -IncludeLoginLive' }
    if ($includeClassic) { $a += ' -IncludeClassicTelemetry' }
    $a
}

# --- environment helpers ---------------------------------------------------
function Test-IsWindowsHost {
    # $IsWindows does not exist in PowerShell 5.1 (always Windows there); it is $false on
    # pwsh/Linux where the ACL and Net* surfaces are unavailable.
    if ($null -eq $IsWindows) { return $true }
    [bool]$IsWindows
}
function Assert-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Administrator required. Re-run elevated:" -ForegroundColor Red
        Write-Host "  Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Apply'"
        exit 2
    }
}
function Test-IsElevated {
    (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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
    # VR-1: SET THE OWNER. A DACL alone does not close the writable-dir-to-SYSTEM hole, because the
    # object OWNER keeps implicit READ_CONTROL + WRITE_DAC no matter what the DACL says (no OWNER
    # RIGHTS / S-1-3-4 ACE strips it). A standard user can pre-create %ProgramData%\SuppressGDID
    # (default ProgramData grants Users 'create folders'), becoming CREATOR OWNER; Set-Acl would
    # then rewrite the DACL but leave them owner, so they could re-open the DACL later and hijack
    # the file the GDIDie-Enforce SYSTEM task runs. Re-vesting ownership in Administrators (the
    # elevated process holds SeTakeOwnership) makes Set-Acl re-take the directory at apply time.
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $acl
}
function Test-PathIsReparse([string]$path) {
    $i = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    [bool]($i -and ($i.Attributes -band [IO.FileAttributes]::ReparsePoint))
}
$script:UntrustedSids = @('S-1-5-32-545','S-1-1-0','S-1-5-11')  # Users, Everyone, Authenticated Users
function Test-IdentityUntrusted($identityRef) {
    # SID-based, not name-based: robust on non-English Windows where account names are localized.
    $sid = try { $identityRef.Translate([System.Security.Principal.SecurityIdentifier]).Value }
           catch { if ($identityRef.Value -match '^S-\d') { $identityRef.Value } else { $null } }
    $sid -in $script:UntrustedSids
}
function Test-PathUserWritable([string]$path) {
    # true if any Allow ACE grants an untrusted SID a write-class right.
    # Mask is write-only bits (no read bits) so Users:ReadAndExecute never false-positives.
    $wmask = [System.Security.AccessControl.FileSystemRights]'Write,Delete,ChangePermissions,TakeOwnership'
    [bool]((Get-Acl -LiteralPath $path).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        ($_.FileSystemRights -band $wmask) -and
        (Test-IdentityUntrusted $_.IdentityReference) })
}
# VR-1: only SYSTEM and Administrators are trustworthy owners. An elevated admin process creates
# objects owned by the Administrators group by default, and the SYSTEM task creates them owned by
# SYSTEM, so both legitimate writers land in this set; anything else means a standard user owns the
# object and therefore holds implicit WRITE_DAC over it.
$script:TrustedOwnerSids = @('S-1-5-18','S-1-5-32-544')  # SYSTEM, Administrators
function Test-PathOwnerUntrusted([string]$path) {
    # true if the object owner is NOT SYSTEM/Administrators. Owner implies WRITE_DAC, so an untrusted
    # owner is effectively write access that Test-PathUserWritable (DACL-only) cannot see.
    $sid = try { (Get-Acl -LiteralPath $path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
           catch { $null }
    (-not $sid) -or ($sid -notin $script:TrustedOwnerSids)
}
function Protect-InstallDir {
    # Fail-closed: reject reparse points, create+lock the dir, abort if it stays user-writable.
    if (Test-Path -LiteralPath $InstallDir) {
        if (Test-PathIsReparse $InstallDir) { throw "SECURITY: $InstallDir is a reparse point/junction - aborting." }
    } else {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    Set-Acl -LiteralPath $InstallDir -AclObject (New-HardenedAcl)   # no swallow: an ACL failure MUST abort; also RE-TAKES ownership (VR-1)
    if (Test-PathUserWritable $InstallDir)   { throw "SECURITY: $InstallDir still user-writable after hardening - aborting." }
    if (Test-PathOwnerUntrusted $InstallDir) { throw "SECURITY: $InstallDir is owned by a standard user after hardening (implicit WRITE_DAC) - aborting." }
}
function Protect-InstalledScript {
    # Close H-1: a pre-planted script file keeps its explicit writable ACE across Copy-Item -Force.
    # Reject reparse, DELETE any pre-existing file (the new copy then inherits the locked parent DACL),
    # copy, and verify the file is not user-writable BEFORE any SYSTEM task is registered.
    if (Test-Path -LiteralPath $InstalledScript) {
        if (Test-PathIsReparse $InstalledScript) { throw "SECURITY: installed script path is a reparse point - aborting." }
        Remove-Item -LiteralPath $InstalledScript -Force
    }
    Copy-Item -LiteralPath $PSCommandPath -Destination $InstalledScript -Force
    if (Test-PathUserWritable $InstalledScript)   { throw "SECURITY: installed script is user-writable - refusing to register SYSTEM task." }
    if (Test-PathOwnerUntrusted $InstalledScript) { throw "SECURITY: installed script is owned by a standard user (implicit WRITE_DAC) - refusing to register SYSTEM task." }
}
function Remove-OldAuditLog {
    # L-A: keep the newest $LogKeep transcripts. A boot task that re-applies on every servicing
    # event would otherwise accumulate forever.
    $existing = @(Get-ChildItem -LiteralPath $LogDir -Filter 'gdid-*.log' -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTimeUtc -Descending)
    $victims = @(Select-PruneTarget @($existing | ForEach-Object { $_.Name }) $LogKeep)
    foreach ($v in $victims) {
        Remove-Item -LiteralPath (Join-Path $LogDir $v) -Force -ErrorAction SilentlyContinue
    }
    @($victims).Count
}
function Start-AuditLog([string]$mode) {
    if ((Test-Path -LiteralPath $LogDir) -and (Test-PathIsReparse $LogDir)) { throw "SECURITY: $LogDir is a reparse point/junction - aborting." }
    Initialize-Dir $LogDir
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $log = "$LogDir\gdid-$mode-$stamp.log"
    try { Start-Transcript -Path $log -Force | Out-Null } catch { Write-Verbose $_.Exception.Message }
    try { Remove-OldAuditLog | Out-Null } catch { Write-Verbose $_.Exception.Message }
    return $log
}
function Write-Ceiling {
    # H-B: the honest ceiling lives at the bottom of the README, where a user who skims does not
    # read it. Print it where the decision actually gets made.
    Write-Host ""
    Write-Host "  ------------------------------------------------------------------------" -ForegroundColor Yellow
    foreach ($l in $script:Ceiling) { Write-Host ("  {0}" -f $l) -ForegroundColor Yellow }
    Write-Host "  ------------------------------------------------------------------------" -ForegroundColor Yellow
}

function Clear-DnsCache {
    # Thin wrapper over Clear-DnsClientCache so the hosts-file lifecycle is exercisable off Windows,
    # where that cmdlet does not exist. The tests used to shadow the cmdlet itself, which trips
    # PSScriptAnalyzer's PSAvoidOverwritingBuiltInCmdlets - a wrapper is the right seam.
    if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) { Clear-DnsClientCache }
    else { Write-Verbose 'Clear-DnsClientCache unavailable on this platform - skipping DNS cache flush.' }
}
function Set-HostsBlock([string[]]$names) {
    $lines = if (Test-Path $HostsPath) { Get-Content $HostsPath } else { @() }
    $new = Add-ManagedBlock $lines $names
    [System.IO.File]::WriteAllLines($HostsPath, $new, (New-Object System.Text.UTF8Encoding($false)))
    Clear-DnsCache
}
function Remove-HostsBlock {
    $lines = if (Test-Path $HostsPath) { Get-Content $HostsPath } else { @() }
    if (Test-ManagedBlockCorrupt $lines) { Write-Warning "hosts managed block is corrupt - leaving the hosts file untouched (fix it manually)."; return }
    $new = Remove-ManagedBlock $lines
    [System.IO.File]::WriteAllLines($HostsPath, $new, (New-Object System.Text.UTF8Encoding($false)))
    Clear-DnsCache
}
function Test-HostsBlockPresent {
    if (-not (Test-Path $HostsPath)) { return $false }
    [bool]((Get-Content $HostsPath) -contains $Sentinel0)
}
function Get-HostsBlockFqdn {
    if (-not (Test-Path $HostsPath)) { return @() }
    Get-ManagedBlockFqdn (Get-Content $HostsPath)
}

function New-FwBlock([string[]]$services) {
    foreach ($svc in $services) {
        $name = "$FwPrefix block $svc out"
        $existing = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
        if ($existing.Count -eq 0) {
            New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block `
                -Service $svc -Profile Any -Enabled True | Out-Null
        } else {
            # A-2: the old code skipped any rule that already existed. A rule that exists but was
            # disabled (GPO, tampering, a half-finished edit) reads as applied and blocks nothing,
            # so re-assert the whole shape on every apply. This is what makes the boot task heal.
            if ($existing.Count -gt 1) {
                $existing | Select-Object -Skip 1 | Remove-NetFirewallRule
                $existing = @($existing[0])
            }
            $existing | Set-NetFirewallRule -Enabled True -Action Block -Direction Outbound `
                -Profile Any -Service $svc | Out-Null
        }
    }
}
function Remove-FwBlock { Get-NetFirewallRule -DisplayName "$FwPrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule }

function Set-SvcStartMode([string]$name,[string]$mode) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if (Test-Path $key) { Set-ItemProperty $key -Name Start -Value (Get-SvcStartValue $mode) -Type DWord }
}
function Set-SvcStartRaw([string]$name,[int]$start,$delayedAutostart) {
    # H-C: restore the exact registry originals, including the delayed-autostart flag that a
    # friendly 'Auto' StartMode cannot express.
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if (-not (Test-Path $key)) { return }
    if ($start -lt 0 -or $start -gt 4) { throw "Refusing to write out-of-range Start=$start for $name." }
    Set-ItemProperty $key -Name Start -Value $start -Type DWord
    if ($null -ne $delayedAutostart) {
        if ("$delayedAutostart" -eq 'ABSENT') { Remove-ItemProperty $key -Name DelayedAutostart -ErrorAction SilentlyContinue }
        else { Set-ItemProperty $key -Name DelayedAutostart -Value ([int]$delayedAutostart) -Type DWord }
    }
}
function Get-SvcRawState([string]$name) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if (-not (Test-Path $key)) { return $null }
    $p = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($null -eq $p -or $null -eq $p.Start) { return $null }
    $d = 'ABSENT'
    if ($null -ne $p.DelayedAutostart) { $d = [int]$p.DelayedAutostart }
    @{ Start = [int]$p.Start; DelayedAutostart = $d }
}
function Stop-ServiceReporting([string]$name) {
    # L-B: -ErrorAction SilentlyContinue used to hide a service that refused to stop. The start
    # type is already Disabled (effective next boot), but a still-RUNNING service keeps egressing
    # now, and the user deserves to know that rather than read a clean "Stopped + Disabled".
    try { Stop-Service $name -Force -ErrorAction Stop }
    catch { Write-Verbose $_.Exception.Message }
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return 'absent' }
    "$($svc.Status)"
}

function Read-StateFileSafely {
    # F2: never trust a reparse-point or user-writable state file (attacker could steer -Undo).
    if (-not (Test-Path -LiteralPath $StateFile)) { return $null }
    if (Test-PathIsReparse $StateFile)      { throw "SECURITY: $StateFile is a reparse point - aborting." }
    if (Test-PathUserWritable $StateFile)   { throw "SECURITY: $StateFile is writable by standard users - refusing to trust it." }
    if (Test-PathOwnerUntrusted $StateFile) { throw "SECURITY: $StateFile is owned by a standard user (implicit WRITE_DAC) - refusing to trust it." }
    try { Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } catch { $null }
}
function Write-StateFileSafely($obj) {
    if ((Test-Path -LiteralPath $StateFile) -and (Test-PathIsReparse $StateFile)) { throw "SECURITY: $StateFile is a reparse point - aborting." }
    ($obj | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $StateFile -Encoding ASCII
    if (Test-PathUserWritable $StateFile)   { throw "SECURITY: $StateFile is user-writable after write - aborting." }
    if (Test-PathOwnerUntrusted $StateFile) { throw "SECURITY: $StateFile is owned by a standard user after write (implicit WRITE_DAC) - aborting." }
}
function Get-StateForUndo {
    # A-7: classify the state file instead of throwing a raw SECURITY exception out of -Undo.
    # An untrusted file is NEVER parsed - it is treated as absent, so a standard user who can
    # write state.json cannot steer the restore, only force the operator to use -Force.
    if (-not (Test-Path -LiteralPath $StateFile)) {
        return @{ State=$null; Status='missing'; Detail="$StateFile does not exist" }
    }
    try {
        if (Test-PathIsReparse $StateFile)      { return @{ State=$null; Status='untrusted'; Detail="$StateFile is a reparse point" } }
        if (Test-PathUserWritable $StateFile)   { return @{ State=$null; Status='untrusted'; Detail="$StateFile is writable by standard users" } }
        if (Test-PathOwnerUntrusted $StateFile) { return @{ State=$null; Status='untrusted'; Detail="$StateFile is owned by a standard user (implicit WRITE_DAC)" } }
    } catch {
        return @{ State=$null; Status='unreadable'; Detail=$_.Exception.Message }
    }
    $obj = try { Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } catch { $null }
    if ($null -eq $obj) { return @{ State=$null; Status='unreadable'; Detail="$StateFile is not parseable JSON" } }
    @{ State=$obj; Status='ok'; Detail='' }
}
function Get-AppliedScope {
    # H-A/M-C/L-D: -Verify checks against RECORDED INTENT, not hardcoded assumptions, so it can
    # never check less than -Apply changed. $null when there is no trustworthy state to read.
    $si = try { Get-StateForUndo } catch { $null }
    if ($null -eq $si -or $si.Status -ne 'ok') { return $null }
    $sc = Get-PropValue $si.State 'scope'
    if ($null -eq $sc) { return $null }
    @{ IncludeLoginLive        = [bool](Get-PropValue $sc 'includeLoginLive')
       IncludeClassicTelemetry = [bool](Get-PropValue $sc 'includeClassicTelemetry')
       Version                 = "$(Get-PropValue $sc 'version')"
       AppliedUtc              = "$(Get-PropValue $sc 'appliedUtc')" }
}
function Save-State([string[]]$services) {
    Protect-InstallDir
    # Load existing so a re-Apply NEVER clobbers the true pre-mitigation originals.
    $saved = @{}
    $existing = Read-StateFileSafely
    if ($existing) { $existing.psobject.Properties | ForEach-Object { $saved[$_.Name] = $_.Value } }
    $svc = @{}
    if ($saved.ContainsKey('services') -and $saved.services) {
        $saved.services.psobject.Properties | ForEach-Object { $svc[$_.Name] = $_.Value }
    }
    $raw = @{}
    if ($saved.ContainsKey('servicesRaw') -and $saved.servicesRaw) {
        $saved.servicesRaw.psobject.Properties | ForEach-Object { $raw[$_.Name] = $_.Value }
    }
    foreach ($s in (@($services) + @($UserKillServices))) {
        $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue
        if ($w) { Update-SavedOriginal $svc $s $w.StartMode 'Disabled' | Out-Null }
        # H-C: also snapshot the raw registry values so -Undo can be exact (delayed-autostart and
        # per-build oddities that a friendly StartMode string cannot express). Same first-write-wins
        # guard, and Start=4 (Disabled) is never recorded as an original.
        $r = Get-SvcRawState $s
        if ($r -and -not $raw.ContainsKey($s) -and $r.Start -ne 4) { $raw[$s] = $r }
    }
    if (-not $saved.ContainsKey('policyPrev')) {
        # M-3: capture ALL the policy values -Apply changes, first-write-wins, ABSENT if unset.
        $pp = @{}
        foreach ($n in $PolicyNames) {
            $v = Get-ItemProperty $PolicyKey -Name $n -ErrorAction SilentlyContinue
            $pp[$n] = if ($null -ne $v.$n) { $v.$n } else { 'ABSENT' }
        }
        # migrate an older state.json that only saved enableCdpPrev (trust it over the applied value)
        if ($saved.ContainsKey('enableCdpPrev')) { $pp['EnableCdp'] = $saved.enableCdpPrev }
        $saved['policyPrev'] = $pp
    }
    $saved['services']    = $svc
    $saved['servicesRaw'] = $raw
    $saved['version']     = $Version
    # scope is CURRENT INTENT, not an original: it is overwritten on every apply so -Verify and the
    # boot task always reflect the switches of the most recent -Apply.
    $saved['scope'] = @{
        includeLoginLive        = [bool]$IncludeLoginLive
        includeClassicTelemetry = [bool]$IncludeClassicTelemetry
        version                 = $Version
        appliedUtc              = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    Write-StateFileSafely $saved
}

function Assert-InstallSafe {
    # F6: the SYSTEM task must NEVER be registered if any object it depends on is a reparse point
    # or writable by standard users. Checked immediately before Register-ScheduledTask.
    foreach ($p in @($InstallDir, $InstalledScript, $StateFile, $LogDir)) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        if (Test-PathIsReparse $p)      { throw "SECURITY: $p is a reparse point - refusing to register SYSTEM task." }
        if (Test-PathUserWritable $p)   { throw "SECURITY: $p is user-writable - refusing to register SYSTEM task." }
        if (Test-PathOwnerUntrusted $p) { throw "SECURITY: $p is owned by a standard user (implicit WRITE_DAC) - refusing to register SYSTEM task." }
    }
}
function Install-Persistence {
    Protect-InstallDir
    Protect-InstalledScript          # H-1/H-2: reparse-safe, fail-closed; aborts if file stays user-writable
    Assert-InstallSafe               # F6: gate on dir + script + state.json + logs before registering
    $want    = Get-PersistenceArgument $IncludeLoginLive $IncludeClassicTelemetry
    # VR-2: absolute path, not the bare name. A SYSTEM task with -Execute 'powershell.exe' leans on
    # PATH resolution at trigger time; the qualified System32 path removes that search entirely.
    $ps      = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action  = New-ScheduledTaskAction -Execute $ps -Argument $want
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
    $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $princ `
        -Settings $set -Description "Re-apply GDID suppression after Windows servicing" -Force | Out-Null
    # M-B: the check -> register sequence is not atomic. Re-assert afterwards and confirm the task
    # that now exists is the one we meant to create; on any doubt, unregister rather than leave a
    # SYSTEM task standing. Cheap, and it closes the TOCTOU window instead of only documenting it.
    try {
        Assert-InstallSafe
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $got = "$(($t.Actions | Select-Object -First 1).Arguments)"
        if ($got.Trim() -ne $want.Trim()) { throw "SECURITY: registered task arguments do not match intent ('$got') - unregistering." }
    } catch {
        Remove-Persistence
        throw
    }
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
        $services = @(Get-KillServiceList $IncludeClassicTelemetry)
        Save-State $services
        Write-Host "[A] Producer layer: disabling services" -ForegroundColor Cyan
        $stubborn = @()
        foreach ($s in $services) {
            Set-SvcStartMode $s 'Disabled'
            $state = Stop-ServiceReporting $s
            if ($state -eq 'Running') { $stubborn += $s }
            Write-Host ("    {0,-16} -> Disabled (now: {1})" -f $s,$state)
        }
        Set-SvcStartMode 'CDPUserSvc' 'Disabled'
        Get-Service -Name 'CDPUserSvc_*' -ErrorAction SilentlyContinue | ForEach-Object {
            $state = Stop-ServiceReporting $_.Name
            if ($state -eq 'Running') { $stubborn += $_.Name }
            Write-Host ("    {0,-16} -> now: {1}" -f $_.Name,$state)
        }
        if (-not $IncludeClassicTelemetry) {
            Write-Host "    (classic telemetry left alone: $($ClassicKillServices -join ', ') - add -IncludeClassicTelemetry to disable)" -ForegroundColor DarkGray
        }
        if ($stubborn.Count) {
            Write-Warning ("still RUNNING despite Disabled (they keep egressing until reboot): {0}" -f ($stubborn -join ', '))
        }
        Write-Host "[B] Hostname layer: hosts sinkhole" -ForegroundColor Cyan
        $th = @(Get-ExpectedHostList $IncludeLoginLive)
        Set-HostsBlock $th
        Write-Host "    sinkholed $($th.Count) FQDNs -> 0.0.0.0 / ::"
        if ($IncludeLoginLive) { Write-Host "    login.live.com IS sinkholed (-IncludeLoginLive): MSA sign-in and the Store will fail" -ForegroundColor Yellow }
        Write-Host "[C] Process layer: firewall outbound block by service" -ForegroundColor Cyan
        New-FwBlock $services
        Write-Host "    rules: $FwPrefix block {$($services -join ',')} out"
        Write-Host "[D] Policy layer" -ForegroundColor Cyan
        if (-not (Test-Path $PolicyKey)) { New-Item $PolicyKey -Force | Out-Null }
        foreach ($n in $PolicyNames) { Set-ItemProperty $PolicyKey -Name $n -Value 0 -Type DWord }
        Write-Host "    $($PolicyNames -join '=0, ')=0"
        if (-not $NoPersist) {
            Write-Host "[E] Durability: SYSTEM scheduled task '$TaskName' (re-apply at startup)" -ForegroundColor Cyan
            Install-Persistence
        }
        Write-Host "`nAPPLIED (v$Version). Log: $log" -ForegroundColor Green
        Write-Ceiling      # H-B
        Write-Host "  Verify with: -Verify   Roll back with: -Undo" -ForegroundColor DarkGray
    } finally { try { Stop-Transcript | Out-Null } catch { Write-Verbose $_.Exception.Message } }
    exit 0
}

function Invoke-Undo {
    Assert-Admin
    $log = Start-AuditLog 'undo'
    try {
        $si = Get-StateForUndo
        # H-C/A-7/A-8: with no trustworthy state we do NOT guess. Refuse the whole undo before
        # touching anything, so the machine is never left half-reverted, and name the escape hatch.
        if ($si.Status -ne 'ok') {
            Write-Warning "state file $($si.Status): $($si.Detail)"
            if (-not $Force) {
                Write-Host ""
                Write-Host "REFUSING to undo: without state.json the original service start-types and policy" -ForegroundColor Red
                Write-Host "values are unknown, and guessing them would misconfigure this machine." -ForegroundColor Red
                Write-Host ""
                Write-Host "  Nothing was changed. Your options:" -ForegroundColor Yellow
                Write-Host "    1. Restore $StateFile from a backup and re-run -Undo (exact restore)."
                Write-Host "    2. Re-run with -Force to apply documented Microsoft defaults instead:"
                foreach ($k in ($ServiceDefaults.Keys | Sort-Object)) { Write-Host ("         {0,-18} -> {1}" -f $k,$ServiceDefaults[$k]) }
                Write-Host ("         {0} -> removed (default-Windows absent)" -f ($PolicyNames -join ', '))
                Write-Host "       These are defaults, NOT your original configuration."
                Write-Host "    3. Undo by hand: services.msc, remove the hosts block between the GDID-SUPPRESS"
                Write-Host "       sentinels, delete the '$FwPrefix*' firewall rules, clear $PolicyKey."
                Write-Host "`nREFUSED (nothing changed). Log: $log" -ForegroundColor Red
                exit 4
            }
            Write-Warning "-Force: restoring DOCUMENTED DEFAULTS, not your original configuration."
        }
        $st = $si.State
        Write-Host "[E] Removing persistence task" -ForegroundColor Cyan; Remove-Persistence
        Write-Host "[A] Restoring services" -ForegroundColor Cyan
        $plan = Get-ServiceRestorePlan $st (@($AllKillServices) + @($UserKillServices)) ([bool]$Force)
        foreach ($s in (@($AllKillServices) + @($UserKillServices))) {
            $p = $plan[$s]
            switch ($p.Action) {
                'set-raw'  { Set-SvcStartRaw $s $p.Start $p.DelayedAutostart; Write-Host ("    {0,-18} -> Start={1}{2}" -f $s,$p.Start,$(if ("$($p.DelayedAutostart)" -ne 'ABSENT') { " DelayedAutostart=$($p.DelayedAutostart)" } else { '' })) }
                'set-mode' { Set-SvcStartMode $s $p.Mode; Write-Host ("    {0,-18} -> {1} (from legacy state)" -f $s,$p.Mode) }
                'default'  { Set-SvcStartMode $s $p.Mode; Write-Host ("    {0,-18} -> {1} (DEFAULT, not your original)" -f $s,$p.Mode) -ForegroundColor Yellow }
                'skip'     { Write-Host ("    {0,-18} -> left as-is ({1})" -f $s,$p.Reason) -ForegroundColor DarkGray }
                default    { Write-Warning "no restore action for $s ($($p.Reason)) - left as-is." }
            }
        }
        Write-Host "[B] Removing hosts block" -ForegroundColor Cyan;   Remove-HostsBlock
        Write-Host "[C] Removing firewall rules" -ForegroundColor Cyan; Remove-FwBlock
        Write-Host "[D] Restoring policy values" -ForegroundColor Cyan
        $polPrev = if ($st -and (Get-PropValue $st 'policyPrev')) { Get-PropValue $st 'policyPrev' }
                   elseif ($st -and $null -ne (Get-PropValue $st 'enableCdpPrev')) { @{ EnableCdp = (Get-PropValue $st 'enableCdpPrev') } }   # legacy state.json
                   else { $null }
        $pplan = Get-PolicyRestorePlanOrDefault $polPrev ([bool]$Force)
        if ($pplan.Count -eq 0) { Write-Warning "no saved policy values and no -Force: policy layer left applied." }
        foreach ($n in $pplan.Keys) {
            if ($pplan[$n].Action -eq 'remove') { Remove-ItemProperty $PolicyKey -Name $n -ErrorAction SilentlyContinue; Write-Host "    $n -> removed" }
            else { Set-ItemProperty $PolicyKey -Name $n -Value $pplan[$n].Value -Type DWord; Write-Host "    $n -> $($pplan[$n].Value)" }
        }
        Write-Host "`nREVERTED. Reboot to fully restart CDP/DO. Log: $log" -ForegroundColor Green
        Write-Host "  ($StateFile and the logs are kept on purpose - delete $InstallDir yourself if you want them gone.)" -ForegroundColor DarkGray
    } finally { try { Stop-Transcript | Out-Null } catch { Write-Verbose $_.Exception.Message } }
    exit 0
}

function Test-Endpoint([string]$fqdn) {
    $ip = (Resolve-DnsName $fqdn -Type A -ErrorAction SilentlyContinue | Where-Object IPAddress | Select-Object -First 1).IPAddress
    if (-not $ip) { $ip = 'unresolved' }
    $open = Test-NetConnection -ComputerName $fqdn -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
    [pscustomobject]@{ FQDN=$fqdn; IP=$ip; Https443=[bool]$open }
}
function Check([bool]$ok,[string]$label) {
    # Gating check: contributes to the exit code. Configuration only - deterministic and offline.
    if (-not $ok) { $script:Fail++ }
    Write-Host ("  [{0}] {1}" -f $(if($ok){'PASS'}else{'FAIL'}),$label)
}
function Note([string]$label,[string]$colour='DarkGray') {
    # M-D: advisory output. NEVER touches $script:Fail, so CI/Intune exit-code gating cannot flap
    # on something that is not a configuration fact.
    Write-Host ("  [INFO] {0}" -f $label) -ForegroundColor $colour
}

function Invoke-Verify {
    Write-Host "=== VERIFY (v$Version) ===" -ForegroundColor Cyan
    $scope = Get-AppliedScope
    if ($scope) {
        Note ("recorded scope: applied {0} by v{1}; IncludeLoginLive={2} IncludeClassicTelemetry={3}" -f $scope.AppliedUtc,$scope.Version,$scope.IncludeLoginLive,$scope.IncludeClassicTelemetry)
        $wantLogin   = $scope.IncludeLoginLive
        $wantClassic = $scope.IncludeClassicTelemetry
    } else {
        Note "no trustworthy state.json scope found - checking the DEFAULT scope only; classic telemetry is reported as advisory." 'Yellow'
        $wantLogin = $false; $wantClassic = $false
    }
    $services = @(Get-KillServiceList $wantClassic)

    Write-Host "  -- configuration (deterministic; gates the exit code) --"
    # H-A: iterate the SAME service list -Apply used, not a hardcoded pair.
    foreach ($s in (@($services) + @($UserKillServices))) {
        $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue
        if ($null -eq $w) { Note ("{0,-18} not present on this build" -f $s); continue }
        # CDPUserSvc is a per-user service template: its own State is meaningless, the per-session
        # instances below are what matter, so only its start type gates.
        $stateOk = ($s -in $UserKillServices) -or ($w.State -eq 'Stopped')
        Check ($stateOk -and $w.StartMode -eq 'Disabled') ("{0,-18} State={1} Start={2}" -f $s,$w.State,$w.StartMode)
    }
    $cdpuser = Get-Service -Name 'CDPUserSvc_*' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'
    Check (-not $cdpuser) ("CDPUserSvc running instances: {0}" -f (@($cdpuser).Count))

    # H-A: compare the block CONTENTS with what this scope should sinkhole, not just the sentinel.
    Check (Test-HostsBlockPresent) "hosts managed block present"
    $expected = @(Get-ExpectedHostList $wantLogin)
    $actual   = @(Get-HostsBlockFqdn)
    $missing  = @($expected | Where-Object { $actual -notcontains $_ })
    Check ($missing.Count -eq 0) ("hosts block covers {0}/{1} expected FQDNs{2}" -f ($expected.Count - $missing.Count),$expected.Count,$(if ($missing.Count) { " (missing: $($missing -join ', '))" } else { '' }))
    $extra = @($actual | Where-Object { $expected -notcontains $_ })
    if ($extra.Count) { Note ("hosts block also sinkholes {0} FQDN(s) outside the current scope: {1}" -f $extra.Count,($extra -join ', ')) }

    # H-A: all four policy values, not just EnableCdp.
    foreach ($n in $PolicyNames) {
        $v = (Get-ItemProperty $PolicyKey -Name $n -ErrorAction SilentlyContinue).$n
        Check ($v -eq 0) ("{0,-24} = {1} (want 0)" -f $n,$(if ($null -ne $v) { $v } else { 'unset' }))
    }

    # H-A: each rule's Enabled/Action/Direction/service filter - a disabled rule is not a block.
    foreach ($svc in $services) {
        $name = "$FwPrefix block $svc out"
        $r = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
        if ($r.Count -eq 0) { Check $false ("firewall rule missing: '{0}'" -f $name); continue }
        if ($r.Count -gt 1) { Check $false ("{0} duplicate firewall rules named '{1}'" -f $r.Count,$name); continue }
        $sf = "$((@($r[0] | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue) | Select-Object -First 1).Service)"
        $ok = ("$($r[0].Enabled)" -eq 'True') -and ("$($r[0].Action)" -eq 'Block') -and ("$($r[0].Direction)" -eq 'Outbound') -and ($sf -eq $svc)
        Check $ok ("firewall {0,-18} Enabled={1} Action={2} Dir={3} Service={4}" -f $svc,$r[0].Enabled,$r[0].Action,$r[0].Direction,$sf)
    }
    $strayRules = @(Get-NetFirewallRule -DisplayName "$FwPrefix*" -ErrorAction SilentlyContinue |
                    Where-Object { $services -notcontains ($_.DisplayName -replace "^$FwPrefix block (.+) out$",'$1') })
    if ($strayRules.Count) { Note ("{0} GDID firewall rule(s) outside the current scope: {1}" -f $strayRules.Count,(($strayRules | ForEach-Object { $_.DisplayName }) -join '; ')) }

    if (Test-Path $InstallDir)      { Check (-not (Test-PathUserWritable $InstallDir)) "install dir not writable by standard users" }
    if (Test-Path $InstalledScript) { Check (-not (Test-PathUserWritable $InstalledScript)) "installed script not writable by standard users" }
    # VR-1 regression: a trusted DACL with an untrusted owner is still hijackable (owner has implicit
    # WRITE_DAC), so verify ownership too - this is the check that would catch a pre-created dir.
    if (Test-Path $InstallDir)      { Check (-not (Test-PathOwnerUntrusted $InstallDir)) "install dir owned by SYSTEM/Administrators (not a standard user)" }
    if (Test-Path $InstalledScript) { Check (-not (Test-PathOwnerUntrusted $InstalledScript)) "installed script owned by SYSTEM/Administrators" }
    # The task runs as SYSTEM and is not readable by a standard user, so only check it when elevated.
    if (Test-IsElevated) {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Check ([bool]$task) "persistence task registered"
        if ($task) {
            # L-D/M-C: a task whose args lost a scope switch silently narrows the mitigation on the
            # next reboot, which is exactly the bug -IncludeLoginLive persistence once had.
            $want = Get-PersistenceArgument $wantLogin $wantClassic
            $got  = "$(($task.Actions | Select-Object -First 1).Arguments)"
            Check ($got.Trim() -eq $want.Trim()) ("task args match recorded scope{0}" -f $(if ($got.Trim() -ne $want.Trim()) { " (task: '$got')" } else { '' }))
        }
    } else {
        Note "persistence task not checked (SYSTEM-owned; re-run elevated to include it)"
    }

    Write-Host "  -- advisory (does NOT affect the exit code) --"
    if ($wantLogin) { Note "login.live.com IS being sinkholed (you chose -IncludeLoginLive): MSA sign-in and the Microsoft Store will fail. Run -Undo, or -Apply without the switch, to restore them." 'Yellow' }
    else            { Note "login.live.com is NOT sinkholed (default): MSA sign-in keeps working." }
    foreach ($s in $ClassicKillServices) {
        if ($services -contains $s) { continue }
        $w = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue
        if ($null -eq $w) { continue }
        Note ("classic telemetry {0,-18} State={1} Start={2} (out of scope: not checked, not required)" -f $s,$w.State,$w.StartMode)
    }
    if ($IncludeReachability) {
        # M-D: reachability depends on live DNS + routing, so it can FAIL for reasons that have
        # nothing to do with this tool (offline, corporate proxy, run before -Apply). It is
        # reported, never gated.
        Write-Host "  -- endpoint reachability (advisory; want closed) --"
        foreach ($f in $DdsHosts) {
            $r = Test-Endpoint $f
            Note ("{0,-32} IP={1,-16} 443={2}" -f $r.FQDN,$r.IP,$r.Https443) $(if ($r.Https443) { 'Yellow' } else { 'DarkGray' })
        }
    } else {
        Note "endpoint reachability not probed (add -IncludeReachability; it is slow, network-dependent and advisory only)"
    }

    if ($script:Fail -eq 0) {
        Write-Host "`nALL CONFIGURATION CHECKS PASS" -ForegroundColor Green
        Write-Ceiling      # H-B: green must not read as "you are anonymous"
        exit 0
    }
    Write-Host "`n$($script:Fail) FAILED CHECK(S)" -ForegroundColor Red
    exit 1
}

function Invoke-Test {
    Assert-Admin
    # A-3: -Test narrows the managed hosts block to two FQDNs for the duration of the run. On a
    # machine that is currently suppressed that REDUCES live protection, so refuse by default.
    $applied = $false
    try { $applied = (Test-HostsBlockPresent) -or [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) } catch { $applied = $false }
    if ($applied -and -not $Force) {
        Write-Host "REFUSING to run -Test: suppression is currently applied." -ForegroundColor Red
        Write-Host "  -Test rewrites the managed hosts block to two probe FQDNs and rolls it back afterwards," -ForegroundColor Yellow
        Write-Host "  which would leave you less protected for the length of the test." -ForegroundColor Yellow
        Write-Host "  Use -Verify to check the applied configuration, or -Test -Force to accept that window."
        exit 4
    }
    # A-9: -Test writes an audit log under $InstallDir, so the directory must be locked down first -
    # otherwise -Test would create a user-writable dir next to the SYSTEM task path (the H-1 class).
    $installExisted = Test-Path -LiteralPath $InstallDir
    Protect-InstallDir
    $log = Start-AuditLog 'test'      # M-A: -Test mutates system state, so it gets a transcript too
    $proof = 'activity.windows.com','aad.cs.dds.microsoft.com'
    $verdict = @{ Verdict='FAILED'; Exit=1; Detail='test did not complete' }
    Write-Host "=== REVERSIBLE LIVE TEST (hostname + firewall; services untouched) ===" -ForegroundColor Cyan
    Write-Host "Log: $log" -ForegroundColor DarkGray
    # M-2/F5: snapshot the EXACT bytes of the hosts file so rollback is byte-for-byte
    # (preserves BOM, encoding, newline style, unrelated content). $null = file did not exist.
    $hostsSnapshot = if (Test-Path -LiteralPath $HostsPath) { [System.IO.File]::ReadAllBytes($HostsPath) } else { $null }
    try {
        Write-Host "`n-- BEFORE --" -ForegroundColor Yellow
        $before = @($proof | ForEach-Object { Test-Endpoint $_ })
        $before | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "-- APPLYING sinkhole + one firewall rule (CDPSvc) --" -ForegroundColor Yellow
        Set-HostsBlock $proof
        New-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE CDPSvc out" -Direction Outbound -Action Block `
            -Service CDPSvc -Profile Any -Enabled True | Out-Null
        Start-Sleep -Milliseconds 500; Clear-DnsCache
        Write-Host "-- AFTER --" -ForegroundColor Yellow
        $after = @($proof | ForEach-Object { Test-Endpoint $_ })
        $after | Format-Table -AutoSize | Out-String | Write-Host
        $fw = Get-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE*" -ErrorAction SilentlyContinue
        $svcFilter = if ($fw) { "$((@($fw | Get-NetFirewallServiceFilter) | Select-Object -First 1).Service)" } else { '(none)' }
        # A-4: proof requires reachable-before -> blocked-after. "Already unreachable" proves nothing.
        $verdict = Get-TestVerdict $before $after
        Write-Host ("`nVERDICT: {0} - {1}" -f $verdict.Verdict,$verdict.Detail) -ForegroundColor $(if ($verdict.Exit -eq 0) { 'Green' } else { 'Yellow' })
        Write-Host ("  {0}/{1} endpoints went reachable -> blocked; firewall rule scoped to '{2}'." -f $verdict.Proved,$verdict.ReachableBefore,$svcFilter)
        # H-B: say exactly what was and was not measured.
        Write-Host "  This proves HOSTNAME REACHABILITY BLOCKING only. It does NOT prove the GDID stopped" -ForegroundColor Yellow
        Write-Host "  egressing: a privileged component can still reach the graph over DoH or a hardcoded IP," -ForegroundColor Yellow
        Write-Host "  and this tool never observes the absence of GDID traffic on the wire." -ForegroundColor Yellow
    } finally {
        Write-Host "`n-- ROLLING BACK (always runs) --" -ForegroundColor Yellow
        if ($null -ne $hostsSnapshot) { [System.IO.File]::WriteAllBytes($HostsPath, $hostsSnapshot) }
        elseif (Test-Path -LiteralPath $HostsPath) { Remove-Item -LiteralPath $HostsPath -Force }   # F5: file did not exist pre-test
        Get-NetFirewallRule -DisplayName "$FwPrefix TESTPROBE*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        Clear-DnsCache
        ($proof | ForEach-Object { Test-Endpoint $_ }) | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "Hosts file and firewall restored to pre-test state." -ForegroundColor Green
        if (-not $installExisted) {
            Write-Host "Left behind on purpose: $InstallDir (hardened) holding this run's audit log." -ForegroundColor DarkGray
        }
        try { Stop-Transcript | Out-Null } catch { Write-Verbose $_.Exception.Message }
    }
    exit $verdict.Exit
}

# --- dispatcher (skipped when dot-sourced for tests) -----------------------
# Switches on the mode switches themselves rather than $PSCmdlet.ParameterSetName so that a bare
# modifier (e.g. `-IncludeLoginLive` with no mode) can never resolve into an unintended -Apply.
if ($MyInvocation.InvocationName -ne '.') {
    if     ($Apply) { Invoke-Apply }
    elseif ($Undo)  { Invoke-Undo }
    elseif ($Test)  { Invoke-Test }
    else            { Invoke-Verify }
}
