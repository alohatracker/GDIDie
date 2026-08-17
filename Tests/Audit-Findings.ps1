<#
    Audit-Findings.ps1 - one or more assertions per registered review finding.

    Every assertion is tagged with an Id from Tests/findings.psd1. Tests/Invoke-AuditLoop.ps1 then
    enforces the loop-closing invariant: a finding marked Fixed must have at least one assertion
    that RAN and PASSED, and no assertion may cite an unregistered Id.

    These are regression pins, not a restatement of the fix: each one fails if the specific defect
    the reviewer described comes back. Three assertion styles are used, in order of preference:
      behavioural - call the pure helper and check the contract (strongest, platform-independent)
      structural  - walk the AST (used where the behaviour needs Windows services/registry/firewall)
      documentary - assert the doc text a finding required (used for Accepted residuals)

        powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\Audit-Findings.ps1 [-ReportPath out.json]
#>
[CmdletBinding()]
param(
    [string]$ReportPath
)
$ErrorActionPreference = 'Stop'
$Repo     = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ToolPath = Join-Path $Repo 'Suppress-GDID.ps1'
$script:Results = New-Object System.Collections.Generic.List[object]

# --- registry ---------------------------------------------------------------
$Registry = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'findings.psd1')
$ValidIds = @($Registry.Findings | ForEach-Object { $_.Id })

function Assert-Finding([string]$Id,[bool]$Cond,[string]$Name) {
    if ($ValidIds -notcontains $Id) { throw "Assertion cites unregistered finding '$Id' - add it to Tests/findings.psd1." }
    $status = if ($Cond) { 'PASS' } else { 'FAIL' }
    $script:Results.Add([pscustomobject]@{ Id=$Id; Status=$status; Name=$Name })
    $c = if ($Cond) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1,-5} {2}" -f $status,$Id,$Name) -ForegroundColor $c
}
function Write-SkippedFinding([string]$Id,[string]$Name,[string]$Why) {
    if ($ValidIds -notcontains $Id) { throw "Assertion cites unregistered finding '$Id' - add it to Tests/findings.psd1." }
    $script:Results.Add([pscustomobject]@{ Id=$Id; Status='SKIP'; Name="$Name ($Why)" })
    Write-Host ("  [SKIP] {0,-5} {1} ({2})" -f $Id,$Name,$Why) -ForegroundColor Yellow
}
function Section([string]$t) { Write-Host "`n$t" -ForegroundColor Cyan }

# --- load the tool + its AST -----------------------------------------------
. $ToolPath
$onWindows = Test-IsWindowsHost
$parseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile($ToolPath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw "Suppress-GDID.ps1 does not parse: $($parseErrors[0].Message)" }
$ToolText = Get-Content -LiteralPath $ToolPath -Raw

function Get-Fn([string]$name) {
    $f = $Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $f) { throw "function '$name' not found in Suppress-GDID.ps1" }
    $f
}
function Get-CallAst($fn,[string]$cmd) {
    @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $cmd }, $true))
}
function Test-CommandCall($fn,[string]$cmd) { (Get-CallAst $fn $cmd).Count -gt 0 }
function Get-FirstCallLine($fn,[string]$cmd) {
    $c = Get-CallAst $fn $cmd
    if ($c.Count -eq 0) { return [int]::MaxValue }
    ($c | ForEach-Object { $_.Extent.StartLineNumber } | Sort-Object)[0]
}
function Get-ExitLine($fn,[string]$code) {
    $e = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true) |
           Where-Object { "$($_.Pipeline.Extent.Text)".Trim() -eq $code })
    if ($e.Count -eq 0) { return [int]::MaxValue }
    ($e | ForEach-Object { $_.Extent.StartLineNumber } | Sort-Object)[0]
}
function Test-RefsVar($fn,[string]$varName) {
    [bool]($fn.Find({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq $varName }, $true))
}
function Test-InsideIfOn($node,[string]$varName) {
    # walk up the AST looking for an enclosing if whose condition mentions $varName
    $p = $node.Parent
    while ($null -ne $p) {
        if ($p -is [System.Management.Automation.Language.IfStatementAst]) {
            foreach ($clause in $p.Clauses) {
                if ("$($clause.Item1.Extent.Text)" -match [regex]::Escape('$' + $varName)) { return $true }
            }
        }
        $p = $p.Parent
    }
    $false
}
function Get-DocText([string]$rel) {
    $p = Join-Path $Repo $rel
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    Get-Content -LiteralPath $p -Raw
}
$Readme = Get-DocText 'README.md'
$AuditDoc = Get-DocText 'SECURITY-AUDIT.md'

# =============================================================================================
Section 'H-A  -Verify must check everything -Apply changed'
# behavioural: one source of truth for the service list
Assert-Finding 'H-A' ((@(Get-KillServiceList $false) -join ',') -eq 'CDPSvc,DoSvc')                    'default scope service list is exactly the GDID producers'
Assert-Finding 'H-A' ((@(Get-KillServiceList $true).Count) -eq 4)                                      'classic scope adds both telemetry services'
$fnApply = Get-Fn 'Invoke-Apply'; $fnVerify = Get-Fn 'Invoke-Verify'
Assert-Finding 'H-A' ((Test-CommandCall $fnApply 'Get-KillServiceList') -and (Test-CommandCall $fnVerify 'Get-KillServiceList')) 'apply and verify derive services from the same helper'
Assert-Finding 'H-A' ((Test-CommandCall $fnApply 'Get-ExpectedHostList') -and (Test-CommandCall $fnVerify 'Get-ExpectedHostList')) 'apply and verify derive the FQDN set from the same helper'
Assert-Finding 'H-A' ((Test-RefsVar $fnApply 'PolicyNames') -and (Test-RefsVar $fnVerify 'PolicyNames')) 'apply and verify iterate the same policy-value list'
Assert-Finding 'H-A' ($fnVerify.Extent.Text -notmatch "foreach\s*\(\s*\`$s\s+in\s+'CDPSvc','DoSvc'\s*\)") 'the hardcoded two-service loop is gone'
Assert-Finding 'H-A' (Test-CommandCall $fnVerify 'Get-NetFirewallServiceFilter')                            'verify inspects each rule service filter, not just a rule count'
Assert-Finding 'H-A' ($fnVerify.Extent.Text -notmatch '-ge 3')                                        'verify no longer passes on a bare rule count of 3'
Assert-Finding 'H-A' (Test-CommandCall $fnVerify 'Get-HostsBlockFqdn')                                     'verify compares hosts-block contents'
# behavioural: the exact false-pass the reviewer described
$expected  = @(Get-ExpectedHostList $false)
$blockOk   = Add-ManagedBlock @('127.0.0.1 localhost') $expected
$blockThin = @($blockOk | Where-Object { $_ -notmatch 'activity\.windows\.com' })
Assert-Finding 'H-A' (($blockThin -contains $Sentinel0) -and ((@(Get-ManagedBlockFqdn $blockThin)) -notcontains 'activity.windows.com')) 'an incomplete block is present-but-detectably-short'
$missing = @($expected | Where-Object { (@(Get-ManagedBlockFqdn $blockThin)) -notcontains $_ })
Assert-Finding 'H-A' ($missing.Count -eq 1 -and $missing[0] -eq 'activity.windows.com')             'the missing FQDN is named, not just counted'

Section 'H-B  the honest ceiling must be in the runtime voice, not only the README footer'
Assert-Finding 'H-B' (@($script:Ceiling).Count -ge 3)                                               'a runtime ceiling banner exists'
$ceilText = ($script:Ceiling -join ' ')
Assert-Finding 'H-B' ($ceilText -match 'does NOT make you anonymous|not make you anonymous')        'banner says it does not make you anonymous'
Assert-Finding 'H-B' ($ceilText -match 'DNS-over-HTTPS|DoH')                                        'banner names the DoH bypass'
Assert-Finding 'H-B' ($ceilText -match 'hardcoded IP')                                              'banner names the hardcoded-IP bypass'
Assert-Finding 'H-B' ($ceilText -match 'not doing it on Windows')                                   'banner carries the README own ceiling verdict'
Assert-Finding 'H-B' (Test-CommandCall $fnApply 'Write-Ceiling')                                            '-Apply prints the ceiling on completion'
Assert-Finding 'H-B' (Test-CommandCall $fnVerify 'Write-Ceiling')                                           '-Verify prints the ceiling on ALL PASS (green != anonymous)'
$fnTest = Get-Fn 'Invoke-Test'
Assert-Finding 'H-B' ($fnTest.Extent.Text -match 'HOSTNAME REACHABILITY BLOCKING only')               '-Test verdict states what it actually measured'
Assert-Finding 'H-B' ($fnTest.Extent.Text -match 'does NOT prove the GDID stopped')                   '-Test verdict refuses to claim GDID suppression'
Assert-Finding 'H-B' ($Readme -match 'does \*\*not\*\* make you anonymous|does not make you anonymous') 'README still states the ceiling'

Section 'H-C  -Undo must never guess a service configuration'
$rawState = @{ servicesRaw = @{ CDPSvc = @{ Start = 2; DelayedAutostart = 1 } } }
$p1 = Get-ServiceRestorePlan $rawState @('CDPSvc') $false
Assert-Finding 'H-C' ($p1['CDPSvc'].Action -eq 'set-raw' -and $p1['CDPSvc'].Start -eq 2)            'a recorded raw original is restored exactly'
Assert-Finding 'H-C' ($p1['CDPSvc'].DelayedAutostart -eq 1)                                         'delayed-autostart survives the round trip (a friendly StartMode cannot express it)'
$p2 = Get-ServiceRestorePlan $rawState @('DoSvc') $false
Assert-Finding 'H-C' ($p2['DoSvc'].Action -eq 'skip')                                               'state present but no original for this service -> left alone, never guessed'
$p3 = Get-ServiceRestorePlan $null @('CDPSvc','DoSvc') $false
Assert-Finding 'H-C' (@($p3.Values | Where-Object { $_.Action -eq 'refuse' }).Count -eq 2)          'no state and no -Force -> refuse (both services)'
$p4 = Get-ServiceRestorePlan $null @('CDPSvc','DiagTrack') $true
Assert-Finding 'H-C' ($p4['CDPSvc'].Action -eq 'default' -and $p4['CDPSvc'].Mode -eq 'Automatic')   'no state WITH -Force -> documented default, flagged as such'
Assert-Finding 'H-C' ($p4['DiagTrack'].Mode -eq $ServiceDefaults['DiagTrack'])                      'defaults come from the published table, not an inline literal'
$p5 = Get-ServiceRestorePlan @{ services = @{ DoSvc = 'Manual' } } @('DoSvc') $false
Assert-Finding 'H-C' ($p5['DoSvc'].Action -eq 'set-mode' -and $p5['DoSvc'].Mode -eq 'Manual')       'legacy friendly-only state still restores'
$p6 = Get-ServiceRestorePlan @{ cdpUserStart = 2 } @('CDPUserSvc') $false
Assert-Finding 'H-C' ($p6['CDPUserSvc'].Action -eq 'set-raw' -and $p6['CDPUserSvc'].Start -eq 2)    'legacy v1.4.0 cdpUserStart is honoured'
# the real path: state.json is JSON, so the plan must work on a ConvertFrom-Json object
$json = @{ servicesRaw = @{ CDPSvc = @{ Start = 3; DelayedAutostart = 'ABSENT' } }; services = @{ DiagTrack = 'Auto' } } |
        ConvertTo-Json -Depth 5 | ConvertFrom-Json
$p7 = Get-ServiceRestorePlan $json @('CDPSvc','DiagTrack','dmwappushservice') $false
Assert-Finding 'H-C' ($p7['CDPSvc'].Action -eq 'set-raw' -and $p7['CDPSvc'].Start -eq 3)            'plan works against a real ConvertFrom-Json state object'
Assert-Finding 'H-C' ($p7['DiagTrack'].Action -eq 'set-mode' -and $p7['dmwappushservice'].Action -eq 'skip') 'per-service actions are independent'
$fnUndo = Get-Fn 'Invoke-Undo'
Assert-Finding 'H-C' ((Get-ExitLine $fnUndo '4') -lt (Get-FirstCallLine $fnUndo 'Remove-Persistence'))  'the refusal happens BEFORE anything is changed (no half-undo)'
Assert-Finding 'H-C' ((Get-ExitLine $fnUndo '4') -lt (Get-FirstCallLine $fnUndo 'Remove-HostsBlock'))   'the refusal precedes the hosts edit too'
Assert-Finding 'H-C' ($fnUndo.Extent.Text -match 'REFUSING to undo')                                  'the refusal is explicit, not a silent skip'
Assert-Finding 'H-C' ($fnUndo.Extent.Text -match 'Nothing was changed')                               'the refusal tells the user nothing was changed'
Assert-Finding 'H-C' ($Readme -match 'exact.{0,80}state file is present|state file is present.{0,80}exact')  'README no longer claims an unconditional exact undo'

Section 'M-A  -Test mutates state, so it must leave an audit log'
Assert-Finding 'M-A' (Test-CommandCall $fnTest 'Start-AuditLog')                                            '-Test opens a transcript'
Assert-Finding 'M-A' (Test-CommandCall $fnTest 'Stop-Transcript')                                           '-Test closes the transcript'
Assert-Finding 'M-A' ((Get-FirstCallLine $fnTest 'Start-AuditLog') -lt (Get-FirstCallLine $fnTest 'Set-HostsBlock')) 'the transcript starts before the first mutation'
Assert-Finding 'M-A' ($fnTest.Extent.Text -match 'Stop-Transcript[\s\S]{0,400}$')                     'the transcript stop is in the finally block that always runs'

Section 'M-B  the check-then-register TOCTOU window'
$fnInstall = Get-Fn 'Install-Persistence'
Assert-Finding 'M-B' ((Get-CallAst $fnInstall 'Assert-InstallSafe').Count -ge 2)                      'Assert-InstallSafe runs both before AND after registration'
$regLine = Get-FirstCallLine $fnInstall 'Register-ScheduledTask'
$safeLines = @((Get-CallAst $fnInstall 'Assert-InstallSafe') | ForEach-Object { $_.Extent.StartLineNumber })
Assert-Finding 'M-B' ((@($safeLines | Where-Object { $_ -lt $regLine }).Count -ge 1) -and (@($safeLines | Where-Object { $_ -gt $regLine }).Count -ge 1)) 'the second assertion is genuinely after Register-ScheduledTask'
Assert-Finding 'M-B' (Test-CommandCall $fnInstall 'Remove-Persistence')                                     'a failed post-check unregisters the task (fail-closed)'
Assert-Finding 'M-B' ($fnInstall.Extent.Text -match 'registered task arguments do not match')         'the registered task is compared against intent'
Assert-Finding 'M-B' ($AuditDoc -match 'TOCTOU')                                                    'SECURITY-AUDIT.md names the TOCTOU class explicitly'
Assert-Finding 'M-B' ($AuditDoc -match 'T-1')                                                       'it is tracked as a numbered finding, not a footnote'

Section 'M-C  classic telemetry is opt-in, so the blast radius matches the threat model'
Assert-Finding 'M-C' ((@(Get-KillServiceList $false)) -notcontains 'DiagTrack')                        'DiagTrack is NOT disabled by default'
Assert-Finding 'M-C' ((@(Get-KillServiceList $false)) -notcontains 'dmwappushservice')                 'dmwappushservice is NOT disabled by default'
Assert-Finding 'M-C' ((@(Get-KillServiceList $true)) -contains 'DiagTrack')                            'the opt-in switch does disable it'
Assert-Finding 'M-C' ($ToolText -match '\[switch\]\$IncludeClassicTelemetry')                        'the switch exists and mirrors -IncludeLoginLive'
Assert-Finding 'M-C' ((Get-PersistenceArgument $false $true) -match '-IncludeClassicTelemetry')      'the boot task carries the choice (it would otherwise narrow on reboot)'
$save = Get-Fn 'Save-State'
Assert-Finding 'M-C' ($save.Extent.Text -match "includeClassicTelemetry")                           'the choice is recorded in state.json scope'
Assert-Finding 'M-C' ($fnVerify.Extent.Text -match 'out of scope')                                    'verify reports out-of-scope classic services as advisory, not as a FAIL'
Assert-Finding 'M-C' ($Readme -match 'IncludeClassicTelemetry')                                     'README documents the switch'
Assert-Finding 'M-C' ($Readme -match 'DiagTrack')                                                   'README names the side effects of the classic layer'

Section 'M-D  configuration verification must not depend on the network'
# behavioural: Note must never touch the failure counter that drives the exit code
$before = $script:Fail
Note 'advisory probe line' | Out-Null
Assert-Finding 'M-D' ($script:Fail -eq $before)                                                     'advisory output does not affect the exit code'
Check $false '<<harness self-test of the gating counter - this FAIL line is expected>>' | Out-Null
Assert-Finding 'M-D' ($script:Fail -eq ($before + 1))                                               'gating checks still do affect the exit code'
$script:Fail = $before                                                                              # undo the self-test
$teCalls = Get-CallAst $fnVerify 'Test-Endpoint'
Assert-Finding 'M-D' ($teCalls.Count -ge 1)                                                         'verify can still probe reachability'
Assert-Finding 'M-D' (@($teCalls | Where-Object { -not (Test-InsideIfOn $_ 'IncludeReachability') }).Count -eq 0) 'every probe is behind -IncludeReachability'
Assert-Finding 'M-D' ($ToolText -match '\[switch\]\$IncludeReachability')                            'the opt-in switch exists'
$reachNotes = @((Get-CallAst $fnVerify 'Note') | Where-Object { Test-InsideIfOn $_ 'IncludeReachability' })
$reachChecks = @((Get-CallAst $fnVerify 'Check') | Where-Object { Test-InsideIfOn $_ 'IncludeReachability' })
Assert-Finding 'M-D' ($reachNotes.Count -ge 1 -and $reachChecks.Count -eq 0)                        'reachability results are reported via Note, never Check'
Assert-Finding 'M-D' ($Readme -match 'IncludeReachability')                                          'README documents the split'

Section 'L-A  transcripts must not grow without bound'
Assert-Finding 'L-A' ((@(Select-PruneTarget (1..40 | ForEach-Object { "gdid-$_.log" }) 30)).Count -eq 10) 'over the cap, the excess is pruned'
Assert-Finding 'L-A' ((@(Select-PruneTarget @('a','b') 30)).Count -eq 0)                           'under the cap, nothing is pruned'
$startLog = Get-Fn 'Start-AuditLog'
Assert-Finding 'L-A' (Test-CommandCall $startLog 'Remove-OldAuditLog')                                    'every logged run prunes (including the boot task)'
Assert-Finding 'L-A' ($LogKeep -gt 0)                                                               'the cap is a positive number'
Assert-Finding 'L-A' ($AuditDoc -match 'I-1')                                                       'SECURITY-AUDIT.md I-1 is still tracked'
Assert-Finding 'L-A' ($AuditDoc -match 'Fixed.{0,40}1\.5\.0|rotat')                                 'SECURITY-AUDIT.md reflects that rotation now exists'

Section 'L-B  a service that refused to stop must not be reported as stopped'
Assert-Finding 'L-B' (Test-CommandCall $fnApply 'Stop-ServiceReporting')                                    'apply uses the reporting stop helper'
Assert-Finding 'L-B' ((Get-CallAst $fnApply 'Stop-Service').Count -eq 0)                              'no bare Stop-Service -EA SilentlyContinue left in apply'
$stopFn = Get-Fn 'Stop-ServiceReporting'
Assert-Finding 'L-B' ($stopFn.Extent.Text -match 'Get-Service')                                     'the helper re-reads the real post-stop state'
Assert-Finding 'L-B' ($fnApply.Extent.Text -match 'still RUNNING')                                    'apply warns when a service stayed running'
Assert-Finding 'L-B' ($fnApply.Extent.Text -match 'until reboot')                                     'the warning says what that means for the user'
Assert-Finding 'L-B' ($fnVerify.Extent.Text -match "State=")                                          'verify reports the run state for every in-scope service'

Section 'L-C  pinned CI tooling needs automated bump PRs'
$dependabot = Get-DocText '.github/dependabot.yml'
Assert-Finding 'L-C' ($dependabot -ne '')                                                           '.github/dependabot.yml exists'
Assert-Finding 'L-C' ($dependabot -match 'github-actions')                                          'the action pins are watched'
$ci = Get-DocText '.github/workflows/ci.yml'
Assert-Finding 'L-C' ($ci -match 'actions/checkout@[0-9a-f]{40}')                                    'checkout is still pinned by SHA (the pinning was right)'
Assert-Finding 'L-C' ($ci -match 'RequiredVersion')                                                  'PSScriptAnalyzer is still version-pinned'
Assert-Finding 'L-C' ($ci -match 'schedule:')                                                        'a scheduled run surfaces rot on a cadence, not at the next push'

Section 'L-D  a sinkholed login.live.com needs an on-screen reminder'
Assert-Finding 'L-D' ($fnVerify.Extent.Text -match 'login\.live\.com IS being sinkholed')             'verify names the active login.live.com sinkhole'
Assert-Finding 'L-D' ($fnVerify.Extent.Text -match 'Microsoft Store')                                 'it names the breakage the user will actually notice'
Assert-Finding 'L-D' ($fnVerify.Extent.Text -match 'login\.live\.com is NOT sinkholed')               'and confirms the default case explicitly'
Assert-Finding 'L-D' (Test-CommandCall $fnVerify 'Get-AppliedScope')                                        'the reminder is driven by recorded scope, not a guess'
Assert-Finding 'L-D' ($fnApply.Extent.Text -match 'MSA sign-in and the Store will fail')              'apply warns at the moment of choosing'

Section 'A-1  an unrecognised start mode must throw, never write a garbage Start value'
Assert-Finding 'A-1' ((Get-SvcStartValue 'Disabled') -eq 4)                                         'known modes still map correctly'
$threw = $false; try { Get-SvcStartValue 'NotAMode' | Out-Null } catch { $threw = $true }
Assert-Finding 'A-1' $threw                                                                          'an unknown mode throws'
$threw = $false; try { Get-SvcStartValue $null | Out-Null } catch { $threw = $true }
Assert-Finding 'A-1' $threw                                                                          'a null mode throws instead of writing Start=$null'
$setMode = Get-Fn 'Set-SvcStartMode'
Assert-Finding 'A-1' (Test-CommandCall $setMode 'Get-SvcStartValue')                                       'the writer goes through the validated map'
Assert-Finding 'A-1' ($setMode.Extent.Text -notmatch '\$map\[\$mode\]')                              'the unchecked hashtable lookup is gone'
$setRaw = Get-Fn 'Set-SvcStartRaw'
Assert-Finding 'A-1' ($setRaw.Extent.Text -match 'out-of-range')                                     'the raw writer range-checks Start too'

Section 'A-2  an existing-but-disabled firewall rule must be healed, not skipped'
$fw = Get-Fn 'New-FwBlock'
Assert-Finding 'A-2' (Test-CommandCall $fw 'Set-NetFirewallRule')                                          'existing rules are re-asserted'
Assert-Finding 'A-2' ($fw.Extent.Text -match '-Enabled True')                                        'Enabled is part of what gets re-asserted'
Assert-Finding 'A-2' (Test-CommandCall $fw 'Remove-NetFirewallRule')                                       'duplicate rules are collapsed'
Assert-Finding 'A-2' ($fw.Extent.Text -notmatch 'if \(-not \(Get-NetFirewallRule')                   'the old skip-if-exists shortcut is gone'
Assert-Finding 'A-2' ($fw.Ast.ParamBlock -or $fw.Parameters.Count -ge 1)                             'the rule set is driven by the caller scope'

Section 'A-3  -Test must not quietly reduce live protection'
Assert-Finding 'A-3' ((Get-ExitLine $fnTest '4') -lt (Get-FirstCallLine $fnTest 'Set-HostsBlock'))       'the refusal precedes the hosts rewrite'
Assert-Finding 'A-3' ($fnTest.Extent.Text -match 'REFUSING to run -Test')                              'the refusal is explicit'
Assert-Finding 'A-3' ($fnTest.Extent.Text -match 'less protected')                                     'it explains why (the protection window)'
Assert-Finding 'A-3' ($fnTest.Extent.Text -match '-Test -Force')                                       'it names the override'
Assert-Finding 'A-3' (Test-CommandCall $fnTest 'Test-HostsBlockPresent')                                     'applied-state detection looks at real state'

Section 'A-4  -Test must not claim proof it did not obtain'
$v1 = Get-TestVerdict @(@{FQDN='a';Https443=$true},@{FQDN='b';Https443=$true}) @(@{FQDN='a';Https443=$false},@{FQDN='b';Https443=$false})
Assert-Finding 'A-4' ($v1.Verdict -eq 'PROVED' -and $v1.Exit -eq 0)                                  'reachable -> blocked on all endpoints = PROVED (exit 0)'
$v2 = Get-TestVerdict @(@{FQDN='a';Https443=$true},@{FQDN='b';Https443=$true}) @(@{FQDN='a';Https443=$false},@{FQDN='b';Https443=$true})
Assert-Finding 'A-4' ($v2.Verdict -eq 'FAILED' -and $v2.Exit -eq 1 -and $v2.StillOpen -contains 'b') 'one endpoint left open = FAILED, and it is named'
$v3 = Get-TestVerdict @(@{FQDN='a';Https443=$false}) @(@{FQDN='a';Https443=$false})
Assert-Finding 'A-4' ($v3.Verdict -eq 'INCONCLUSIVE' -and $v3.Exit -eq 3)                            'already-unreachable proves nothing (exit 3, not 0)'
$v4 = Get-TestVerdict @(@{FQDN='a';Https443=$true},@{FQDN='b';Https443=$false}) @(@{FQDN='a';Https443=$false},@{FQDN='b';Https443=$false})
Assert-Finding 'A-4' ($v4.Verdict -eq 'PROVED' -and $v4.ReachableBefore -eq 1)                       'endpoints unreachable beforehand are excluded from the denominator'
Assert-Finding 'A-4' ($fnTest.Extent.Text -match 'exit \$verdict\.Exit')                               '-Test exit code comes from the verdict'
Assert-Finding 'A-4' ($Readme -match '\| *3 *\||exit ``?3``?|`3`')                                   'README documents exit code 3'

Section 'A-5  the three shipped copies of the blocklist must agree'
$txt = @(Get-Content (Join-Path $Repo 'gdid-domains.txt') | ForEach-Object { $_.Trim() })
$txtActive = @($txt | Where-Object { $_ -and $_ -notmatch '^#' })
$scriptAll = @(@($DdsHosts) + @($TelemetryHosts))
$onlyTxt    = @($txtActive | Where-Object { $scriptAll -notcontains $_ })
$onlyScript = @($scriptAll | Where-Object { $txtActive -notcontains $_ })
Assert-Finding 'A-5' ($onlyTxt.Count -eq 0)    ("gdid-domains.txt has no entry the script omits{0}" -f $(if ($onlyTxt.Count) { ": $($onlyTxt -join ', ')" } else { '' }))
Assert-Finding 'A-5' ($onlyScript.Count -eq 0) ("the script sinkholes nothing missing from gdid-domains.txt{0}" -f $(if ($onlyScript.Count) { ": $($onlyScript -join ', ')" } else { '' }))
Assert-Finding 'A-5' (@($txt | Where-Object { $_ -match '^#\s*login\.live\.com$' }).Count -eq 1) 'login.live.com stays commented-out (opt-in) in the txt list'
$sh = Get-DocText 'pihole-add-gdid.sh'
$wild = @()
if ($sh -match '(?m)^for d in (.+); do') { $wild = @($Matches[1] -split '\s+' | Where-Object { $_ }) }
Assert-Finding 'A-5' ($wild.Count -ge 1) 'the Pi-hole helper wildcard list is parseable'
$uncovered = @($DdsHosts | Where-Object { $h = $_; -not (@($wild | Where-Object { $h -eq $_ -or $h.EndsWith(".$_") }).Count) })
Assert-Finding 'A-5' ($uncovered.Count -eq 0) ("every DDS/activity FQDN is covered by a Pi-hole wildcard{0}" -f $(if ($uncovered.Count) { ": $($uncovered -join ', ')" } else { '' }))
Assert-Finding 'A-5' ($sh -match 'login\.live\.com' -and $sh -match '(?m)^#\s*pihole --wild login\.live\.com') 'the Pi-hole helper also leaves login.live.com opt-in'

Section 'A-6  version and exit-code documentation must not drift'
Assert-Finding 'A-6' ($ToolText -match "(?m)^\s+Version $([regex]::Escape($Version))\s*$")           'the header comment version matches $Version'
foreach ($code in 0,1,2,3,4) {
    Assert-Finding 'A-6' ($ToolText -match "(?m)^\s+$code = ")                                       "exit code $code is documented in the header"
}
Assert-Finding 'A-6' ($Readme -match [regex]::Escape('-IncludeClassicTelemetry') -and $Readme -match [regex]::Escape('-IncludeReachability')) 'README modes table covers the new switches'

Section 'A-7  an untrusted state file needs a recovery path, not a raw throw'
# Test seam: shadow the ACL probe so the CLASSIFICATION logic is testable on both lanes.
$stateDir = Join-Path ([IO.Path]::GetTempPath()) ("gdidie-state-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
try {
    $StateFile = Join-Path $stateDir 'state.json'
    # Shadow BOTH ACL probes so the classification logic is testable on both lanes. VR-1 added an
    # owner check to Get-StateForUndo, so it needs a stub too, or Get-Acl fires on the Linux lane.
    $script:fakeWritable = $false; $script:fakeOwnerUntrusted = $false
    function Test-PathUserWritable([string]$path)   { $script:fakeWritable }
    function Test-PathOwnerUntrusted([string]$path) { $script:fakeOwnerUntrusted }

    Assert-Finding 'A-7' ((Get-StateForUndo).Status -eq 'missing')                                   'no file -> missing (not an exception)'
    Set-Content -LiteralPath $StateFile -Value 'this is not json {{{' -Encoding ASCII
    Assert-Finding 'A-7' ((Get-StateForUndo).Status -eq 'unreadable')                                'unparseable file -> unreadable (not an exception)'
    Set-Content -LiteralPath $StateFile -Value (@{ services = @{ CDPSvc = 'Auto' } } | ConvertTo-Json) -Encoding ASCII
    $ok = Get-StateForUndo
    Assert-Finding 'A-7' ($ok.Status -eq 'ok' -and (Get-PropValue $ok.State 'services'))             'a good file -> ok, with the parsed state'
    $script:fakeWritable = $true
    $bad = Get-StateForUndo
    Assert-Finding 'A-7' ($bad.Status -eq 'untrusted' -and $null -eq $bad.State)                     'a user-writable file -> untrusted AND never parsed'
    $script:fakeWritable = $false
    # VR-1: an untrusted OWNER (implicit WRITE_DAC) must classify untrusted and never be parsed.
    $script:fakeOwnerUntrusted = $true
    $badOwner = Get-StateForUndo
    Assert-Finding 'VR-1' ($badOwner.Status -eq 'untrusted' -and $null -eq $badOwner.State)          'a state file owned by a standard user -> untrusted AND never parsed'
    $script:fakeOwnerUntrusted = $false
} finally { Remove-Item $stateDir -Recurse -Force -ErrorAction SilentlyContinue }
Assert-Finding 'A-7' ($fnUndo.Extent.Text -match 'state file \$\(\$si\.Status\)')                       'undo surfaces the classification to the user'
Assert-Finding 'A-7' ($fnUndo.Extent.Text -match 'Re-run with -Force')                                 'undo names the escape hatch'
Assert-Finding 'A-7' ($fnUndo.Extent.Text -match 'Undo by hand')                                       'undo offers a manual path as well'

Section 'A-8  a missing state file must not leave the policy layer applied'
Assert-Finding 'A-8' ((Get-PolicyRestorePlanOrDefault $null $false).Count -eq 0)                     'no state, no -Force -> empty plan (caller must refuse)'
$dp = Get-PolicyRestorePlanOrDefault $null $true
Assert-Finding 'A-8' ($dp.Count -eq @($PolicyNames).Count)                                           'no state WITH -Force -> a plan for every policy value'
Assert-Finding 'A-8' (@($dp.Values | Where-Object { $_.Action -eq 'remove' }).Count -eq $dp.Count)    'the default action is remove (= default-Windows absent)'
$sp = Get-PolicyRestorePlanOrDefault @{ EnableCdp = 1 } $true
Assert-Finding 'A-8' ($sp['EnableCdp'].Action -eq 'set' -and $sp['EnableCdp'].Value -eq 1)            'a saved value always beats the default'
Assert-Finding 'A-8' (Test-CommandCall $fnUndo 'Get-PolicyRestorePlanOrDefault')                             'undo uses the default-aware plan'
Assert-Finding 'A-8' ($fnUndo.Extent.Text -match 'policy layer left applied')                          'undo warns if it could not restore the policy layer'

Section 'A-9  -Test must not create a user-writable install directory'
Assert-Finding 'A-9' (Test-CommandCall $fnTest 'Protect-InstallDir')                                         '-Test hardens the install dir'
Assert-Finding 'A-9' ((Get-FirstCallLine $fnTest 'Protect-InstallDir') -lt (Get-FirstCallLine $fnTest 'Start-AuditLog')) 'it hardens BEFORE writing the transcript into it'
Assert-Finding 'A-9' ($fnTest.Extent.Text -match 'Left behind on purpose')                             '-Test admits what it leaves behind rather than claiming a full restore'

Section 'A-10  the harness must not report a pass for something it never ran'
$unitText  = Get-DocText 'Tests/Run-Tests.ps1'
$smokeText = Get-DocText 'Tests/Smoke-Test.ps1'
$loopText  = Get-DocText 'Tests/Invoke-AuditLoop.ps1'
Assert-Finding 'A-10' ($unitText -match 'function Skip' -and $unitText -match 'Test-IsWindowsHost')  'unit suite skips Windows-only sections instead of failing'
Assert-Finding 'A-10' ($smokeText -match 'function Skip' -and $smokeText -match 'Test-IsWindowsHost') 'smoke suite does the same'
Assert-Finding 'A-10' ($unitText -match 'skipped')                                                    'skips are counted and printed, never folded into passes'
Assert-Finding 'A-10' ($loopText -match 'FailOnSkip')                                                 'the loop can be made to fail on any skip'
Assert-Finding 'A-10' ($loopText -match 'Disposition')                                                'the loop reads the findings registry to gate coverage'
# A gate nobody has watched fail is not a gate: the meta-test injects known regressions into a copy
# of the repo and asserts the loop rejects each one.
$metaText = Get-DocText 'Tests/Test-AuditLoop.ps1'
Assert-Finding 'A-10' ($metaText -ne '')                                                              'a meta-test for the loop itself exists'
Assert-Finding 'A-10' ($metaText -match 'UNVALIDATED' -and $metaText -match 'unregistered finding')   'it covers both coverage-gate failure modes'
Assert-Finding 'A-10' ($metaText -match 'control: an unmodified copy passes')                         'it has a control case, so a failure means the injected defect'
# A-12: the harness must run on the runtime the tool targets. Both of these actually broke the
# Windows lane on the first CI run while the Linux lane was green, which is the whole reason the
# Windows lane exists - so they are pinned rather than just fixed.
$psFiles = @(Get-ChildItem -LiteralPath $Repo -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notmatch '\.git' })
$threeArgJoin = @($psFiles | Where-Object {
    @(Get-Content -LiteralPath $_.FullName |
      Where-Object { $_ -notmatch '^\s*#' } |
      Where-Object { $_ -match "Join-Path\s+[^\s(|;]+\s+'[^']*'\s+'[^']*'" }).Count -gt 0
} | ForEach-Object { $_.Name })
Assert-Finding 'A-12' ($threeArgJoin.Count -eq 0) ("no 3-segment Join-Path (-AdditionalChildPath is PowerShell 6+, absent in the 5.1 target){0}" -f $(if ($threeArgJoin.Count) { ": $($threeArgJoin -join ', ')" } else { '' }))
$shadowed = @()
foreach ($f in $psFiles) {
    $fa = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    foreach ($fn in @($fa.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))) {
        # a function that shadows a shipped cmdlet trips PSAvoidOverwritingBuiltInCmdlets; the tool
        # wraps the platform-specific cmdlet instead (Clear-DnsCache), which is the correct seam.
        if ($fn.Name -in @('Clear-DnsClientCache','Get-Acl','Set-Acl','Get-Service','Stop-Service','Get-Content','Set-Content','Test-Path','Join-Path')) {
            $shadowed += ("{0}:{1}" -f $f.Name,$fn.Name)
        }
    }
}
Assert-Finding 'A-12' ($shadowed.Count -eq 0) ("no test shadows a shipped cmdlet{0}" -f $(if ($shadowed.Count) { ": $($shadowed -join ', ')" } else { '' }))
Assert-Finding 'A-12' ([bool](Get-Fn 'Clear-DnsCache'))                                               'the resolver flush is wrapped, so the hosts lifecycle is testable without shadowing'
$loopChild = Get-DocText 'Tests/Invoke-AuditLoop.ps1'
Assert-Finding 'A-12' ($loopChild -match "ErrorActionPreference = 'Continue'")                        'child stderr produces a FAIL stage instead of aborting the loop mid-run'
Assert-Finding 'A-12' ($loopChild -match 'Get-ChildFailureLine')                                      'a crashing child is diagnosable from one run'

# A-13: the coverage gate's per-finding attribution must survive the 5.1/6+ ConvertFrom-Json split.
# AST, not regex: a textual scan also matches the comment that EXPLAINS the bug (it did, on the
# first run of this pin). @(...) is an ArrayExpressionAst, so ask the parser instead.
$pipelineWrap = @()
foreach ($f in $psFiles) {
    $fa = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    $wrapped = @($fa.FindAll({ param($n)
        ($n -is [System.Management.Automation.Language.ArrayExpressionAst]) -and
        [bool]$n.Find({ param($m) ($m -is [System.Management.Automation.Language.CommandAst]) -and $m.GetCommandName() -eq 'ConvertFrom-Json' }, $true)
    }, $true))
    if ($wrapped.Count) { $pipelineWrap += $f.Name }
}
Assert-Finding 'A-13' ($pipelineWrap.Count -eq 0) ("no @() wrapped directly around a ConvertFrom-Json pipeline (5.1 emits an array as one object){0}" -f $(if ($pipelineWrap.Count) { ": $($pipelineWrap -join ', ')" } else { '' }))
Assert-Finding 'A-13' ($loopChild -match '\$parsed = Get-Content[^\r\n]*ConvertFrom-Json')                    'the report is assigned before being wrapped, which is flat on both runtimes'
Assert-Finding 'A-13' ($loopChild -notmatch 'Select-Object -ExpandProperty Id')                        'the orphan check cannot hard-error on an unexpected row shape'
Assert-Finding 'A-13' ($metaText -match 'fails only its own finding')                                 'a meta-test case pins per-finding attribution'
Assert-Finding 'A-13' ($metaText -match 'WantRegex')                                                  'that case asserts the shape of the coverage table, not just a phrase'
$ciText = Get-DocText '.github/workflows/ci.yml'
Assert-Finding 'A-13' (@([regex]::Matches($ciText,'if: always\(\)')).Count -ge 2)                     'both CI lanes run the meta-test even when the loop step fails'
if ($onWindows) { Assert-Finding 'A-10' $true 'running the Windows lane: ACL assertions are live' }
else            { Write-SkippedFinding 'A-10' 'ACL assertion liveness' 'non-Windows lane; CI Windows job covers it' }

Section 'VR-1  install-dir ownership must be asserted, not just the DACL'
# the trusted-owner set is exactly SYSTEM + Administrators (behavioural, cross-platform)
Assert-Finding 'VR-1' ((@($script:TrustedOwnerSids | Sort-Object) -join ',') -eq 'S-1-5-18,S-1-5-32-544') 'only SYSTEM and Administrators are trusted owners'
Assert-Finding 'VR-1' ([bool](Get-Fn 'Test-PathOwnerUntrusted'))                                       'an owner-trust predicate exists'
$hardenedAcl = Get-Fn 'New-HardenedAcl'
# AST, not raw text: find the .SetOwner(...) member invocation so a comment mentioning SetOwner
# cannot satisfy the pin (the A-13 lesson - a pin must not match the prose that explains it).
$setOwnerCall = @($hardenedAcl.FindAll({ param($n)
    ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and ("$($n.Member)" -eq 'SetOwner') }, $true))
Assert-Finding 'VR-1' ($setOwnerCall.Count -ge 1)                                                      'the hardened ACL sets an owner (so Set-Acl re-takes the directory)'
Assert-Finding 'VR-1' ($setOwnerCall.Count -ge 1 -and "$($setOwnerCall[0].Extent.Text)" -match 'S-1-5-32-544') 'ownership is vested in Administrators'
# every fail-closed gate consults the owner, not just the DACL (structural)
foreach ($fn in 'Protect-InstallDir','Protect-InstalledScript','Assert-InstallSafe','Read-StateFileSafely','Write-StateFileSafely','Get-StateForUndo','Invoke-Verify') {
    $f = Get-Fn $fn
    Assert-Finding 'VR-1' (Test-CommandCall $f 'Test-PathOwnerUntrusted') ("$fn checks the owner, not just the DACL")
}
# the DACL-only writability check must NOT be treated as sufficient on its own in the install gate
$fnProtectDir = Get-Fn 'Protect-InstallDir'
Assert-Finding 'VR-1' ((Get-CallAst $fnProtectDir 'Test-PathOwnerUntrusted').Count -ge 1 -and (Get-CallAst $fnProtectDir 'Test-PathUserWritable').Count -ge 1) 'Protect-InstallDir gates on owner AND DACL'
if ($onWindows) {
    # live proof: applying the hardened ACL to a real dir re-vests ownership in Administrators and
    # the owner check clears. This is the assertion that would have caught the pre-created-dir LPE.
    $vrTmp = Join-Path ([IO.Path]::GetTempPath()) ("gdidie-vr1-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $vrTmp -Force | Out-Null
    try {
        Set-Acl -LiteralPath $vrTmp -AclObject (New-HardenedAcl)
        $ownerSid = (Get-Acl -LiteralPath $vrTmp).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        Assert-Finding 'VR-1' ($ownerSid -eq 'S-1-5-32-544')            'live: hardened dir is owned by Administrators after Set-Acl'
        Assert-Finding 'VR-1' (-not (Test-PathOwnerUntrusted $vrTmp))   'live: the owner check clears on a properly hardened dir'
    } finally { Remove-Item -LiteralPath $vrTmp -Recurse -Force -ErrorAction SilentlyContinue }
} else {
    Write-SkippedFinding 'VR-1' 'live owner re-take on a real dir' 'Set-Acl/owner APIs are Windows-only; CI Windows job covers it'
}

Assert-Finding 'VR-1' ($AuditDoc -match 'H-2' -and $AuditDoc -match 'WRITE_DAC')                       'SECURITY-AUDIT.md documents the ownership finding and why a DACL is insufficient'

Section 'VR-2  the SYSTEM task must not resolve its interpreter via PATH'
# Inspect the New-ScheduledTaskAction call node, not the whole function text (which includes the
# comment that names the old bare form) - again the A-13 discipline.
$fnInstallP = Get-Fn 'Install-Persistence'
$taskAction = @(Get-CallAst $fnInstallP 'New-ScheduledTaskAction')
Assert-Finding 'VR-2' ($taskAction.Count -ge 1)                                                        'the persistence task action is created'
$actionText = if ($taskAction.Count) { "$($taskAction[0].Extent.Text)" } else { '' }
Assert-Finding 'VR-2' ($actionText -notmatch "-Execute\s+'powershell\.exe'")                          'the action no longer uses the bare powershell.exe name'
Assert-Finding 'VR-2' ($fnInstallP.Extent.Text -match 'System32\\WindowsPowerShell\\v1\.0\\powershell\.exe') 'the interpreter is the absolute System32 path'
Assert-Finding 'VR-2' ($AuditDoc -match 'P-1')                                                         'SECURITY-AUDIT.md documents the unqualified-interpreter finding'

Section 'I-2 / I-3 / I-4  accepted residuals must stay documented'
Assert-Finding 'I-2' ($Readme -match 'Honest limitations')                                            'README keeps the honest-limitations section'
Assert-Finding 'I-2' ($Readme -match 'DNS-over-HTTPS|DoH')                                            'README names the DoH bypass'
Assert-Finding 'I-2' ($AuditDoc -match 'I-2')                                                         'SECURITY-AUDIT.md still tracks the vendor ceiling'
Assert-Finding 'I-3' ($Readme -match 'new egress FQDN|does not detect the omission|list is an enumeration|allowlist') 'README states the blocklist is an enumeration that can miss a new FQDN'
Assert-Finding 'I-4' ($Readme -match 'never been verified|not verified|unverified')                    'README states the efficacy claim is unverified by execution'
Assert-Finding 'I-4' ($Readme -match 'packet capture|on the wire|observed absence')                    'README says what verification would actually require'

# --- report -----------------------------------------------------------------
$pass = @($script:Results | Where-Object Status -eq 'PASS').Count
$fail = @($script:Results | Where-Object Status -eq 'FAIL').Count
$skip = @($script:Results | Where-Object Status -eq 'SKIP').Count
Write-Host ""
Write-Host ("FINDINGS: {0} passed, {1} failed, {2} skipped across {3} finding id(s)" -f $pass,$fail,$skip,(@($script:Results | Select-Object -ExpandProperty Id -Unique).Count)) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($ReportPath) {
    $script:Results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    Write-Host "report: $ReportPath" -ForegroundColor DarkGray
}
exit ([int]($fail -gt 0))
