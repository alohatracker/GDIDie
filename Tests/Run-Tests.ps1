<#
    Run-Tests.ps1 - dependency-free unit tests for the pure helpers in Suppress-GDID.ps1.
    No admin, no registry, no network. Exit 0 = all pass, 1 = any fail. CI-friendly.
        powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\Run-Tests.ps1

    A-10: Windows-only sections (the ACL surface) are SKIPPED with a visible marker off Windows
    rather than hard-failing, so the same suite runs on the Linux lane. A skip is never a pass -
    Invoke-AuditLoop.ps1 counts skips separately and can fail the run on them with -FailOnSkip.
#>
$ErrorActionPreference = 'Stop'
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0
function Assert([bool]$cond,[string]$name) {
    if ($cond) { $script:Pass++; Write-Host "  [PASS] $name" -ForegroundColor Green }
    else       { $script:Fail++; Write-Host "  [FAIL] $name" -ForegroundColor Red }
}
function Skip([string]$name,[string]$why) {
    $script:Skip++; Write-Host "  [SKIP] $name ($why)" -ForegroundColor Yellow
}

# dot-source the tool: dispatcher is guarded, so only functions + vars load
. (Join-Path (Join-Path $PSScriptRoot '..') 'Suppress-GDID.ps1')
$onWindows = Test-IsWindowsHost

Write-Host "hosts block helpers" -ForegroundColor Cyan
$orig  = @('127.0.0.1 localhost','# a comment','10.0.0.1 nas')
$names = @('dds.microsoft.com','activity.windows.com')

$withBlock = Add-ManagedBlock $orig $names
Assert (($withBlock -contains $Sentinel0) -and ($withBlock -contains $Sentinel1)) 'block adds sentinels'
Assert (($withBlock -contains '0.0.0.0 dds.microsoft.com') -and ($withBlock -contains ':: dds.microsoft.com')) 'block adds dual-stack lines'
Assert (($withBlock | Where-Object { $_ -eq '0.0.0.0 activity.windows.com' }).Count -eq 1) 'one v4 line per name'

$stripped = Remove-ManagedBlock $withBlock
Assert (($stripped -join "`n") -eq ($orig -join "`n")) 'round-trip: add then strip == original'

# idempotency: applying twice then stripping once must equal original (no dupes left)
$twice = Add-ManagedBlock (Add-ManagedBlock $orig $names) $names
Assert ((($twice | Where-Object { $_ -eq $Sentinel0 }).Count) -eq 1) 're-add keeps a single block'
Assert (((Remove-ManagedBlock $twice) -join "`n") -eq ($orig -join "`n")) 'idempotent: strip after double-add == original'

Write-Host "managed block introspection (H-A)" -ForegroundColor Cyan
Assert (((@(Get-ManagedBlockFqdn $withBlock)) -join ',') -eq ($names -join ',')) 'reads back exactly the FQDNs in the block'
Assert ((@(Get-ManagedBlockFqdn $orig)).Count -eq 0) 'no block -> no names'
Assert ((@(Get-ManagedBlockFqdn @('a',$Sentinel0,'0.0.0.0 x'))).Count -eq 0) 'corrupt block -> no names (never a partial answer)'
Assert (((@(Get-ManagedBlockFqdn (Add-ManagedBlock $orig @('a.com')))) -join ',') -eq 'a.com') 'ignores the :: line, one name per FQDN'

Write-Host "state guard (the CRITICAL fix)" -ForegroundColor Cyan
# a. records a real original
$h = @{}; Update-SavedOriginal $h 'CDPSvc' 'Auto' 'Disabled' | Out-Null
Assert ($h['CDPSvc'] -eq 'Auto') 'records original when absent and not-disabled'
# b. first-write-wins: a later (post-disable) call must NOT clobber
Update-SavedOriginal $h 'CDPSvc' 'Disabled' 'Disabled' | Out-Null
Assert ($h['CDPSvc'] -eq 'Auto') 'first-write-wins: re-apply does not overwrite saved original'
# c. never record an already-disabled value as the original
$h2 = @{}; Update-SavedOriginal $h2 'DoSvc' 'Disabled' 'Disabled' | Out-Null
Assert (-not $h2.ContainsKey('DoSvc')) 'skip: already-disabled is never recorded as original'
# d. unrelated key untouched
$h3 = @{ Existing = 'Manual' }; Update-SavedOriginal $h3 'New' 'Auto' 'Disabled' | Out-Null
Assert (($h3['Existing'] -eq 'Manual') -and ($h3['New'] -eq 'Auto')) 'independent keys coexist'

Write-Host "member access across hashtable / JSON object" -ForegroundColor Cyan
Assert ((Get-PropValue @{ a = 1 } 'a') -eq 1)                              'hashtable hit'
Assert ($null -eq (Get-PropValue @{ a = 1 } 'b'))                          'hashtable miss -> $null'
Assert ((Get-PropValue ('{"a":2}' | ConvertFrom-Json) 'a') -eq 2)          'json object hit'
Assert ($null -eq (Get-PropValue ('{"a":2}' | ConvertFrom-Json) 'b'))      'json object miss -> $null'
Assert ($null -eq (Get-PropValue $null 'a'))                               'null object -> $null'

Write-Host "install-dir ACL hardening" -ForegroundColor Cyan
if (-not $onWindows) {
    Skip 'New-HardenedAcl assertions (6)' 'System.Security.AccessControl is Windows-only'
} else {
    $acl = New-HardenedAcl
    Assert ($acl.AreAccessRulesProtected) 'inheritance disabled (protected DACL)'
    $ar = $acl.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier])
    $users = $ar | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-545' }
    $usersRx = $users -and ($users.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Assert ([bool]$usersRx) 'Users have ReadAndExecute'
    $usersWrite = $ar | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-545' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) }
    Assert (-not $usersWrite) 'Users have NO write/create on the install dir'
    $sys = $ar | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-18' }
    Assert ($sys.FileSystemRights -eq 'FullControl') 'SYSTEM = FullControl'
    $adm = $ar | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-544' }
    Assert ($adm.FileSystemRights -eq 'FullControl') 'Administrators = FullControl'
    Assert (($ar | Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' }).Count -eq 0) 'no Everyone ACE'
}

Write-Host "persistence carries every scope choice" -ForegroundColor Cyan
Assert ((Get-PersistenceArgument $false $false) -match '-Apply -NoPersist')            'boot task always re-applies -Apply -NoPersist'
Assert ((Get-PersistenceArgument $false $false) -notmatch 'IncludeLoginLive')          'default: boot task does NOT block login.live.com'
Assert ((Get-PersistenceArgument $true  $false) -match '-IncludeLoginLive')            'opt-in: boot task carries -IncludeLoginLive so the block persists'
Assert ((Get-PersistenceArgument $false $false) -notmatch 'IncludeClassicTelemetry')   'default: boot task does NOT disable classic telemetry'
Assert ((Get-PersistenceArgument $false $true)  -match '-IncludeClassicTelemetry')     'opt-in: boot task carries -IncludeClassicTelemetry'
Assert ((Get-PersistenceArgument $true  $true)  -match '-IncludeLoginLive -IncludeClassicTelemetry') 'both switches survive together'
Assert ((Get-PersistenceArgument $false) -notmatch 'IncludeClassicTelemetry')          'one-arg call still works (back-compat)'

Write-Host "unbalanced sentinel safety (L-1)" -ForegroundColor Cyan
$broken = @('127.0.0.1 localhost', $Sentinel0, '0.0.0.0 evil.example', 'important.tail.line')  # begin, no end
$res = Remove-ManagedBlock $broken
Assert ((($res -join "`n")) -eq ($broken -join "`n")) 'begin-without-end leaves the file unchanged (no tail drop)'
$balanced = @('127.0.0.1 localhost', $Sentinel0, '0.0.0.0 x', $Sentinel1, 'keep.me')
Assert (((Remove-ManagedBlock $balanced) -join "`n") -eq "127.0.0.1 localhost`nkeep.me") 'balanced block still strips correctly'

Write-Host "sentinel corruption detection (F4)" -ForegroundColor Cyan
$B=$Sentinel0; $E=$Sentinel1
Assert (-not (Test-ManagedBlockCorrupt @('a',$B,'0.0.0.0 x',$E,'b'))) 'clean single balanced block: not corrupt'
Assert (-not (Test-ManagedBlockCorrupt @('a','b')))                   'no block: not corrupt'
Assert (Test-ManagedBlockCorrupt @('a',$B,'x'))                       'begin-without-end: corrupt'
Assert (Test-ManagedBlockCorrupt @('a',$E,'x'))                       'end-without-begin: corrupt'
Assert (Test-ManagedBlockCorrupt @($B,'x',$E,$B,'y',$E))             'two/duplicate blocks: corrupt'
Assert (Test-ManagedBlockCorrupt @($B,$B,'x',$E))                     'nested begin: corrupt'
Assert (Test-ManagedBlockCorrupt @($B,'x',$E,$E))                     'duplicate end: corrupt'
$threw=$false; try { Add-ManagedBlock @('a',$B,'x') @('z.com') | Out-Null } catch { $threw=$true }
Assert $threw 'Add-ManagedBlock throws on a corrupt existing block (never appends onto corruption)'
Assert (((Remove-ManagedBlock @('a',$B,'x')) -join "`n") -eq (@('a',$B,'x') -join "`n")) 'Remove leaves a corrupt file unchanged'

Write-Host "SID-based identity check (F1)" -ForegroundColor Cyan
if (-not $onWindows) {
    Skip 'Test-IdentityUntrusted assertions (3)' 'SecurityIdentifier translation is Windows-only'
} else {
    Assert (Test-IdentityUntrusted (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545'))) 'Users SID = untrusted'
    Assert (Test-IdentityUntrusted (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')))      'Everyone SID = untrusted'
    Assert (-not (Test-IdentityUntrusted (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')))) 'SYSTEM SID = trusted'
}

Write-Host "policy restore plan (F7)" -ForegroundColor Cyan
$pp = Get-PolicyRestorePlan @{ EnableCdp='ABSENT'; UploadUserActivities=0; PublishUserActivities=1 }
Assert ($pp['EnableCdp'].Action -eq 'remove')                                      'ABSENT -> remove'
Assert ($pp['UploadUserActivities'].Action -eq 'set' -and $pp['UploadUserActivities'].Value -eq 0) 'present-0 -> set 0'
Assert ($pp['PublishUserActivities'].Action -eq 'set' -and $pp['PublishUserActivities'].Value -eq 1) 'present-1 -> set 1'
Assert ((Get-PolicyRestorePlan @{ EnableCdp='2' })['EnableCdp'].Value -eq 2)       'legacy string value coerced to int'
Assert ((Get-PolicyRestorePlan $null).Count -eq 0)                                 'null policyPrev -> empty plan'
$jsonPrev = '{"EnableCdp":"ABSENT","UploadUserActivities":1}' | ConvertFrom-Json
$jp = Get-PolicyRestorePlan $jsonPrev
Assert ($jp['EnableCdp'].Action -eq 'remove' -and $jp['UploadUserActivities'].Value -eq 1) 'works on a ConvertFrom-Json state object'

Write-Host "service start-mode validation (A-1)" -ForegroundColor Cyan
Assert ((Get-SvcStartValue 'Disabled') -eq 4)   'Disabled -> 4'
Assert ((Get-SvcStartValue 'Manual')   -eq 3)   'Manual -> 3'
Assert ((Get-SvcStartValue 'Auto')     -eq 2)   'Auto (CIM StartMode spelling) -> 2'
Assert ((Get-SvcStartValue 'Automatic') -eq 2)  'Automatic -> 2'
Assert ((Get-SvcStartValue 'AutomaticDelayedStart') -eq 2) 'AutomaticDelayedStart -> 2'
foreach ($bad in @('','Enabled','4',$null,'Automatic ')) {
    $threw = $false; try { Get-SvcStartValue $bad | Out-Null } catch { $threw = $true }
    Assert $threw ("throws on unrecognised mode '{0}' instead of writing a bad Start value" -f $bad)
}

Write-Host "log pruning (L-A)" -ForegroundColor Cyan
$logs = 1..10 | ForEach-Object { "gdid-apply-2026081$_.log" }
Assert ((@(Select-PruneTarget $logs 10)).Count -eq 0)   'at the cap: nothing pruned'
Assert ((@(Select-PruneTarget $logs 3)).Count -eq 7)    'over the cap: prune the excess'
Assert ((@(Select-PruneTarget $logs 3))[0] -eq $logs[3]) 'prunes oldest-first (keeps the newest N)'
Assert ((@(Select-PruneTarget @() 5)).Count -eq 0)      'empty input is safe'
Assert ((@(Select-PruneTarget $logs 0)).Count -eq 10)   'keep=0 prunes everything'
Assert ((@(Select-PruneTarget $logs -1)).Count -eq 10)  'negative keep is clamped, not crashed'

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed, {2} skipped" -f $script:Pass,$script:Fail,$script:Skip) -ForegroundColor $(if($script:Fail){'Red'}else{'Green'})
exit ([int]($script:Fail -gt 0))
