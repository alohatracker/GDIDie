<#
    Run-Tests.ps1 - dependency-free unit tests for the pure helpers in Suppress-GDID.ps1.
    No admin, no registry, no network. Exit 0 = all pass, 1 = any fail. CI-friendly.
        powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\Run-Tests.ps1
#>
$ErrorActionPreference = 'Stop'
$script:Pass = 0; $script:Fail = 0
function Assert([bool]$cond,[string]$name) {
    if ($cond) { $script:Pass++; Write-Host "  [PASS] $name" -ForegroundColor Green }
    else       { $script:Fail++; Write-Host "  [FAIL] $name" -ForegroundColor Red }
}

# dot-source the tool: dispatcher is guarded, so only functions + vars load
. (Join-Path $PSScriptRoot '..\Suppress-GDID.ps1')

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

Write-Host "install-dir ACL hardening" -ForegroundColor Cyan
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

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass,$script:Fail) -ForegroundColor $(if($script:Fail){'Red'}else{'Green'})
exit ([int]($script:Fail -gt 0))
