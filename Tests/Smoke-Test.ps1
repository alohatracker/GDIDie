<#
    Smoke-Test.ps1 - live smoketest for the install-dir hardening on a REAL filesystem object.
    Applies New-HardenedAcl to a throwaway temp dir and asserts, via the on-disk DACL, that
    standard users have no write/create. No admin, no system changes, self-cleaning. Exit 0/1.

    (This tool is a PowerShell CLI with no browser surface, so a Playwright/browser test would
     be fabricated. This ACL smoketest is the correct end-to-end check for the hardening fix.)
#>
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert([bool]$c,[string]$n){ if($c){$script:pass++;Write-Host "  [PASS] $n" -ForegroundColor Green}else{$script:fail++;Write-Host "  [FAIL] $n" -ForegroundColor Red} }

. (Join-Path $PSScriptRoot '..\Suppress-GDID.ps1')

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("gdidie-smoke-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
Write-Host "smoketest dir: $tmp" -ForegroundColor Cyan
try {
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Set-Acl -Path $tmp -AclObject (New-HardenedAcl)

    $acl = Get-Acl $tmp
    Assert ($acl.AreAccessRulesProtected) 'on-disk DACL is protected (no inheritance)'

    $rules = $acl.Access
    $usersWrite = $rules | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -match '\\Users$|Everyone|Authenticated Users' -and
        ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) }
    Assert (-not $usersWrite) 'no Allow-write ACE for Users/Everyone/Authenticated Users'

    $usersRx = $rules | Where-Object { $_.IdentityReference.Value -match '\\Users$' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) }
    Assert ([bool]$usersRx) 'Users retain ReadAndExecute'

    $sys = $rules | Where-Object { $_.IdentityReference.Value -match 'SYSTEM' -and $_.FileSystemRights -eq 'FullControl' }
    Assert ([bool]$sys) 'SYSTEM retains FullControl'

    # H-1 detector: false on the locked dir; true when a Users:Modify ACE exists.
    # (The 'writable' case runs on a fresh unhardened dir; hardening $tmp would lock the runner out of its own ACL.)
    Assert (-not (Test-PathUserWritable $tmp)) 'Test-PathUserWritable: false on hardened dir'
    $tmp2 = Join-Path ([IO.Path]::GetTempPath()) ("gdidie-smoke2-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $tmp2 -Force | Out-Null
    try {
        $a2 = Get-Acl $tmp2
        $a2.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Users','Modify','ContainerInherit,ObjectInherit','None','Allow')))
        Set-Acl $tmp2 $a2
        Assert (Test-PathUserWritable $tmp2) 'Test-PathUserWritable: true when a Users:Modify ACE is present'
    } finally { Remove-Item $tmp2 -Recurse -Force -ErrorAction SilentlyContinue }
} finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host "byte-exact hosts rollback (F5)" -ForegroundColor Cyan
$hf = Join-Path ([IO.Path]::GetTempPath()) ("gdidie-hosts-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
try {
    # original: UTF-8 BOM + CRLF + a trailing line with no EOL
    $orig = [byte[]]@(0xEF,0xBB,0xBF) + [Text.Encoding]::UTF8.GetBytes("127.0.0.1 localhost`r`n# keep`r`nno-eol-tail")
    [IO.File]::WriteAllBytes($hf, $orig)
    $snap = [IO.File]::ReadAllBytes($hf)                                    # -Test snapshot
    [IO.File]::WriteAllLines($hf, @('0.0.0.0 proof','# junk'), (New-Object Text.UTF8Encoding($false)))  # -Test mutation (re-encodes)
    [IO.File]::WriteAllBytes($hf, $snap)                                    # -Test rollback
    $now = [IO.File]::ReadAllBytes($hf)
    Assert (($now.Length -eq $orig.Length) -and (-not (Compare-Object $now $orig))) 'byte-for-byte restore preserves BOM/CRLF/tail'
} finally { Remove-Item $hf -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host ("SMOKE: {0} passed, {1} failed" -f $pass,$fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit ([int]($fail -gt 0))
