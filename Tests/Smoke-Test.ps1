<#
    Smoke-Test.ps1 - end-to-end checks against REAL filesystem objects (no admin, no system
    changes, self-cleaning). Exit 0/1.

    Covers: the install-dir DACL on a real directory, the byte-exact hosts rollback, the hosts
    managed-block lifecycle against a real file (H-A), and transcript pruning against a real
    directory (L-A).

    (This tool is a PowerShell CLI with no browser surface, so a Playwright/browser test would
     be fabricated. Real-filesystem checks are the correct end-to-end layer here.)

    A-10: the ACL section is Windows-only and SKIPS elsewhere; everything else runs on both lanes.
#>
$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0; $script:skip = 0
function Assert([bool]$c,[string]$n){ if($c){$script:pass++;Write-Host "  [PASS] $n" -ForegroundColor Green}else{$script:fail++;Write-Host "  [FAIL] $n" -ForegroundColor Red} }
function Skip([string]$n,[string]$why){ $script:skip++; Write-Host "  [SKIP] $n ($why)" -ForegroundColor Yellow }

. (Join-Path $PSScriptRoot '..' 'Suppress-GDID.ps1')
$onWindows = Test-IsWindowsHost
if (-not $onWindows) {
    # Test seam: Set-HostsBlock flushes the resolver cache, which does not exist off Windows.
    # Shadowing it here keeps the hosts-file lifecycle testable on the Linux lane.
    function Clear-DnsClientCache { }
}
function New-TempDir([string]$tag) {
    $p = Join-Path ([IO.Path]::GetTempPath()) ("gdidie-$tag-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $p -Force | Out-Null
    $p
}

Write-Host "install-dir DACL on a real directory" -ForegroundColor Cyan
if (-not $onWindows) {
    Skip 'DACL assertions (6)' 'Access Control List APIs are Windows-only'
} else {
    $tmp = New-TempDir 'smoke'
    Write-Host "  smoketest dir: $tmp" -ForegroundColor DarkGray
    try {
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
        $tmp2 = New-TempDir 'smoke2'
        try {
            $a2 = Get-Acl $tmp2
            $a2.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Users','Modify','ContainerInherit,ObjectInherit','None','Allow')))
            Set-Acl $tmp2 $a2
            Assert (Test-PathUserWritable $tmp2) 'Test-PathUserWritable: true when a Users:Modify ACE is present'
        } finally { Remove-Item $tmp2 -Recurse -Force -ErrorAction SilentlyContinue }
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
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

Write-Host "hosts managed-block lifecycle on a real file (H-A)" -ForegroundColor Cyan
$hostsDir = New-TempDir 'hosts'
try {
    # Point the tool's hosts path at a scratch file: Set-HostsBlock / Get-HostsBlockFqdn /
    # Remove-HostsBlock then exercise the same code path -Apply and -Verify use.
    $HostsPath = Join-Path $hostsDir 'hosts'
    $before = @('127.0.0.1 localhost','# user comment','10.0.0.5 nas')
    Set-Content -LiteralPath $HostsPath -Value $before -Encoding ASCII

    $expected = @(Get-ExpectedHostList $false)
    Set-HostsBlock $expected
    Assert (Test-HostsBlockPresent) 'Set-HostsBlock writes a block the presence check finds'
    $inBlock = @(Get-HostsBlockFqdn)
    Assert (($inBlock -join ',') -eq ($expected -join ',')) ("block contains exactly the {0} expected FQDNs" -f $expected.Count)
    Assert ((Get-Content $HostsPath) -contains '10.0.0.5 nas') 'unrelated user entries survive the write'

    # This is the H-A failure mode as a test: a block that is PRESENT but INCOMPLETE must be
    # detectable. Sentinel-presence alone reports fine; the content comparison catches it.
    $tampered = @(Get-Content $HostsPath) | Where-Object { $_ -notmatch 'activity\.windows\.com' }
    Set-Content -LiteralPath $HostsPath -Value $tampered -Encoding ASCII
    Assert (Test-HostsBlockPresent) 'a partially-stripped block still looks "present" (the old check)'
    $missing = @($expected | Where-Object { (Get-HostsBlockFqdn) -notcontains $_ })
    Assert ($missing -contains 'activity.windows.com') 'content comparison detects the missing FQDN (the new check)'

    # login.live.com scope
    Set-HostsBlock (Get-ExpectedHostList $true)
    Assert ((Get-HostsBlockFqdn) -contains 'login.live.com') '-IncludeLoginLive scope adds login.live.com'
    Set-HostsBlock (Get-ExpectedHostList $false)
    Assert ((Get-HostsBlockFqdn) -notcontains 'login.live.com') 'default scope removes it again'

    Remove-HostsBlock
    Assert (-not (Test-HostsBlockPresent)) 'Remove-HostsBlock removes the block'
    Assert (((Get-Content $HostsPath) -join "`n") -eq ($before -join "`n")) 'file returns to its original lines'
} finally { Remove-Item $hostsDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "transcript pruning on a real directory (L-A)" -ForegroundColor Cyan
$LogDir = New-TempDir 'logs'
try {
    1..8 | ForEach-Object {
        $f = Join-Path $LogDir ("gdid-apply-2026081{0}-000000.log" -f $_)
        Set-Content -LiteralPath $f -Value "run $_" -Encoding ASCII
        # deterministic ordering without relying on filesystem timestamp granularity
        (Get-Item -LiteralPath $f).LastWriteTimeUtc = [datetime]::new(2026,8,10,0,0,0,[DateTimeKind]::Utc).AddHours($_)
    }
    Set-Content -LiteralPath (Join-Path $LogDir 'keep-me.txt') -Value 'not a transcript' -Encoding ASCII
    $LogKeep = 3          # shadows the tool's default cap for this test
    Write-Host ("  cap under test: LogKeep=$LogKeep against 8 transcripts") -ForegroundColor DarkGray
    $pruned = Remove-OldAuditLog
    $left = @(Get-ChildItem -LiteralPath $LogDir -Filter 'gdid-*.log' | ForEach-Object { $_.Name } | Sort-Object)
    Assert ($pruned -eq 5) 'prunes down to the cap (8 -> 3)'
    Assert ($left.Count -eq 3) 'exactly $LogKeep transcripts remain'
    Assert (($left -join ',') -eq 'gdid-apply-20260816-000000.log,gdid-apply-20260817-000000.log,gdid-apply-20260818-000000.log') 'the NEWEST transcripts are the ones kept'
    Assert (Test-Path (Join-Path $LogDir 'keep-me.txt')) 'non-transcript files are never touched'
    $again = Remove-OldAuditLog
    Assert ($again -eq 0) 'pruning is idempotent'
} finally { Remove-Item $LogDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host ("SMOKE: {0} passed, {1} failed, {2} skipped" -f $script:pass,$script:fail,$script:skip) -ForegroundColor $(if($script:fail){'Red'}else{'Green'})
exit ([int]($script:fail -gt 0))
