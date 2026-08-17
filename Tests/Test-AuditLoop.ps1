<#
    Test-AuditLoop.ps1 - the meta-test: does the audit loop actually FAIL when it should?

    A gate nobody has seen fail is not a gate. This copies the repo to a temp directory, injects
    known regressions one at a time, and asserts the loop rejects each one - then asserts the
    unmodified copy still passes, so the failures are caused by the injected defect and not by the
    copy itself.

    Injected cases:
        1. clean copy                      -> loop passes                    (control)
        2. a Fixed finding with no pin      -> coverage gate FAILS            (unvalidated)
        3. an original defect reintroduced  -> the finding's assertion FAILS  (regression caught)
        4. an Accepted residual undocumented-> the documentary assertion FAILS
        5. an assertion citing an unknown id-> Audit-Findings THROWS          (orphan pin)

    Not part of Invoke-AuditLoop's own stages (it would recurse). CI runs it as its own step.

        powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\Test-AuditLoop.ps1
#>
$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function Assert([bool]$c,[string]$n){ if($c){$script:pass++;Write-Host "  [PASS] $n" -ForegroundColor Green}else{$script:fail++;Write-Host "  [FAIL] $n" -ForegroundColor Red} }

$Repo      = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$onWindows = if ($null -eq $IsWindows) { $true } else { [bool]$IsWindows }

function New-RepoCopy {
    $dst = Join-Path ([IO.Path]::GetTempPath()) ("gdidie-meta-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
    foreach ($item in (Get-ChildItem -LiteralPath $Repo -Force | Where-Object { $_.Name -ne '.git' })) {
        Copy-Item -LiteralPath $item.FullName -Destination $dst -Recurse -Force
    }
    $dst
}
function Invoke-LoopIn([string]$copy) {
    $exe = (Get-Process -Id $PID).Path
    $argList = @('-NoProfile')
    if ($onWindows) { $argList += @('-ExecutionPolicy','Bypass') }
    # -SkipAnalyzer: the injected defects are logic/doc regressions, and the analyzer module may not
    # be present. -Stage keeps the meta-test fast; parse still runs so a broken injection is obvious.
    $argList += @('-File',(Join-Path $copy 'Tests/Invoke-AuditLoop.ps1'),'-Stage','parse,findings,coverage')
    $out = & $exe @argList 2>&1
    @{ Code = $LASTEXITCODE; Text = (@($out) -join "`n") }
}
function Edit-File([string]$copy,[string]$rel,[string]$find,[string]$replace) {
    $p = Join-Path $copy $rel
    $s = Get-Content -LiteralPath $p -Raw
    if ($s -notmatch [regex]::Escape($find)) { throw "meta-test injection point not found in $rel : $find" }
    Set-Content -LiteralPath $p -Value ($s.Replace($find,$replace)) -Encoding UTF8
}

$cases = @(
    @{ Name    = 'control: an unmodified copy passes'
       Mutate  = { param($c) }
       WantExit= 0
       WantText= 'findings validated' }

    @{ Name    = 'a Fixed finding with no assertion is rejected as UNVALIDATED'
       Mutate  = { param($c) Edit-File $c 'Tests/findings.psd1' '        # --- deliberate residuals' @"
        @{  Id = 'A-11'; Severity = 'High'; Title = 'meta-test: unpinned finding'
            Disposition = 'Fixed'; Platform = 'Any'; Fix = 'claimed fixed, nothing pins it' }

        # --- deliberate residuals
"@ }
       WantExit= 1
       WantText= 'UNVALIDATED' }

    @{ Name    = 'reintroducing the H-A firewall-count defect trips its pin'
       Mutate  = { param($c) Edit-File $c 'Suppress-GDID.ps1' 'Check $ok ("firewall {0,-18}' 'Check (@($r).Count -ge 3) ("firewall {0,-18}' }
       WantExit= 1
       WantText= 'H-A' }

    @{ Name    = 'an Accepted residual that stops being documented is rejected'
       Mutate  = { param($c) Edit-File $c 'README.md' '## Honest limitations' '## Notes' }
       WantExit= 1
       WantText= 'I-2' }

    # A-13: per-finding attribution. One broken pin must fail exactly ITS finding and leave the
    # others passing. The PowerShell 5.1 ConvertFrom-Json array-collapse bug made every finding
    # report FAIL off a single failure anywhere, which this case detects and the cases above do not.
    @{ Name    = 'one failing assertion fails only its own finding, not every finding'
       Mutate  = { param($c) Edit-File $c 'Tests/Audit-Findings.ps1' "Assert-Finding 'M-A' (Test-CommandCall `$fnTest 'Start-AuditLog')" "Assert-Finding 'M-A' (`$false -and (Test-CommandCall `$fnTest 'Start-AuditLog'))" }
       WantExit= 1
       WantRegex= '(?s)M-A\s+Medium\s+Fixed\s+\d+\s+FAIL.*?H-A\s+High\s+Fixed\s+\d+\s+PASS|(?s)H-A\s+High\s+Fixed\s+\d+\s+PASS.*?M-A\s+Medium\s+Fixed\s+\d+\s+FAIL' }

    @{ Name    = 'an assertion citing an unregistered finding id is a hard error'
       Mutate  = { param($c) Edit-File $c 'Tests/Audit-Findings.ps1' "Assert-Finding 'H-A' ((@(Get-KillServiceList" "Assert-Finding 'H-Q' ((@(Get-KillServiceList" }
       WantExit= 1
       WantText= 'unregistered finding' }
)

Write-Host "=== meta-test: the audit loop's own failure modes ===" -ForegroundColor Cyan
foreach ($case in $cases) {
    $copy = New-RepoCopy
    try {
        & $case.Mutate $copy
        $r = Invoke-LoopIn $copy
        $exitOk = ($r.Code -eq $case.WantExit)
        # WantText is a literal substring; WantRegex is a pattern (used where the shape of the
        # coverage table itself is what must be asserted, not just a phrase).
        $expect = if ($case.WantRegex) { $case.WantRegex } else { [regex]::Escape($case.WantText) }
        $textOk = ($r.Text -match $expect)
        Assert ($exitOk -and $textOk) ("{0} (exit {1}, wanted {2})" -f $case.Name,$r.Code,$case.WantExit)
        if (-not ($exitOk -and $textOk)) {
            Write-Host ("    expected match /{0}/ in output; tail follows:" -f $expect) -ForegroundColor DarkGray
            @($r.Text -split "`n" | Select-Object -Last 12) | ForEach-Object { Write-Host "    | $_" -ForegroundColor DarkGray }
        }
    } finally { Remove-Item -LiteralPath $copy -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host ("META: {0} passed, {1} failed" -f $script:pass,$script:fail) -ForegroundColor $(if($script:fail){'Red'}else{'Green'})
exit ([int]($script:fail -gt 0))
