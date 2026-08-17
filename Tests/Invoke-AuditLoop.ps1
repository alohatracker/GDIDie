<#
    Invoke-AuditLoop.ps1 - the single entry point for the test/audit/fix/validate loop.

        powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\Invoke-AuditLoop.ps1

    Stages, in order (each one is skipped-not-faked when its platform prerequisites are missing):

        1. parse     every .ps1 in the repo parses
        2. analyzer  PSScriptAnalyzer against PSScriptAnalyzerSettings.psd1
        3. unit      Tests/Run-Tests.ps1      - pure helpers
        4. smoke     Tests/Smoke-Test.ps1     - real filesystem objects
        5. findings  Tests/Audit-Findings.ps1 - one or more assertions per registered finding
        6. coverage  the gate that closes the loop (below)

    The coverage gate is the whole point of the harness. It reads Tests/findings.psd1 and the
    findings report, and fails the run when:

        - a finding marked Fixed has NO assertion that ran and passed  ("unvalidated")
        - a finding marked Accepted has no assertion proving it is still documented
        - a finding marked Refuted carries no rationale
        - an assertion cites a finding Id that is not registered (Audit-Findings throws on this)

    So the fix for a review finding is not "done" until an assertion pins it, and a finding cannot
    be quietly deleted from the registry without its assertions failing. That is the loop: audit ->
    fix -> pin -> re-validate, with the harness refusing to report all-clear on anything it did not
    actually check. Re-run it after every change; add a row to findings.psd1 for every new finding.

    Exit 0 = everything validated. Exit 1 = a stage failed or a finding is unvalidated.
#>
[CmdletBinding()]
param(
    [switch]$FailOnSkip,        # treat any SKIP (platform-gated assertion, missing analyzer) as a failure
    [switch]$SkipAnalyzer,      # do not attempt PSScriptAnalyzer (it needs the PSGallery module)
    [string]$ReportPath,        # write the full machine-readable result here
    [string[]]$Stage = @('all') # subset of: all parse analyzer unit smoke findings coverage
)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# Split on commas as well as array elements: powershell.exe -File passes '-Stage a,b' as ONE string,
# so a ValidateSet on the array would reject the form the docs and CI use.
$Known = @('all','parse','analyzer','unit','smoke','findings','coverage')
$Stage = @($Stage | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$unknown = @($Stage | Where-Object { $Known -notcontains $_ })
if ($unknown.Count) { throw "Unknown -Stage value(s): $($unknown -join ', '). Valid: $($Known -join ', ')." }
$want = { param($s) ($Stage -contains 'all') -or ($Stage -contains $s) }
$onWindows = if ($null -eq $IsWindows) { $true } else { [bool]$IsWindows }

$Stages = New-Object System.Collections.Generic.List[object]
function Add-Stage([string]$Name,[string]$Status,[string]$Detail) {
    $Stages.Add([pscustomobject]@{ Stage=$Name; Status=$Status; Detail=$Detail })
    $c = switch ($Status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'Yellow' } default { 'Gray' } }
    Write-Host ("[{0,-4}] {1,-9} {2}" -f $Status,$Name,$Detail) -ForegroundColor $c
}
function Get-HostExe {
    $p = (Get-Process -Id $PID).Path
    if ($p) { return $p }
    Join-Path $PSHOME $(if ($onWindows) { 'powershell.exe' } else { 'pwsh' })
}
function Invoke-Child([string]$scriptPath,[string[]]$extra) {
    # Run each suite in a fresh process: clean scope, honest exit code, no cross-stage pollution.
    $exe  = Get-HostExe
    $argList = @('-NoProfile')
    if ($onWindows) { $argList += @('-ExecutionPolicy','Bypass') }
    $argList += @('-File',$scriptPath)
    if ($extra) { $argList += $extra }
    # A child that writes to stderr must produce a FAIL stage, not abort the whole loop. Under
    # $ErrorActionPreference='Stop', '2>&1' from a native command surfaces as a TERMINATING
    # NativeCommandError in Windows PowerShell 5.1, which would kill the run before the remaining
    # stages and the coverage table ever printed.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $exe @argList 2>&1 } finally { $ErrorActionPreference = $prev }
    @{ Code = $LASTEXITCODE; Output = @($out) }
}
function Get-ChildFailureLine($output) {
    # Prefer the suite's own [FAIL] lines; fall back to raw stderr so a crashing child is still
    # diagnosable from one run instead of needing a second, more verbose one.
    $lines = @($output | ForEach-Object { "$_" })
    $marked = @($lines | Where-Object { $_ -match '\[FAIL\]' })
    if ($marked.Count) { return $marked }
    @($lines | Where-Object { $_ -match '\S' } | Select-Object -Last 12)
}
function Write-ChildOutput($lines) { foreach ($l in $lines) { Write-Host ("    | {0}" -f $l) } }

Write-Host "=== GDIDie audit loop ===" -ForegroundColor Cyan
Write-Host ("repo: {0}   host: PowerShell {1} on {2}" -f $Repo,$PSVersionTable.PSVersion,$(if ($onWindows) { 'Windows' } else { 'non-Windows (Windows-only checks will SKIP)' })) -ForegroundColor DarkGray
Write-Host ""

# --- 1. parse ---------------------------------------------------------------
if (& $want 'parse') {
    $bad = @()
    foreach ($f in (Get-ChildItem -LiteralPath $Repo -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notmatch '\.git' })) {
        $errs = $null
        [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs) | Out-Null
        if ($errs) { $bad += ("{0}:{1} {2}" -f $f.Name,$errs[0].Extent.StartLineNumber,$errs[0].Message) }
    }
    $count = @(Get-ChildItem -LiteralPath $Repo -Recurse -Filter '*.ps1' -File).Count
    # V-5: a malformed workflow is DISCARDED by GitHub before any job is created - zero jobs, no
    # check run, which is indistinguishable from "this workflow did not apply" and reads as success.
    # A validation step that silently does not run is the H-A defect wearing a different hat, so lint
    # the workflow files here too. Windows PowerShell 5.1 ships no YAML parser, so this targets the
    # specific class that actually bit: an unquoted scalar containing ': ', which YAML parses as a
    # nested mapping and rejects.
    $wfDir = Join-Path $Repo '.github/workflows'
    $wfCount = 0
    foreach ($wf in @(Get-ChildItem -LiteralPath $wfDir -Filter '*.yml' -File -ErrorAction SilentlyContinue)) {
        $wfCount++
        $lines = @(Get-Content -LiteralPath $wf.FullName)
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*-?\s*(name|description):\s*(.+)$') {
                $val = $Matches[2].Trim()
                if ($val -notmatch '^[''"]' -and $val -match ':\s') {
                    $bad += ("{0}:{1} unquoted value contains ': ' so YAML will reject the whole file -> {2}" -f $wf.Name,($i+1),$val)
                }
            }
        }
        # V-6: capturing an in-process call with 2>&1 misses Write-Host (information stream in 5.1),
        # so any later -match on the captured text is vacuous and can never fail.
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '\.\\Suppress-GDID\.ps1[^|]*2>&1\s*\|') {
                $bad += ("{0}:{1} captures tool output with 2>&1; use *>&1 or the match is vacuous (Write-Host is the information stream)" -f $wf.Name,($i+1))
            }
        }
        $text = ($lines -join "`n")
        if ($text -notmatch '(?m)^jobs:') { $bad += ("{0} has no jobs: block" -f $wf.Name) }
        if ($text -notmatch '(?m)^on:')   { $bad += ("{0} has no on: trigger block" -f $wf.Name) }
    }
    if ($bad.Count) { Add-Stage 'parse' 'FAIL' ($bad -join '; ') }
    else            { Add-Stage 'parse' 'PASS' ("$count script(s) parse clean, $wfCount workflow(s) lint clean") }
}

# --- 2. static analysis -----------------------------------------------------
if (& $want 'analyzer') {
    if ($SkipAnalyzer) {
        Add-Stage 'analyzer' 'SKIP' '-SkipAnalyzer was passed'
    } elseif (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Add-Stage 'analyzer' 'SKIP' 'PSScriptAnalyzer not installed (CI installs a pinned version)'
    } else {
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        $findings = @(Invoke-ScriptAnalyzer -Path $Repo -Recurse -Settings (Join-Path $Repo 'PSScriptAnalyzerSettings.psd1'))
        if ($findings.Count) {
            $findings | Format-Table -AutoSize | Out-String | Write-Host
            Add-Stage 'analyzer' 'FAIL' ("{0} finding(s)" -f $findings.Count)
        } else {
            Add-Stage 'analyzer' 'PASS' '0 findings'
        }
    }
}

# --- 3. unit ----------------------------------------------------------------
if (& $want 'unit') {
    $r = Invoke-Child (Join-Path $PSScriptRoot 'Run-Tests.ps1')
    $summary = @($r.Output | Where-Object { $_ -match '^RESULT:' }) -join ' '
    if (-not $summary) { $summary = "child exited $($r.Code) without a RESULT line" }
    if ($r.Code -ne 0) { Write-ChildOutput (Get-ChildFailureLine $r.Output); Add-Stage 'unit' 'FAIL' $summary }
    else               { Add-Stage 'unit' 'PASS' $summary }
    foreach ($s in @($r.Output | Where-Object { $_ -match '\[SKIP\]' })) { Add-Stage 'unit' 'SKIP' ("$s".Trim()) }
}

# --- 4. smoke ---------------------------------------------------------------
if (& $want 'smoke') {
    $r = Invoke-Child (Join-Path $PSScriptRoot 'Smoke-Test.ps1')
    $summary = @($r.Output | Where-Object { $_ -match '^SMOKE:' }) -join ' '
    if (-not $summary) { $summary = "child exited $($r.Code) without a SMOKE line" }
    if ($r.Code -ne 0) { Write-ChildOutput (Get-ChildFailureLine $r.Output); Add-Stage 'smoke' 'FAIL' $summary }
    else               { Add-Stage 'smoke' 'PASS' $summary }
    foreach ($s in @($r.Output | Where-Object { $_ -match '\[SKIP\]' })) { Add-Stage 'smoke' 'SKIP' ("$s".Trim()) }
}

# --- 5. findings ------------------------------------------------------------
$findingRows = @()
if (& $want 'findings') {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("gdidie-findings-" + [Guid]::NewGuid().ToString('N').Substring(0,8) + '.json')
    try {
        $r = Invoke-Child (Join-Path $PSScriptRoot 'Audit-Findings.ps1') @('-ReportPath',$tmp)
        $summary = @($r.Output | Where-Object { $_ -match '^FINDINGS:' }) -join ' '
        if (-not $summary) { $summary = "child exited $($r.Code) without a FINDINGS line" }
        if ($r.Code -ne 0) {
            Write-ChildOutput (Get-ChildFailureLine $r.Output)
            Add-Stage 'findings' 'FAIL' $summary
        } else {
            Add-Stage 'findings' 'PASS' $summary
        }
        # A-13: Windows PowerShell 5.1 emits a parsed JSON array as ONE pipeline object; 6+
        # enumerates it. So `@(... | ConvertFrom-Json)` collapses 155 assertion rows into a single
        # nested row on 5.1, which destroys per-finding attribution: every finding then reports one
        # assertion, and a single failure anywhere marks them all FAIL. Assign first, THEN wrap -
        # correct under both, because @() on a variable that already holds an array stays flat.
        if (Test-Path -LiteralPath $tmp) {
            $parsed = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
            $findingRows = @($parsed)
        }
        else { Add-Stage 'findings' 'FAIL' 'no findings report was produced'; Write-ChildOutput @($r.Output | Select-Object -Last 15) }
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

# --- 6. coverage gate -------------------------------------------------------
if (& $want 'coverage') {
    $registry = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'findings.psd1')
    Write-Host ""
    Write-Host "--- finding coverage ---" -ForegroundColor Cyan
    $rows = @()
    foreach ($f in $registry.Findings) {
        $mine   = @($findingRows | Where-Object { $_.Id -eq $f.Id })
        $passed = @($mine | Where-Object { $_.Status -eq 'PASS' }).Count
        $failed = @($mine | Where-Object { $_.Status -eq 'FAIL' }).Count
        $skipped= @($mine | Where-Object { $_.Status -eq 'SKIP' }).Count
        $status =
            if ($failed -gt 0)                          { 'FAIL' }
            elseif ($f.Disposition -eq 'Refuted')       { if ("$($f.Rationale)".Trim()) { 'PASS' } else { 'FAIL' } }
            elseif ($passed -gt 0)                      { 'PASS' }
            elseif ($skipped -gt 0)                     { 'SKIP' }
            else                                        { 'FAIL' }
        $note =
            if ($status -eq 'FAIL' -and $mine.Count -eq 0) { 'UNVALIDATED: no assertion pins this finding' }
            elseif ($status -eq 'FAIL' -and $failed -gt 0) { "$failed assertion(s) failing" }
            elseif ($status -eq 'SKIP')                    { 'only platform-skipped assertions ran' }
            else                                           { "$passed assertion(s) pass" }
        $rows += [pscustomobject]@{
            Id = $f.Id; Sev = $f.Severity; Disposition = $f.Disposition
            Asserts = $mine.Count; Status = $status; Note = $note; Title = $f.Title
        }
    }
    $rows | Format-Table -Property Id,Sev,Disposition,Asserts,Status,Note -AutoSize | Out-String -Width 200 | Write-Host
    $covFail = @($rows | Where-Object Status -eq 'FAIL')
    $covSkip = @($rows | Where-Object Status -eq 'SKIP')
    # Orphan check: an assertion for an Id nobody registered. Audit-Findings throws on this, so
    # reaching here means the registry was edited after the fact.
    # ForEach-Object rather than Select-Object -ExpandProperty: the latter throws outright if a row
    # is not shaped as expected, turning a reportable gate failure into a crashed run.
    $orphans = @($findingRows | Where-Object { $_.Id -and ($registry.Findings.Id -notcontains $_.Id) } |
                 ForEach-Object { $_.Id } | Sort-Object -Unique)
    if ($orphans.Count) { Add-Stage 'coverage' 'FAIL' ("assertions cite unregistered finding(s): {0}" -f ($orphans -join ', ')) }
    if ($covFail.Count) {
        foreach ($r in $covFail) { Write-Host ("    ! {0}: {1} - {2}" -f $r.Id,$r.Note,$r.Title) -ForegroundColor Red }
        Add-Stage 'coverage' 'FAIL' ("{0}/{1} findings not validated" -f $covFail.Count,$rows.Count)
    } else {
        Add-Stage 'coverage' 'PASS' ("{0}/{1} findings validated ({2} platform-skipped)" -f ($rows.Count - $covSkip.Count),$rows.Count,$covSkip.Count)
    }
    foreach ($r in $covSkip) { Add-Stage 'coverage' 'SKIP' ("{0} ({1})" -f $r.Id,$r.Note) }
    $script:CoverageRows = $rows
}

# --- summary ----------------------------------------------------------------
$fail = @($Stages | Where-Object Status -eq 'FAIL').Count
$skip = @($Stages | Where-Object Status -eq 'SKIP').Count
$pass = @($Stages | Where-Object Status -eq 'PASS').Count
Write-Host ""
Write-Host ("=== AUDIT LOOP: {0} passed, {1} failed, {2} skipped ===" -f $pass,$fail,$skip) -ForegroundColor $(if ($fail) { 'Red' } elseif ($skip -and $FailOnSkip) { 'Red' } else { 'Green' })
if ($skip) { Write-Host "    (a SKIP is never a PASS - run the Windows lane, or pass -FailOnSkip to gate on them)" -ForegroundColor DarkGray }
if ($ReportPath) {
    @{ Generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
       Host      = "PowerShell $($PSVersionTable.PSVersion) on $(if ($onWindows) { 'Windows' } else { 'non-Windows' })"
       Stages    = $Stages
       Findings  = $script:CoverageRows
       Assertions= $findingRows } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    Write-Host "report: $ReportPath" -ForegroundColor DarkGray
}
if ($fail -gt 0) { exit 1 }
if ($FailOnSkip -and $skip -gt 0) { Write-Host "-FailOnSkip: failing because $skip check(s) were skipped." -ForegroundColor Red; exit 1 }
exit 0
