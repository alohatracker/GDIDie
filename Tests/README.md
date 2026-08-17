# The audit loop

One command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\Invoke-AuditLoop.ps1
```

```
1. parse      every .ps1 in the repo parses
2. analyzer   PSScriptAnalyzer against PSScriptAnalyzerSettings.psd1
3. unit       Run-Tests.ps1      - pure helpers, no admin/registry/network
4. smoke      Smoke-Test.ps1     - real filesystem objects (DACL, hosts file, log dir)
5. findings   Audit-Findings.ps1 - one or more regression pins per registered finding
6. coverage   the gate: no Fixed finding may lack a passing assertion
```

Exit `0` = everything validated, `1` = a stage failed or a finding is unvalidated.

And because a gate nobody has watched fail is not a gate, `Test-AuditLoop.ps1` is the meta-test: it
copies the repo to a temp directory, injects known regressions one at a time — an unpinned finding, a
reintroduced defect, an undocumented residual, an assertion citing an unknown id — and asserts the
loop rejects each one, with an unmodified copy as the control. It runs as its own CI step rather than
as a loop stage, since a loop that ran itself would recurse.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\Test-AuditLoop.ps1
```

## Why a registry, not just tests

A review hands you a list of findings. Fixing them is the easy half; the hard half is that six months
later nobody can tell which fixes are still in force, and a refactor can quietly undo one without a
single test going red. So the findings themselves are data:

| File | Role |
|---|---|
| `findings.psd1` | every finding — id, severity, title, disposition, the fix, the rationale |
| `Audit-Findings.ps1` | assertions, each tagged with a finding id |
| `Invoke-AuditLoop.ps1` | runs everything, then gates on the mapping between the two |

The gate enforces three things:

- A finding marked **`Fixed`** must have **at least one assertion that ran and passed.** No assertion
  → `UNVALIDATED` → the build fails. You cannot mark something fixed and walk away.
- A finding marked **`Accepted`** must have an assertion proving it is still **documented**, so a
  deliberate residual risk cannot silently stop being disclosed.
- An assertion citing an **unregistered id** is a hard error, so the registry cannot be trimmed while
  its assertions remain.

The loop therefore refuses to report all-clear for anything it did not actually check — which is the
exact defect finding **H-A** described in the tool itself (`-Verify` printing `ALL PASS` while
checking half of what `-Apply` changed). The harness is held to the standard it enforces.

## Skips are not passes

`System.Security.AccessControl`, `Get-CimInstance Win32_Service`, `Get-NetFirewallRule` and the
scheduled-task cmdlets only exist on Windows. Off Windows those assertions report **`SKIP`**, are
counted separately, and are never folded into the pass total. The CI Windows lane runs with
`-FailOnSkip`, so a platform-gated check silently ceasing to run on the one platform that *can* run
it is a build failure.

```powershell
.\Tests\Invoke-AuditLoop.ps1 -FailOnSkip          # Windows lane: a skip is a failure
.\Tests\Invoke-AuditLoop.ps1 -SkipAnalyzer        # Linux lane: pure + AST + drift subset
.\Tests\Invoke-AuditLoop.ps1 -Stage findings,coverage -ReportPath out.json
```

## Assertion styles, strongest first

1. **Behavioural** — call the pure helper, check the contract. `Get-ServiceRestorePlan` returning
   `refuse` with no state file is a fact about the code, tested directly, on any platform.
2. **Structural (AST)** — used where the behaviour needs live Windows services, the registry or the
   firewall. These check relationships that a regex cannot: that `Assert-InstallSafe` really is called
   *after* `Register-ScheduledTask`, that every `Test-Endpoint` call sits inside an
   `if ($IncludeReachability)` block, that the `exit 4` refusal precedes the first mutation.
3. **Documentary** — assert the doc text a finding required. Used for the `Accepted` residuals, where
   the deliverable *is* the disclosure.

Where a fix needs a Windows-only side effect, the seam is stubbed rather than skipped: `A-7` shadows
`Test-PathUserWritable` to test the state-file *classification* logic on both lanes, and the tool wraps
the Windows-only resolver flush as `Clear-DnsCache` so the real hosts-file lifecycle runs on Linux
too (wrapping beats shadowing the built-in cmdlet, which the analyzer rightly rejects).

## Adding a finding

1. Add a row to `findings.psd1` (`Id`, `Severity`, `Title`, `Disposition`, `Fix`, optional
   `Rationale`, `Platform`).
2. Fix it.
3. Add at least one assertion to `Audit-Findings.ps1` tagged with that id, written so it fails if the
   original defect returns — not merely restating the new code.
4. `.\Tests\Invoke-AuditLoop.ps1` — the coverage table should show your id with `Status = PASS`.

Step 3 is not optional: skip it and step 4 fails.

## What this harness cannot do

No stage observes real GDID egress. There is no lab VM, no packet capture, and no live Microsoft
endpoint in CI, so the tool's central efficacy claim stays **unverified by execution** — tracked as
`I-4`, documented in the README, and reflected in `-Test`'s verdict wording, which claims only
hostname reachability blocking. Nor can the loop tell you the blocklist is *complete* (`I-3`); it can
only keep the three shipped copies of the list in agreement. A network-forensics seat with a VM is
the missing piece, and the honest move is to say so rather than let a green run imply otherwise.
