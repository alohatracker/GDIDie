@{
    # ---------------------------------------------------------------------------------------------
    # Findings registry - the spine of the test/audit/fix/validate loop.
    #
    # Every review finding (internal or external) gets a row here. Tests/Audit-Findings.ps1 asserts
    # the FIXED behaviour and tags each assertion with an Id from this file.
    # Tests/Invoke-AuditLoop.ps1 then enforces the invariant that closes the loop:
    #
    #     no finding may be marked Fixed without at least one assertion that actually RAN and PASSED
    #     on this platform, and no assertion may reference an Id that is not registered here.
    #
    # That is the whole point: a finding cannot be silently dropped, and the harness cannot report
    # "all clear" for something it never checked - the exact failure mode of H-A itself.
    #
    # Disposition:
    #   Fixed      - code/doc changed; MUST have >=1 passing assertion.
    #   Accepted   - deliberate residual risk; MUST have an assertion proving it is DOCUMENTED.
    #   Refuted    - the finding does not hold against this code; Rationale must say why.
    # Platform: Any | Windows   (Windows rows are reported SKIPPED, never PASSED, off-Windows)
    # ---------------------------------------------------------------------------------------------
    Version  = '1.0'
    Source   = 'Expert panel review of Suppress-GDID.ps1 v1.4.0 (external, static) + v1.5.0 self-audit'
    Findings = @(
        # --- external panel review: HIGH ---------------------------------------------------------
        @{  Id          = 'H-A'
            Severity    = 'High'
            Title       = '-Verify reported ALL PASS while checking only half of what -Apply changed'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Verify is driven from the same single-source data as Apply: Get-KillServiceList, Get-ExpectedHostList, $PolicyNames, and the firewall service list. Firewall rules are checked for Enabled/Action/Direction/Service filter, not counted. Hosts block contents are compared FQDN-by-FQDN, not just sentinel-presence.'
            Rationale   = 'A false PASS is the single most dangerous output a privacy tool can produce.'
        }
        @{  Id          = 'H-B'
            Severity    = 'High'
            Title       = 'Efficacy unverified; README confidence outran the tool honest ceiling'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = '-Apply prints the anonymity ceiling at completion; -Verify prints it on ALL PASS; -Test verdict states it proves hostname reachability blocking only, never GDID suppression.'
            Rationale   = 'The ceiling was already documented at the bottom of the README; the fix promotes it into the runtime voice where the at-risk user actually reads it.'
        }
        @{  Id          = 'H-C'
            Severity    = 'High'
            Title       = '-Undo restore defaults were hardcoded guesses when state.json was absent'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Get-ServiceRestorePlan never guesses: a recorded original is restored exactly (raw Start + DelayedAutostart), a service with no recorded original is left alone, and a missing/untrusted state file refuses the whole undo (exit 4, nothing changed) unless -Force opts into documented Microsoft defaults.'
            Rationale   = 'Reversibility is the central promise; a lossy undo undercuts it.'
        }

        # --- external panel review: MEDIUM -------------------------------------------------------
        @{  Id          = 'M-A'
            Severity    = 'Medium'
            Title       = '-Test mutated system state with no audit log'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Invoke-Test hardens the install dir, then wraps its work in Start-AuditLog test / Stop-Transcript like -Apply and -Undo.'
        }
        @{  Id          = 'M-B'
            Severity    = 'Medium'
            Title       = 'TOCTOU window between the writability check and SYSTEM-task registration went unmentioned in SECURITY-AUDIT.md'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'SECURITY-AUDIT.md documents the window (T-1) and its mitigations; Install-Persistence re-runs Assert-InstallSafe after Register-ScheduledTask and verifies the registered arguments, unregistering the task if either check fails.'
        }
        @{  Id          = 'M-C'
            Severity    = 'Medium'
            Title       = 'DiagTrack / dmwappushservice widened the blast radius beyond the stated GDID threat model'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Classic telemetry moved behind an opt-in -IncludeClassicTelemetry switch (mirroring -IncludeLoginLive), the choice is recorded in state.json scope, carried by the boot task, and reported by -Verify.'
            Rationale   = 'Panel disagreed (privacy-maximalism vs scope-discipline). Resolved toward scope-discipline: the default now matches the documented threat model, and privacy-maximalism is one flag away.'
        }
        @{  Id          = 'M-D'
            Severity    = 'Medium'
            Title       = '-Verify exit code coupled to live network reachability, so CI/Intune gating flaps'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Verify splits deterministic CONFIG checks (gate the exit code) from ADVISORY output (never gates). Reachability probing is opt-in via -IncludeReachability and always advisory.'
        }

        # --- external panel review: LOW ----------------------------------------------------------
        @{  Id          = 'L-A'
            Severity    = 'Low'
            Title       = 'Unbounded transcript log growth'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Start-AuditLog prunes to the newest $LogKeep transcripts via the pure Select-PruneTarget helper.'
        }
        @{  Id          = 'L-B'
            Severity    = 'Low'
            Title       = 'ErrorAction SilentlyContinue around Stop-Service masked a service that refused to stop'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Stop-ServiceReporting reports the post-stop state per service and warns that a still-running service keeps egressing until reboot; -Verify checks running state for every in-scope service.'
        }
        @{  Id          = 'L-C'
            Severity    = 'Low'
            Title       = 'Pinned CI tool versions would silently bit-rot with no automated bump PRs'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = '.github/dependabot.yml added for the github-actions ecosystem; the PSScriptAnalyzer pin keeps a documented bump procedure and CI gained a weekly scheduled run so rot surfaces on a schedule rather than at the next push.'
        }
        @{  Id          = 'L-D'
            Severity    = 'Low'
            Title       = 'login.live.com sinkhole had no on-screen reminder, so later sign-in failures look mysterious'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = '-Verify prints an advisory naming login.live.com as sinkholed by explicit choice, read from the recorded scope in state.json.'
        }

        # --- v1.5.0 self-audit: findings the external panel did not surface ----------------------
        @{  Id          = 'A-1'
            Severity    = 'Medium'
            Title       = 'Set-SvcStartMode silently wrote a null/garbage Start value for an unrecognised mode'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Get-SvcStartValue is a pure validated map that throws on an unknown mode, so a corrupt state.json can never coax a service into Start=0 (boot-start).'
            Rationale   = 'Start=0 on a Win32 service is not a benign value; refusing beats guessing.'
        }
        @{  Id          = 'A-2'
            Severity    = 'Medium'
            Title       = 'New-FwBlock skipped any rule that already existed, so a disabled/edited rule was never healed'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'New-FwBlock re-asserts Enabled/Action/Direction/Profile/Service on existing rules and removes duplicates, so the boot task self-heals a tampered or GPO-disabled rule.'
            Rationale   = 'A rule that exists but blocks nothing is worse than a missing one: it reads as applied.'
        }
        @{  Id          = 'A-3'
            Severity    = 'Medium'
            Title       = '-Test silently narrowed an active -Apply hosts block to two FQDNs for the duration of the test'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Invoke-Test refuses to run when suppression is already applied (exit 4) unless -Force, because the test window would reduce live protection.'
        }
        @{  Id          = 'A-4'
            Severity    = 'Medium'
            Title       = '-Test exited 0 when the endpoints were already unreachable, proving nothing'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Get-TestVerdict requires reachable-before -> blocked-after for proof and returns INCONCLUSIVE (exit 3) when nothing was reachable to begin with.'
        }
        @{  Id          = 'A-5'
            Severity    = 'Low'
            Title       = 'Endpoint lists could drift apart across Suppress-GDID.ps1, gdid-domains.txt and pihole-add-gdid.sh'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'The audit loop asserts the three sources agree: the txt list matches the script sets exactly, and every DDS/activity FQDN the script sinkholes is covered by a wildcard in the Pi-hole script.'
            Rationale   = 'Closes the review coverage gap: nothing detected an omission in the blocklist.'
        }
        @{  Id          = 'A-6'
            Severity    = 'Low'
            Title       = 'Version string was duplicated between the header comment and $Version with no drift check'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'The audit loop asserts the header comment, $Version, and the documented exit-code table stay in sync.'
        }
        @{  Id          = 'A-7'
            Severity    = 'Medium'
            Title       = 'An untrusted state.json threw a raw SECURITY exception out of -Undo with no recovery path'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Get-StateForUndo classifies the state file (ok/missing/unreadable/untrusted) and -Undo prints the classification plus the exact -Force escape hatch instead of an unhandled throw. An untrusted file is never parsed.'
        }
        @{  Id          = 'A-8'
            Severity    = 'High'
            Title       = '-Undo silently left all four policy values at 0 when state.json was missing'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Get-PolicyRestorePlanOrDefault removes the four policy values (their default-Windows absent state) when -Force is used without state; without -Force the undo refuses rather than half-reverting.'
            Rationale   = 'The old empty restore plan meant the policy layer stayed applied while the run printed REVERTED.'
        }
        @{  Id          = 'A-9'
            Severity    = 'Low'
            Title       = '-Test created %ProgramData%\SuppressGDID with default inherited (user-writable) ACLs'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Invoke-Test calls Protect-InstallDir before Start-AuditLog, and states plainly that the log directory it created is left behind on purpose.'
            Rationale   = 'A user-writable directory adjacent to the SYSTEM task path is the H-1 class this repo already fixed for -Apply.'
        }
        @{  Id          = 'A-10'
            Severity    = 'Low'
            Title       = 'Test harness passed on Windows only; ACL tests hard-failed instead of skipping elsewhere'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Run-Tests and Smoke-Test gate Windows-only ACL work behind a platform check and report SKIP; Invoke-AuditLoop reports skipped rows distinctly and can fail on them with -FailOnSkip.'
            Rationale   = 'Same principle as H-A applied to the harness: never report a pass for something that did not run.'
        }

        @{  Id          = 'A-12'
            Severity    = 'Medium'
            Title       = 'The harness itself was not runtime-clean on Windows PowerShell 5.1, the version the tool targets'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Three-segment Join-Path (-AdditionalChildPath, PowerShell 6+) replaced with nested two-argument calls; the tests no longer shadow Clear-DnsClientCache (the tool wraps it as Clear-DnsCache); and Invoke-Child drops to ErrorActionPreference Continue so a child writing to stderr yields a FAIL stage instead of a terminating NativeCommandError that kills the run before the coverage table prints.'
            Rationale   = 'Found by the Windows CI lane on the first run while the Linux lane was green - exactly the split the two lanes exist for. Pinned so a PowerShell-7-only idiom cannot creep back into a 5.1 tool.'
        }

        @{  Id          = 'A-13'
            Severity    = 'High'
            Title       = 'The coverage gate lost per-finding attribution on Windows PowerShell 5.1 (ConvertFrom-Json array collapse)'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'The findings report is assigned before being wrapped in @(), so the parsed array stays flat on both runtimes; the orphan check uses ForEach-Object instead of Select-Object -ExpandProperty so a malformed row reports instead of crashing; and the meta-test gained an attribution case that fails one pin and requires the other findings to stay PASS.'
            Rationale   = '5.1 emits a parsed JSON array as one pipeline object while 6+ enumerates it, so @(pipeline) collapsed 155 assertion rows into one. Effect was over-reporting, not a false all-clear: a missing pin still showed 0 assertions, but any single failure marked every finding FAIL and the Asserts column read 1 everywhere. Registered High because the gate is the control the whole harness rests on.'
        }

        # --- deliberate residuals ---------------------------------------------------------------
        # --- code-viability pass (does it actually run correctly on the target runtime) ---------
        @{  Id          = 'V-1'
            Severity    = 'High'
            Title       = 'The VR-1 owner gate asserted an invariant it never established, so -Apply aborted on a default Windows box'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Set-TrustedOwner vests ownership in BUILTIN\Administrators on every object the tool creates - the installed script after Copy-Item, state.json after each write, and the log directory on creation - so the owner assertions in Protect-InstalledScript, Write-StateFileSafely and Assert-InstallSafe are satisfiable.'
            Rationale   = 'Ownership is NOT inherited from the parent directory (only ACEs are), and Windows has defaulted object ownership to the OBJECT CREATOR since XP - so a file written by elevated admin Alice is owned by Alice user SID, not Administrators. Test-PathOwnerUntrusted therefore rejected the tool own freshly created files and threw. A functional regression introduced by the adversarial pass, invisible to CI because every ACL-writing path needs a real elevated Windows session.'
        }
        @{  Id          = 'V-2'
            Severity    = 'Medium'
            Title       = '-Verify never validated the CDPUserSvc registry Start value that -Apply writes'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'The start-type check now reads the registry through Get-SvcRawState for every service, which is exactly what Set-SvcStartMode writes; CIM is used only for the genuine runtime State property, and a service CIM does not surface no longer silently downgrades to an advisory Note.'
            Rationale   = 'Win32_Service does not reliably surface a per-user service TEMPLATE like CDPUserSvc. When it did not, the null branch emitted a non-gating Note, so the single value -Apply wrote for CDPUserSvc went unverified - the H-A false-pass class surviving in one spot.'
        }
        @{  Id          = 'V-3'
            Severity    = 'Medium'
            Title       = '-Undo could throw mid-way on a malformed state.json, leaving the machine half-reverted'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'ConvertTo-IntOrNull replaces bare [int] casts on state-file data; an unusable value becomes an explicit invalid action that is reported and skipped. Invoke-Undo now builds the service AND policy plans before any mutation, so a bad field cannot strand the machine after Remove-Persistence has run.'
            Rationale   = 'A bare [int] cast on a hand-edited or corrupt field threw under ErrorActionPreference Stop, and the plans were built after the persistence task had already been removed.'
        }
        @{  Id          = 'V-4'
            Severity    = 'Low'
            Title       = 'An unconditional Stop-Transcript could tear down the caller own transcript'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Start-AuditLog records whether it actually started the transcript; Stop-AuditLog only stops one the tool started.'
            Rationale   = 'Start-Transcript fails when the session is already transcribing. That failure was swallowed, then the finally block stopped whatever transcript WAS running - the operator own.'
        }

        @{  Id          = 'V-5'
            Severity    = 'High'
            Title       = 'A malformed workflow YAML is discarded by GitHub before any job runs, so a validation lane silently does not exist'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Every step name in the workflows is quoted, and the audit loop parse stage now lints .github/workflows/*.yml for the defect class - an unquoted scalar containing a colon-space, which YAML reads as a nested mapping - plus the presence of on: and jobs: blocks.'
            Rationale   = 'The integration workflow was rejected at startup because a step name contained "no SECURITY: throw". The run reported failure with ZERO jobs, produced no check run, and would have been trivially mistaken for not-applicable. Same shape as H-A: a check that never ran, presenting as fine.'
        }

        @{  Id          = 'V-6'
            Severity    = 'Medium'
            Title       = 'Integration assertions captured tool output with 2>&1, which misses Write-Host, making every text match vacuous'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'The integration workflow captures with *>&1 so the information stream is included, and the audit loop lints the workflows for a 2>&1 capture whose result is later matched.'
            Rationale   = 'The tool reports through Write-Host, which in Windows PowerShell 5.1 writes to the INFORMATION stream; an in-process call captured with 2>&1 yields an empty string. So the -Apply check for a SECURITY: throw could never fail, and the post-apply -Verify check threw even though the log plainly showed ALL CONFIGURATION CHECKS PASS. A false PASS inside the validation lane - the H-A class, one level up.'
        }

        # --- VR pass (adversarial LPE audit) ----------------------------------------------------
        @{  Id          = 'VR-1'
            Severity    = 'High'
            Title       = 'Install-dir ownership never asserted: a pre-created attacker-owned directory keeps implicit WRITE_DAC and can hijack the SYSTEM task (LPE)'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'New-HardenedAcl now SetOwner(BUILTIN\Administrators) so Set-Acl re-takes ownership at apply time; Test-PathOwnerUntrusted rejects any owner outside {SYSTEM, Administrators}; every fail-closed gate (Protect-InstallDir, Protect-InstalledScript, Assert-InstallSafe, Read-StateFileSafely, Write-StateFileSafely, Get-StateForUndo) and -Verify now checks owner, not just the DACL.'
            Rationale   = 'A DACL does not bind the object owner - the owner keeps implicit READ_CONTROL+WRITE_DAC with no OWNER RIGHTS (S-1-3-4) ACE to strip it. %ProgramData% lets a standard user pre-create the subdir as CREATOR OWNER; the prior code re-wrote the DACL but left them owner, so they could re-open the DACL later and replace the script the GDIDie-Enforce SYSTEM task executes. Test-PathUserWritable is DACL-only and cannot see implicit owner rights.'
        }
        @{  Id          = 'VR-2'
            Severity    = 'Low'
            Title       = 'SYSTEM scheduled task invoked powershell.exe by bare name, leaning on PATH resolution at trigger time'
            Disposition = 'Fixed'
            Platform    = 'Any'
            Fix         = 'Install-Persistence registers the task with the absolute %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe, removing any executable search.'
            Rationale   = 'Defense-in-depth. A standard user cannot write System32 or earlier SYSTEM PATH entries, so this was not directly exploitable, but an unqualified interpreter in a SYSTEM task is a hardening gap an LPE reviewer expects closed.'
        }

        @{  Id          = 'I-2'
            Severity    = 'Info'
            Title       = 'On-host controls are defeatable by a sufficiently privileged OS-vendor component (hardcoded IPs, DoH)'
            Disposition = 'Accepted'
            Platform    = 'Any'
            Fix         = 'Documented ceiling: README Honest limitations, SECURITY-AUDIT.md I-2, and now the runtime banner (H-B).'
            Rationale   = 'Not fixable on-host by construction. The off-host DNS/router layer is the sovereign control.'
        }
        @{  Id          = 'I-3'
            Severity    = 'Info'
            Title       = 'The FQDN blocklist is an allowlist-style enumeration: a new Microsoft egress FQDN is missed silently'
            Disposition = 'Accepted'
            Platform    = 'Any'
            Fix         = 'Documented in README (Honest limitations) as an inherent limit; A-5 keeps the three shipped copies of the list in agreement, which is the part that IS mechanisable.'
            Rationale   = 'No on-host mechanism can enumerate an endpoint Microsoft has not shipped yet; the Pi-hole wildcard layer is the mitigation.'
        }
        @{  Id          = 'I-4'
            Severity    = 'Info'
            Title       = 'Efficacy against live GDID egress is unverified by execution (no lab VM, no packet capture)'
            Disposition = 'Accepted'
            Platform    = 'Any'
            Fix         = 'Documented in README as an explicitly unverified claim; -Test verdict wording (H-B) refuses to overstate what it measured.'
            Rationale   = 'Requires a network-forensics lab seat the CI does not have. Stating it beats implying it was measured.'
        }
    )
}
