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

        # --- deliberate residuals ---------------------------------------------------------------
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
