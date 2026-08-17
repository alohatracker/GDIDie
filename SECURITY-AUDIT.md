# GDIDie — Security Hardening Review

**Reviewer perspective:** senior Windows security engineer (SYSTEM/privilege-boundary focus).
**Scope:** `Suppress-GDID.ps1` v1.5.0 and its runtime footprint (services, registry, hosts file,
Windows Firewall, scheduled task, install directory). **Method:** static read + live ACL/behaviour
probing on the target host. **Severity:** CVSS-style, adjusted for local-only reachability.

Findings from the external expert-panel review are tracked in `Tests/findings.psd1` and pinned by
assertions in `Tests/Audit-Findings.ps1`; run `Tests/Invoke-AuditLoop.ps1` to re-validate all of
them. This document covers the privilege-boundary subset.

## Summary

| # | Finding | CWE | Severity | Status |
|---|---------|-----|----------|--------|
| H-1 | Install dir writable by standard users while a **SYSTEM** task executes from it | CWE-377 / CWE-427 | High (local) | **Fixed** (v1.2.0) |
| T-1 | TOCTOU window between `Assert-InstallSafe` and `Register-ScheduledTask` | CWE-367 | Low (local) | **Mitigated** (v1.5.0) |
| T-2 | `-Test` created `%ProgramData%\SuppressGDID` with inherited (user-writable) ACLs | CWE-377 | Low (local) | **Fixed** (v1.5.0) |
| I-1 | Transcript logs grow unbounded (no rotation) | CWE-400 | Low | **Fixed** (v1.5.0) |
| I-2 | On-host controls defeatable by the OS vendor (hardcoded IP / DoH) | — | Info | Documented ceiling |

Items explicitly reviewed and found **sound** are listed under "Reviewed / no action".

## H-1 — Writable install directory feeding a SYSTEM task  *(fixed)*

**What.** `-Apply` installs a copy of the script to `%ProgramData%\SuppressGDID\` and registers the
`GDIDie-Enforce` scheduled task, which runs **as SYSTEM at startup** executing that copy. By default
`%ProgramData%` subdirectories inherit an ACE granting `BUILTIN\Users` create/write:

```
BEFORE:  C:\ProgramData\SuppressGDID   BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)
```

**Impact.** A standard user can create files in the directory a SYSTEM process runs from. The script
file itself was already `RX`-only (no overwrite), and the code contains **no** relative
dot-source / `Import-Module` / `Invoke-Expression`, so there is no *direct* code-execution path today.
But a world-writable directory backing a SYSTEM task is a latent local-privilege-escalation surface
(sideloading, future relative-load regressions) and fails least-privilege on its own.

**Fix (v1.2.0).** `Protect-InstallDir` applies an explicit, inheritance-protected DACL before anything
is written into the directory (`New-HardenedAcl`, a pure/unit-tested builder):

```
AFTER:   C:\ProgramData\SuppressGDID   NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                        BUILTIN\Administrators:(OI)(CI)(F)
                                        BUILTIN\Users:(OI)(CI)(RX)
```

**Verification (live, non-elevated after fix):**
- `icacls` shows no `Users` write ACE and no inheritance (`(I)` gone).
- create-file probe: `Permission denied` (was: succeeded).
- `-Verify` gains a permanent regression check: `[PASS] install dir not writable by standard users`.
- Covered by unit tests (`New-HardenedAcl`) and `Tests/Smoke-Test.ps1` (applies the DACL to a real
  temp dir and asserts Users cannot write).

## T-1 — Check-then-register TOCTOU window  *(mitigated, v1.5.0)*

**What.** The install sequence is `Protect-InstallDir` → `Protect-InstalledScript` →
`Assert-InstallSafe` → `Register-ScheduledTask`. These are sequential and **non-atomic**: between the
final safety assertion and the moment the SYSTEM task exists, the checked objects are, in principle,
mutable. This is CWE-367, and the previous revision of this document listed the whole install/task
area as "sound" without naming the class — an omission worth correcting on its own, since the audit's
credibility rests on completeness rather than on a clean verdict.

**Why the practical risk is low.**
- `%ProgramData%` itself is not user-writable, so the parent of the install dir cannot be swapped.
- `Protect-InstallDir` runs **first** and applies an inheritance-protected DACL, so by the time the
  window opens, standard users already have `RX` only.
- `Protect-InstalledScript` deletes any pre-existing file before copying, so the new file inherits
  the locked parent DACL rather than keeping an attacker-planted explicit ACE.
- Reparse points are rejected at every step, closing the junction-swap variant.
- The window is microseconds of wall clock and requires the attacker to already be able to write
  where they cannot.

**Mitigation (v1.5.0).** Naming it is not enough where closing it is cheap. `Install-Persistence`
now re-runs `Assert-InstallSafe` **after** `Register-ScheduledTask` and compares the registered
action arguments against the arguments it intended to register. If either check fails it calls
`Remove-Persistence` and rethrows — so the failure mode is "no SYSTEM task" rather than "a SYSTEM
task pointing at something unverified". Pinned by `M-B` assertions in `Tests/Audit-Findings.ps1`,
including an AST check that the second assertion really is after the registration call.

**Residual.** A same-process race that wins between `Register-ScheduledTask` returning and the
post-check reading the task would still be undetected. Closing that fully requires a transactional
API that Windows does not offer here. Accepted.

## T-2 — `-Test` created the install directory unhardened  *(fixed, v1.5.0)*

**What.** v1.5.0 gives `-Test` an audit transcript (external finding M-A), which means `-Test` now
writes into `%ProgramData%\SuppressGDID\logs`. Creating that tree with `New-Item` alone would have
reproduced H-1 on a machine that had never run `-Apply`: an inherited `Users:(WD,AD)` ACE on a
directory sitting at the path a SYSTEM task later executes from.

**Fix.** `Invoke-Test` calls `Protect-InstallDir` before `Start-AuditLog`, so the directory is
created with the hardened DACL or the run aborts. `-Test` also states plainly that the log directory
is left behind, rather than claiming a full restore it did not perform. Pinned by `A-9`.

## Reviewed / no action (defense-in-depth confirmations)

- **Scheduled-task object ACL** — `C:\Windows\System32\Tasks\GDIDie-Enforce` is writable only by
  SYSTEM/Administrators; a standard user cannot alter the task definition. OK.
- **Task invocation** — `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<absolute>"`.
  `-NoProfile` blocks profile injection; absolute path blocks CWD resolution. OK. The registered
  argument string is now also compared against intent post-registration (T-1).
- **No dynamic execution** — no `Invoke-Expression`/`iex`, no relative module import, no download-run.
- **`state.json` integrity** — `RX` for Users after the H-1 fix; only SYSTEM/Admin can tamper with the
  undo source of truth. A state file that *is* user-writable is now classified `untrusted` and
  **never parsed** (`Get-StateForUndo`), so a standard user cannot steer `-Undo` — the worst they can
  do is force the operator to fall back to documented defaults via `-Force`. OK.
- **Privilege gating** — all state-changing paths call `Assert-Admin` (exit 2 if not elevated);
  `-Verify` is read-only and the SYSTEM-task check is elevation-gated (advisory, not a false fail).
- **Input handling** — service names and endpoints are hardcoded allowlists; no untrusted input
  reaches `Get-CimInstance -Filter`, the registry paths, or the firewall/host writes. Values read
  back out of `state.json` now go through `Get-SvcStartValue` / `Set-SvcStartRaw`, which reject
  anything outside the known start-value range instead of writing it (external finding A-1).
- **Hosts write** — BOM-free UTF-8 via `WriteAllLines`; sentinel-delimited managed block;
  round-trip + idempotency unit-tested; `-Test` restores the original bytes exactly.
- **Parameter-set binding** — the mode dispatcher switches on the `-Apply/-Undo/-Test` switches
  themselves rather than `$PSCmdlet.ParameterSetName`, so a bare modifier switch cannot resolve into
  an unintended `-Apply`.

## Accepted / residual

- **I-1 log growth** — *fixed in v1.5.0.* `Start-AuditLog` prunes to the newest `$LogKeep` (30)
  transcripts through the pure `Select-PruneTarget` helper, so a boot task that re-applies on every
  servicing event no longer accumulates without bound. Kept in this table for history.
- **I-2 vendor ceiling** — on-host suppression cannot bind a sufficiently privileged Microsoft
  component (hardcoded IPs, DoH). The off-host DNS/router layer remains the sovereign control.
  Documented in the README **and now printed by the tool itself** on `-Apply` and on a passing
  `-Verify`, so a user who never scrolls to the bottom of the README still sees it.
- **T-1 residual race** — see above.

## Test/verification inventory

| Check | Where | Result |
|-------|-------|--------|
| Loop entry point (all stages + coverage gate) | `Tests/Invoke-AuditLoop.ps1` | green |
| Pure-helper units (hosts block, state guard, restore plans, verdict, pruning) | `Tests/Run-Tests.ps1` | 59 pass on Linux; 68 on Windows |
| Real-filesystem behaviour (DACL, byte-exact rollback, hosts lifecycle, log pruning) | `Tests/Smoke-Test.ps1` | 15 pass on Linux; 21 on Windows |
| Per-finding regression pins | `Tests/Audit-Findings.ps1` | one or more assertions per registered finding |
| Finding coverage gate (no Fixed finding without a passing assertion) | `Tests/Invoke-AuditLoop.ps1` stage 6 | enforced |
| Live H-1 closed | `icacls` + create probe + `-Verify` | denied / PASS |
| Static analysis | PSScriptAnalyzer 1.25.0 (CI) | 0 findings |
| Parse + logic | CI (GitHub Actions, Windows + Linux lanes) | green |
