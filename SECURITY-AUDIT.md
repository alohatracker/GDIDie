# GDIDie — Security Hardening Review

**Reviewer perspective:** senior Windows security engineer (SYSTEM/privilege-boundary focus).
**Scope:** `Suppress-GDID.ps1` v1.2.0 and its runtime footprint (services, registry, hosts file,
Windows Firewall, scheduled task, install directory). **Method:** static read + live ACL/behaviour
probing on the target host. **Severity:** CVSS-style, adjusted for local-only reachability.

## Summary

| # | Finding | CWE | Severity | Status |
|---|---------|-----|----------|--------|
| H-1 | Install dir writable by standard users while a **SYSTEM** task executes from it | CWE-377 / CWE-427 | High (local) | **Fixed** (v1.2.0) |
| I-1 | Transcript logs grow unbounded (no rotation) | CWE-400 | Low | Accepted |
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

## Reviewed / no action (defense-in-depth confirmations)

- **Scheduled-task object ACL** — `C:\Windows\System32\Tasks\GDIDie-Enforce` is writable only by
  SYSTEM/Administrators; a standard user cannot alter the task definition. OK.
- **Task invocation** — `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<absolute>"`.
  `-NoProfile` blocks profile injection; absolute path blocks CWD resolution. OK.
- **No dynamic execution** — no `Invoke-Expression`/`iex`, no relative module import, no download-run.
- **`state.json` integrity** — `RX` for Users after H-1 fix; only SYSTEM/Admin can tamper the undo
  source of truth. OK.
- **Privilege gating** — all state-changing paths call `Assert-Admin` (exit 2 if not elevated);
  `-Verify`/`-Test` self-limit and the SYSTEM-task check is elevation-gated (skip, not fail).
- **Input handling** — service names and endpoints are hardcoded allowlists; no untrusted input
  reaches `Get-CimInstance -Filter`, the registry paths, or the firewall/host writes.
- **Hosts write** — BOM-free UTF-8 via `WriteAllLines`; sentinel-delimited managed block;
  round-trip + idempotency unit-tested.

## Accepted / residual

- **I-1 log growth** — transcripts under `…\logs` are not rotated. Local, low; a boot-time task writes
  one small file per apply. Accepted rather than adding a scheduler/cleanup surface.
- **I-2 vendor ceiling** — on-host suppression cannot bind a sufficiently privileged Microsoft
  component (hardcoded IPs, DoH). The off-host DNS/router layer remains the sovereign control.
  Documented in README, not a code defect.

## Test/verification inventory

| Check | Where | Result |
|-------|-------|--------|
| ACL builder correctness | `Tests/Run-Tests.ps1` (unit) | 16/16 pass |
| ACL applied on real fs | `Tests/Smoke-Test.ps1` | 4/4 pass |
| Live H-1 closed | `icacls` + create probe + `-Verify` | denied / PASS |
| Static analysis | PSScriptAnalyzer (CI) | 0 findings |
| Parse + logic | CI (GitHub Actions) | green |
