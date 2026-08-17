<div align="center">

# GDIDie

**Cut the Windows GDID and the device-graph telemetry that carries it — reversibly.**

[![CI](https://github.com/alohatracker/GDIDie/actions/workflows/ci.yml/badge.svg)](https://github.com/alohatracker/GDIDie/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-Windows_10_%2F_11-0078d6)
![Shell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![Reversible](https://img.shields.io/badge/reversible-yes_(--Undo)-2ea44f)
![License](https://img.shields.io/badge/license-MIT-informational)

</div>

---

## What this is

The **GDID** (Global Device Identifier) is a persistent, per-installation Windows fingerprint —
a **server-assigned Microsoft Account Device PUID** (64-bit, `0018`-class). It is *not* a hardware
hash and it does *not* change when your IP changes. It rode into public view in the July 2026
*U.S. v. Stokes* (Scattered Spider) complaint, where Microsoft used it to attribute activity to a
device **behind a VPN across three countries**.

It survives a local account (Windows mints one anonymously anyway), survives disabling classic
telemetry (it travels a different path), and survives deleting the registry value (your PC just
re-downloads the *same* number from Microsoft). You cannot erase it. What you *can* do is **stop it
from leaving your machine.**

GDIDie does exactly that, at four on-host layers plus an optional network layer, and every change is
reversible with one command.

## The kill chain (and where GDIDie cuts it)

```
wlidsvc ──provision──► login.live.com ──returns PUID──► registry (IdentityCRL / IdentityStore)
                                                              │  [D] policy
CDPSvc ──reads PUID, registers──► Device Directory Service (dds.microsoft.com)   [A] service  [B] hosts  [C] firewall
DoSvc  ──reports──► Delivery Optimization  ──► UCDOStatus.GlobalDeviceId          [A] service  [B] hosts  [C] firewall
                    activity uploads ──► activity.windows.com                     [B] hosts  [C] firewall
```

| Layer | What it does | Why |
|---|---|---|
| **A. Services** | Disables `CDPSvc`, `CDPUserSvc`, `DoSvc` via the registry `Start=4` value | Nothing locally registers or reports the device. Registry method bypasses the SCM "Access denied" that blocks `DoSvc`. |
| **B. Hosts** | Sinkholes the DDS / CDP / Delivery-Optimization / activity FQDNs to `0.0.0.0` and `::` | Even if a service starts, it can't reach the graph. **Must** be by hostname — DDS hides behind shared Azure Front Door IPs (`13.107.x.x`) that Office/Bing/Windows Update also use, so IP blocking is wrong. |
| **C. Firewall** | Windows Firewall outbound-block rules **scoped to the service SID** | IP/DNS-agnostic backstop — blocks the process wherever it tries to connect. |
| **D. Policy** | `EnableCdp=0` ("Continue experiences off") + Activity History off | Tells Windows to stop trying. |

`login.live.com` (the mint) is **left alone by default** so Microsoft Account sign-in keeps working.

**Scoped by default.** The documented GDID chain runs through `CDPSvc`/`CDPUserSvc`/`DoSvc` and the
DDS / Delivery-Optimization / activity endpoints — that is all the default `-Apply` touches. Classic
telemetry (`DiagTrack`, `dmwappushservice`) is belt-and-suspenders sitting on a *different* path, and
disabling `DiagTrack` has real side effects (enterprise management, Feedback Hub, and on some builds
Windows Update diagnostics), so it is opt-in behind `-IncludeClassicTelemetry` rather than bundled
into the default blast radius. Add the switch if you want privacy-maximalism; leave it off if you
want the mitigation to match the threat model above.

## Requirements

- Windows 10 / 11, PowerShell 5.1+ (built in)
- Administrator (the script self-checks and tells you if not elevated)
- **Test in a VM snapshot first** if you're cautious — this disables system services.

## Quick start

```powershell
# 1. See where you stand + what will change (read-only):
powershell -ExecutionPolicy Bypass -File .\Suppress-GDID.ps1 -Verify

# 2. Prove the block works on the live endpoints, then auto-revert (no services touched):
powershell -ExecutionPolicy Bypass -File .\Suppress-GDID.ps1 -Test

# 3. Apply for real (elevated):
powershell -ExecutionPolicy Bypass -File .\Suppress-GDID.ps1 -Apply

# 4. Undo everything (elevated; exact when state.json is still there, refuses to guess if not):
powershell -ExecutionPolicy Bypass -File .\Suppress-GDID.ps1 -Undo
```

Run elevated. If you double-click or run non-elevated, it prints the elevated command to use.

### Modes

| Mode | Effect |
|---|---|
| `-Verify` | Read-only, offline, fast. Checks **everything `-Apply` changed**, driven from the same lists: every in-scope service, the hosts block *contents* FQDN-by-FQDN, all four policy values, and each firewall rule's `Enabled`/`Action`/`Direction`/service filter. Only these deterministic configuration checks affect the exit code. |
| `-Verify -IncludeReachability` | Adds live DNS + `:443` probes of the DDS endpoints. **Advisory only** — reachability depends on your network, not on this tool, so it never changes the exit code. |
| `-Test` | Reversible proof: sinkholes the two live endpoints + adds one firewall rule, measures before/after, **auto-rolls back** byte-for-byte. Never touches services. Writes an audit transcript. Refuses to run while suppression is applied (see `-Force`). |
| `-Apply` | Applies all four layers **and registers a SYSTEM re-apply task** (below). Records the original service start-types (including the raw registry values) to `state.json` for an exact undo (first-write-wins — safe to re-run). |
| `-Undo` | Restores services and policy values from the state file, removes the hosts block + firewall rules, and unregisters the task. **Refuses** (exit 4, nothing changed) if `state.json` is missing or untrusted — see `-Force`. |
| `-Apply -IncludeLoginLive` | Also sinkholes `login.live.com`. **Breaks Microsoft Store / MSA sign-in.** Opt-in — and the boot-time enforce task remembers the choice, so it stays blocked across reboots. `-Verify` reminds you it is active. Use this if you don't have a Microsoft Account. |
| `-Apply -IncludeClassicTelemetry` | Also disables `DiagTrack` + `dmwappushservice` and adds firewall rules for them. Opt-in (see "Scoped by default" above); the boot task remembers this choice too. |
| `-Apply -NoPersist` | Apply without the scheduled task (also what the task itself runs, to avoid recursion). |
| `-Undo -Force` | Undo *without* a trustworthy `state.json`, using **documented Microsoft defaults** for the services a default `-Apply` disables (`CDPSvc=Automatic`, `DoSvc=Manual`, `CDPUserSvc=Automatic`) and removing the four policy values. These are defaults, **not** your original configuration. `DiagTrack`/`dmwappushservice` are **left alone** — with no state file the tool cannot know whether you had disabled them yourself, and it never re-enables telemetry from a guess. If you applied with `-IncludeClassicTelemetry` and lost the state file, restore those two by hand. |
| `-Test -Force` | Run `-Test` even though suppression is currently applied, accepting that the probe window narrows your hosts block to two FQDNs until rollback. |

`-Apply` is additive: it asserts the layers for the scope you asked for and never re-enables something
a previous, broader `-Apply` disabled. Use `-Undo` for that.

### Durability, logging, exit codes

- **Persistence:** `-Apply` installs a copy to `%ProgramData%\SuppressGDID\` (locked to an explicit SYSTEM/Admin-full, Users-read-only DACL **and re-owned to Administrators** so a pre-created attacker-owned directory can't keep implicit `WRITE_DAC` — see [SECURITY-AUDIT.md](SECURITY-AUDIT.md) H-1/H-2) and registers a SYSTEM scheduled task **`GDIDie-Enforce`** (absolute interpreter path, no PATH search) that re-applies at startup — so a Windows feature update that re-enables `CDPSvc` gets re-blocked. The task carries every scope switch you chose, and `-Verify` fails if the registered arguments drift from the recorded scope. `-Undo` removes it.
- **Audit log:** every `-Apply`/`-Undo`/`-Test` writes a timestamped transcript to `%ProgramData%\SuppressGDID\logs\`, capped at the newest 30 files.
- **Automation:** gate CI/Intune/SCCM on the exit code. Only deterministic configuration state affects it — network reachability is advisory, so a proxy or an offline machine cannot flap your gate.

  | Exit | Meaning |
  |---|---|
  | 0 | success — `-Apply`/`-Undo` completed, `-Verify` all-pass, or `-Test` proved the block |
  | 1 | `-Verify` had at least one failing configuration check, or `-Test` left a reachable endpoint reachable |
  | 2 | not elevated, or a fatal error |
  | 3 | `-Test` inconclusive — the probe endpoints were already unreachable, so nothing was proved |
  | 4 | refused, **nothing changed** — `-Undo` without trustworthy state (add `-Force`), or `-Test` while applied (add `-Force`) |

  (Run `-Verify` elevated to include the SYSTEM task check; non-elevated it is reported as advisory, not failed.)
- **State safety:** `state.json` is merged first-write-wins, so re-running `-Apply` never overwrites the true pre-mitigation values (regression fixed in v1.1.0). `-Undo` is **exact when the state file is present** — it restores the raw registry `Start`/`DelayedAutostart` values it recorded, leaves any service whose original it never recorded alone, and refuses to guess when the file is gone. A state file that standard users can write is treated as untrusted and never parsed.

### Tests & signing

- **Audit loop (one entry point):** `powershell -ExecutionPolicy Bypass -File .\Tests\Invoke-AuditLoop.ps1`
  runs parse → static analysis → unit → smoke → per-finding regression pins → **coverage gate**.
  The gate fails the run if any finding in [`Tests/findings.psd1`](Tests/findings.psd1) marked *Fixed*
  has no assertion that actually ran and passed, so a fix is not "done" until something pins it and a
  finding cannot be quietly dropped. A platform-skipped check is reported as `SKIP`, never folded into
  the passes; `-FailOnSkip` turns skips into failures (that is how the Windows CI lane runs).
  See [Tests/README.md](Tests/README.md).
- **Tests:** `powershell -ExecutionPolicy Bypass -File .\Tests\Run-Tests.ps1` — dependency-free unit tests for the hosts-block and state-guard logic. No admin, no network. Exit 0/1.
- **Signing:** the repo ships unsigned; sign at deploy time with **your** Authenticode / org PKI cert (`Set-AuthenticodeSignature`) so it runs under `AllSigned`. Enterprise trust can't be shipped in source.

Find your own GDID (read-only, no admin), redact before sharing:

```powershell
$lid = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties').LID
"g:$([Convert]::ToUInt64($lid,16))"
```

## The durable layer: Pi-hole / router DNS

On-host controls are strong but not sovereign — the OS vendor can, in principle, bypass a hosts
file or firewall with hardcoded IPs or DNS-over-HTTPS. The block the vendor **can't** route around is
one enforced off the machine. If you run Pi-hole (v6), run `pihole-add-gdid.sh` **on the Pi-hole box**:

```bash
pihole --wild dds.microsoft.com
pihole --wild do.dsp.mp.microsoft.com
pihole --wild cdpcs.access.microsoft.com
pihole --wild activity.windows.com
pihole reloaddns
```

`gdid-domains.txt` is a plain list for any sink (Pi-hole, AdGuard, NextDNS, hosts).
For a true "nothing leaves" guarantee, pair this with a **default-deny outbound firewall** at your
router and force all `:53` through your sink (and block outbound `:853` to kill DoH bypass).

## Honest limitations

The tool prints this ceiling itself, on `-Apply` and on a passing `-Verify` — a green `-Verify` means
"configured as intended", not "you are anonymous".

- This **stops future reporting**. It does **not** erase the GDID already sitting on Microsoft's
  servers since your first login, and it does **not** make you anonymous.
- The GDID value stays readable on your disk (it re-downloads if deleted) — that's fine; it just
  can't egress.
- On-host suppression is defeatable by a sufficiently privileged Microsoft component, via hardcoded
  IPs or **DNS-over-HTTPS**. The Pi-hole / router layer is what makes it durable.
- **The efficacy claim is unverified by execution.** Nothing here has been confirmed with a packet
  capture: `-Test` proves that a TLS connect to two hostnames stops working, which is *hostname
  reachability blocking*, not the observed absence of GDID traffic on the wire. Proving the stronger
  claim needs a lab VM and a network capture; until someone does that, treat the efficacy of the
  four layers as reasoned-but-unmeasured. `-Test`'s own verdict says so.
- **The blocklist is an enumeration, so it can silently miss a new egress FQDN.** If Microsoft ships
  a new endpoint tomorrow, the hosts and firewall layers will not cover it and nothing in the tool
  detects the omission — that is inherent to allowlist-style blocking by name. The Pi-hole wildcard
  layer (`pihole --wild dds.microsoft.com`) is the mitigation, because it covers subdomains that do
  not exist yet. The three shipped copies of the list (`Suppress-GDID.ps1`, `gdid-domains.txt`,
  `pihole-add-gdid.sh`) are kept in agreement by the audit loop, which is the part that *is*
  mechanisable.
- For genuinely sensitive activity, the only solid answer is not doing it on Windows at all
  (e.g. a live Linux system). If you are an activist, a source, or otherwise a target, take that
  sentence more seriously than the rest of this README.

## Credits

- Reverse engineering of the GDID chain: [SmtimesIWndr/gdid-reversal](https://github.com/SmtimesIWndr/gdid-reversal)
- Parallel mitigation work and the DoSvc/registry insight: [Korben00/no-gdid](https://github.com/Korben00/no-gdid) · [writeup](https://korben.info/en/gdid-windows-cut-tracker-vpn.html)
- Primary source: *United States v. Stokes* (N.D. Ill., 2026) · [The Register](https://www.theregister.com/)

## License

MIT — see [LICENSE](LICENSE). Provided as-is; you are modifying your own system services. Test first.
