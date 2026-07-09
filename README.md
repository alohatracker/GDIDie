<div align="center">

# GDIDie

**Cut the Windows GDID and the device-graph telemetry that carries it — reversibly.**

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
| **A. Services** | Disables `CDPSvc`, `CDPUserSvc`, `DoSvc` (+ `DiagTrack`, `dmwappushservice`) via the registry `Start=4` value | Nothing locally registers or reports the device. Registry method bypasses the SCM "Access denied" that blocks `DoSvc`. |
| **B. Hosts** | Sinkholes the DDS / CDP / Delivery-Optimization / activity FQDNs to `0.0.0.0` and `::` | Even if a service starts, it can't reach the graph. **Must** be by hostname — DDS hides behind shared Azure Front Door IPs (`13.107.x.x`) that Office/Bing/Windows Update also use, so IP blocking is wrong. |
| **C. Firewall** | Windows Firewall outbound-block rules **scoped to the service SID** | IP/DNS-agnostic backstop — blocks the process wherever it tries to connect. |
| **D. Policy** | `EnableCdp=0` ("Continue experiences off") + Activity History off | Tells Windows to stop trying. |

`login.live.com` (the mint) is **left alone by default** so Microsoft Account sign-in keeps working.

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

# 4. Undo everything, exactly (elevated):
powershell -ExecutionPolicy Bypass -File .\Suppress-GDID.ps1 -Undo
```

Run elevated. If you double-click or run non-elevated, it prints the elevated command to use.

### Modes

| Mode | Effect |
|---|---|
| `-Verify` | Read-only. Services, hosts block, `EnableCdp`, firewall rules, endpoint reachability, persistence task. PASS/FAIL per check. Exit 0 all-pass, 1 any-fail. |
| `-Test` | Reversible proof: sinkholes the two live endpoints + adds one firewall rule, measures before/after, **auto-rolls back**. Never touches services. |
| `-Apply` | Applies all four layers **and registers a SYSTEM re-apply task** (below). Records original service start-types to `state.json` for exact undo (first-write-wins — safe to re-run). |
| `-Undo` | Restores services from the state file, removes the hosts block + firewall rules, restores the policy key, and unregisters the task. |
| `-Apply -IncludeLoginLive` | Also sinkholes `login.live.com`. **Breaks Microsoft Store / MSA sign-in.** Opt-in. |
| `-Apply -NoPersist` | Apply without the scheduled task (also what the task itself runs, to avoid recursion). |

### Durability, logging, exit codes

- **Persistence:** `-Apply` installs a copy to `%ProgramData%\SuppressGDID\` and registers a SYSTEM scheduled task **`GDIDie-Enforce`** that re-applies at startup — so a Windows feature update that re-enables `CDPSvc` gets re-blocked. `-Undo` removes it.
- **Audit log:** every `-Apply`/`-Undo` writes a timestamped transcript to `%ProgramData%\SuppressGDID\logs\`.
- **Automation:** `-Verify` returns exit `0` (all pass) or `1` (any fail); `Assert-Admin` exits `2`. Gate CI/Intune/SCCM on these. (Run `-Verify` elevated to include the SYSTEM task check; non-elevated it is skipped, not failed.)
- **State safety:** `state.json` is merged first-write-wins, so re-running `-Apply` never overwrites the true pre-mitigation values (regression fixed in v1.1.0).

### Tests & signing

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

- This **stops future reporting**. It does **not** erase the GDID already sitting on Microsoft's
  servers since your first login, and it does **not** make you anonymous.
- The GDID value stays readable on your disk (it re-downloads if deleted) — that's fine; it just
  can't egress.
- On-host suppression is defeatable by a sufficiently privileged Microsoft component. The Pi-hole /
  router layer is what makes it durable.
- For genuinely sensitive activity, the only solid answer is not doing it on Windows at all
  (e.g. a live Linux system).

## Credits

- Reverse engineering of the GDID chain: [SmtimesIWndr/gdid-reversal](https://github.com/SmtimesIWndr/gdid-reversal)
- Parallel mitigation work and the DoSvc/registry insight: [Korben00/no-gdid](https://github.com/Korben00/no-gdid) · [writeup](https://korben.info/en/gdid-windows-cut-tracker-vpn.html)
- Primary source: *United States v. Stokes* (N.D. Ill., 2026) · [The Register](https://www.theregister.com/)

## License

MIT — see [LICENSE](LICENSE). Provided as-is; you are modifying your own system services. Test first.
