# ⚙️ Forged — Windows 11 Gaming ISO Builder (Linux-Native)

> The last Windows project I'll ever make.  
> Forged is a Linux-native toolchain that builds a debloated, gaming-focused Windows 11 ISO without touching NTLITE or any Windows-only tools. It's designed for dual-booters who only keep Windows around for games that refuse to run on Linux (anti-cheat, kernel-level DRM, etc.).

---

## Who Is This For?

- People who dual-boot **CachyOS (or any Linux)** and Windows 11.
- Gamers who need Windows only for titles like *Valorant*, *Fortnite*, *PUBG*, *League of Legends*, *Faceit* – anything with kernel anti-cheat.
- Users who want a **minimal, performance-first Windows** with zero bloat, no telemetry, no Defender, no Edge and zero Microsoft account nonsense.
- Anyone who wants to build the ISO **from Linux** without owning a Windows machine.

---

## What Does Forged Do?

- **Single-pass ISO builder** – extracts your Windows 11 ISO, keeps only the **Pro** edition, deletes every other edition.
- **Offline AppX debloat** – physically removes bloatware packages from the WIM **before** Windows ever boots (Bing, Xbox, Teams, Clipchamp, Store, etc.).
- **Registry hardening from four legendary sources**:
  - [ValleyOfDoom/PC-Tuning](https://github.com/ValleyOfDoom/PC-Tuning)
  - [djdallmann/GamingPCSetup](https://github.com/djdallmann/GamingPCSetup)
  - [XOS Playbook](https://github.com/ionuttbara/xos-playbook)
  - [Revision Tool](https://github.com/meetrevision/revision-tool)
- **TrustedInstaller post-install script** — 13-phase PowerShell script running as SYSTEM via MinSudo:
  - Phase 1: TinyRetroPad replaces Notepad, VBS toggle scripts on desktop, escalate to TI
  - Phase 2: Defender services disabled, IFEO blocks, MpCmdRun renamed, TamperProtection=0
  - Phase 3: Edge removal via XOS RemoveEdge (region spoof + own uninstaller)
  - Phase 4–12: Service debloat, scheduled task purge, power scheme, NTFS/kernel tuning, registry hardening, privacy/telemetry kill, Windows Update annihilation, network optimization, AppX removal
  - Phase 13: Cleanup, self-destruct, reboot
- **Fully automated** — places `autounattend.xml` at ISO root to bypass TPM/SecureBoot, create a local admin user, skip OOBE privacy screens, and auto-launch the Forged script.

---

## 📦 What You Get

```
forged/
├── forge-iso.sh                 # Main Linux ISO builder (Bash)
├── autounattend.xml             # Windows unattended setup (TPM bypass + OOBE skip)
├── payload/
│   ├── Forge-PostInstall.ps1    # Full post-install script (13 phases)
│   ├── MinSudo.exe              # TrustedInstaller elevation tool
│   ├── RemoveEdge.ps1           # XOS Edge uninstaller (region spoof + own setup)
│   ├── onedrive.bat             # XOS OneDrive annihilation script
│   ├── taskbar.bat              # XOS taskbar cleanup script (runs on every logon)
│   ├── W11STARTMENU.ps1         # XOS start menu pin cleaner
│   ├── LayoutModification.xml   # Zero-pins layout for new users
│   ├── services-disable.reg     # Disables Defender/WU services before OOBE
│   ├── driver-exclude.reg       # Prevents Windows Update from installing drivers
│   ├── Forged.png               # Default wallpaper (optional)
│   └── trpad.exe                # TinyRetroPad (lightweight Notepad replacement)
```

---

## 🛠️ How to Build the ISO

### Prerequisites (Arch Linux / CachyOS)

```bash
sudo pacman -S p7zip wimlib libisoburn python3   # or equivalent on your distro
```

### Build

```bash
cd forged
./forge-iso.sh /path/to/en-us_windows_11_consumer_editions_version_26h1_*.iso
```

The script:
1. Extracts the ISO with `7z`
2. Finds the **Windows 11/10 Pro** index and exports only that edition
3. Mounts the WIM with `wimlib-imagex`
4. Injects all payload files + AppX debloat offline
5. Commits changes
6. Builds a UEFI+BIOS hybrid ISO with `xorrisofs`

Output: `Forged-Win11.iso` in the `forged/` directory.

---

## 🖥️ Dual-Boot with CachyOS (or any Linux)

1. **Shrink your Linux partition** (or leave unallocated space) before installing.
2. **Install Forged Windows** to the empty space, the installer won't touch your Linux partitions.
3. **After installation**, Windows will override the boot order. Use your UEFI boot menu to choose your Linux bootloader (systemd-boot, GRUB, rEFInd or Limine).
4. **Windows UTC clock** – Forged sets `RealTimeIsUniversal=1` so your Linux and Windows clocks stay in sync.

---

## 🔐 Security & Performance Trade-Offs

- **Defender** – fully annihilated (services disabled Start=4, TamperProtection=0, DisableAntiSpyware=1, scheduled task re-kills, boot-time safety task, IFEO blocks). If you need real-time protection, this is not for you.
- **Edge** – completely removed (browser + updater + DevTools). WebView2 Runtime preserved for app compatibility.
- **UAC** – disabled (`EnableLUA=0`). Everything runs as admin.
- **Windows Update** – paused until 2038, WSUS nulled, driver updates blocked. Manual update checks may revert tweaks.
- **VBS / HVCI** – toggle scripts on desktop (`VBS-ON.bat` / `VBS-OFF.bat`). Use for Valorant/FACEIT/etc. Reboot required.

---

## 📜 License & Credits

- **Forged** is a personal project — use at your own risk.
- All registry and service lists are derived from the incredible work of:
  - [ValleyOfDoom — PC-Tuning](https://github.com/ValleyOfDoom/PC-Tuning)
  - [djdallmann — GamingPCSetup](https://github.com/djdallmann/GamingPCSetup)
  - [XOS Playbook by imribiy](https://discord.gg/XTYEjZNPgX)
  - [Revision Tool by meetrevision](https://github.com/meetrevision/revision-tool)
- **MinSudo** — TrustedInstaller elevation by [M2Team](https://github.com/M2Team/NanaRun)
- **RemoveEdge** — Edge uninstaller from XOS Playbook
- **TinyRetroPad** — lightweight Notepad replacement by [Plummer's Software LLC](https://github.com/PlummersSoftwareLLC/TinyRetroPad)

---
## 🧹 Final Words

This is my last Windows project. I've moved full-time to CachyOS and the Linux gaming ecosystem. Forged is meant to be the "get in, play your kernel-level game, get out" Windows install – no fluff, no tracking, just performance.

— fernbacher
