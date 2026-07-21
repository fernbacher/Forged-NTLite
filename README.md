# ⚙️ [Forged](https://forgedapp.surge.sh/)
```

Forged/
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

### Build

```
git clone https://github.com/fernbacher/Forged.git
cd Forged
```
```
./forge-iso.sh /path/to/windows.iso
```

The script:

1. Extracts the ISO with `7z`
2. Finds the **Windows 11/10 Pro** index and exports only that edition
3. Mounts the WIM with `wimlib-imagex`
4. Injects all payload files + AppX debloat offline
5. Commits changes
6. Builds a UEFI+BIOS hybrid ISO with `xorrisofs`

Example output: `Forged-Win11.iso` in the `Forged/` directory.

---

## Dual-Boot with CachyOS (or any Linux)

1. **Shrink your Linux partition** (or use a separate drive) before installing.
2. **Install Forged Windows** to the empty space or separate drive. The installer won't touch your Linux partitions.
3. **After installation**, Windows will override the boot order. Use your UEFI boot menu to choose your Linux bootloader.
4. **Windows UTC clock** — Forged sets `RealTimeIsUniversal=1` so your Linux and Windows clocks stay in sync.

For Limine users: [adding a Windows entry](https://forgedapp.surge.sh/dual-boot.html) takes two commands.

---

## Recommendations Once You're on Forged

- Install [dotNetFx35](https://github.com/abbodi1406/dotNetFx35W10/releases) on Windows 10
- Use [Alt App Installer](https://github.com/mjishnu/alt-app-installer) to install NVIDIA Control Panel without the Microsoft Store (use `https://apps.microsoft.com/detail/9nf8h0h7wmlt?hl=en-US&gl=RO`)
- Install [VC Redist](https://github.com/abbodi1406/vcredist) and [DirectX](https://www.microsoft.com/en-US/download/details.aspx?id=35)
- Install [Open-Shell](https://github.com/Open-Shell/Open-Shell-Menu/releases) on Windows 11, I recommend [this skin](https://www.classicshell.net/forum/viewtopic.php?f=17&t=8469)

Do this and you'll have a flawless experience on a Forged Windows install for your games that don't run on Linux.

---

## Security & Performance Trade-Offs

- **Defender** — fully annihilated (services disabled Start=4, TamperProtection=0, DisableAntiSpyware=1, scheduled task re-kills, boot-time safety task, IFEO blocks). If you need real-time protection, this is not for you.
- **Edge** — completely removed (browser + updater + DevTools). WebView2 Runtime preserved for app compatibility.
- **UAC** — disabled (`EnableLUA=0`). Everything runs as admin.
- **Windows Update** — paused until 2038, WSUS nulled, driver updates blocked. Manual update checks may revert tweaks.
- **VBS / HVCI** — toggle scripts on desktop (`VBS-ON.bat` / `VBS-OFF.bat`). Required for any kernel anti-cheat that doesn't work on Linux (Valorant, FACEIT, etc.). Exception: League of Legends doesn't need it. Not required on Windows 10.

---

## Website

Documentation, build guide, dual-boot instructions, and a live source code viewer at **[forged.sh](https://forged.sh)**.

---

## Pre-Built ISOs

Pre-built ISOs are **Discord-exclusive** and will only ever be shared there. It's recommended to use the ISO builder on Linux if you want a specific Windows version (like LTSC Windows 10 or an older Windows 11 version). Browsers are not included, bring your own on a USB drive.

---

## License & Credits

- **Forged** is a personal project — use at your own risk.
- All registry and service lists are derived from the work of:

- [ValleyOfDoom — PC-Tuning](https://github.com/ValleyOfDoom/PC-Tuning)
- [djdallmann — GamingPCSetup](https://github.com/djdallmann/GamingPCSetup)
- [XOS Playbook by imribiy](https://discord.gg/XTYEjZNPgX)
- [Revision](https://revi.cc/)
- **MinSudo** — TrustedInstaller elevation by [M2Team](https://github.com/M2Team/NanaRun)
- **RemoveEdge** — Edge uninstaller from XOS Playbook
- **TinyRetroPad** — lightweight Notepad replacement by [Plummer's Software LLC](https://github.com/PlummersSoftwareLLC/TinyRetroPad)

---

## Final Words

This is my last Windows project. I've moved full-time to CachyOS and the Linux gaming ecosystem. Forged is meant to be the "get in, play your kernel-level game, get out" Windows install — no fluff, no tracking, just performance.

— fernbacher

