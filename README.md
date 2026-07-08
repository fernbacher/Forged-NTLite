# ⚙️ Forged – Windows 11 Gaming ISO Builder (Linux-Native)

> The last Windows project I'll ever make.  
> Forged is a Linux-native toolchain that builds a debloated, gaming‑focused Windows 11 ISO without touching NTLITE or any Windows‑only tools. It's designed for dual‑booters who only keep Windows around for games that refuse to run on Linux (anti‑cheat, kernel-level DRM, etc.).  
> 🔗 My CachyOS optimizations live here: [fernbacher/cachyos-optimization](https://github.com/fernbacher/cachyos-optimization)

---

## Who Is This For?

- People who dual‑boot **CachyOS (or any Linux)** and Windows 11.
- Gamers who need Windows only for titles like *Valorant*, *Fortnite*, *PUBG*, *League of Legends*, *Faceit* – anything with kernel anti‑cheat.
- Users who want a **minimal, performance‑first Windows** with zero bloat, no telemetry, no Defender, no Edge and zero Microsoft account nonsense.
- Anyone who wants to build the ISO **from Linux** without owning a Windows machine.

---

## What Does Forged Do?

- **Single‑pass ISO builder** – extracts your Windows 11 ISO, keeps only the **Pro** edition, deletes every other edition.
- **Offline AppX debloat** – physically removes bloatware packages from the WIM **before** Windows ever boots (Bing, Xbox, Teams, Clipchamp, Store, etc.).
- **Registry hardening merged from four legendary sources**:
  - [ValleyOfDoom/PC-Tuning](https://github.com/ValleyOfDoom/PC-Tuning)
  - [djdallmann/GamingPCSetup](https://github.com/djdallmann/GamingPCSetup)
  - [XOS Playbook](https://github.com/amitxv/Ameliorated) (via Ameliorated)
  - [Revision Playbook](https://github.com/amitxv/ReviOS) (via ReviOS)
- **TrustedInstaller post‑install script** – runs on first logon to annihilate Defender, remove Edge (via its own uninstaller), disable ~100 scheduled tasks, kill telemetry, set up the Ultimate Performance power plan, and more.
- **Fully automated** – places `autounattend.xml` at ISO root to bypass TPM/SecureBoot, create a local admin user, skip OOBE privacy screens, and auto‑launch the Forged script.

---

## 📦 What You Get

```

forged-iso-build/
├── forge-iso.sh                 # Main Linux ISO builder (Bash)
├── autounattend.xml             # Windows unattended setup (TPM bypass + OOBE skip)
├── payload/
│   ├── Forge-PostInstall.ps1    # Full post‑install script (13 phases)
│   ├── MinSudo.exe              # TrustedInstaller elevation tool
│   ├── RemoveEdge.ps1           # XOS Edge uninstaller (region spoof + own setup)
│   ├── onedrive.bat             # XOS OneDrive annihilation script
│   ├── taskbar.bat              # XOS taskbar cleanup script (runs on every logon)
│   ├── W11STARTMENU.ps1         # XOS start menu pin cleaner
│   ├── LayoutModification.xml   # Zero‑pins layout for new users
│   ├── driver-exclude.reg       # Prevents Windows Update from installing drivers
│   └── Forged.png               # Default wallpaper (optional)

```

---

## 🛠️ How to Build the ISO

### Prerequisites (Arch Linux / CachyOS)

```bash
sudo pacman -S p7zip wimlib libisoburn   # or equivalent on your distro
```

### Build

```
cd forged-iso-build
./forge-iso.sh /path/to/en-us_windows_11_consumer_editions_version_25h2_*.iso
# Output: ./Forged-Win11.iso
```

The script:

1. Extracts the ISO with `7z`
2. Finds the **Windows 11 Pro** index and exports only that edition (single‑pass, no multiple rebuilds)
3. Mounts the WIM with `wimlib-imagex`
4. Injects all payload files
5. Deletes bloatware folders offline
6. Commits changes
7. Builds a UEFI+BIOS hybrid ISO with `xorrisofs`

---

## 🖥️ Dual‑Boot with CachyOS (or any Linux)

Forged is built with dual‑boot in mind. Here’s a minimal recipe:

1. **Shrink your Linux partition** (or leave unallocated space) before installing.
2. **Install Forged Windows** to the empty space – the installer won't touch your Linux partitions if you choose manually.
3. **After installation**, Windows will likely override the boot order. Use your UEFI boot menu to choose your Linux bootloader (e.g., `systemd-boot`, `GRUB`, or `rEFInd`).
4. **Restore Linux as default** – on CachyOS, you can use `efibootmgr`:

```
sudo
```
5. **Set Windows UTC clock** – Forged already sets `RealTimeIsUniversal=1` in the registry, so your Linux and Windows clocks stay in sync.

> 💡 My CachyOS tuning repository: [fernbacher/cachyos-optimization](https://github.com/fernbacher/cachyos-optimization) – use it for a latency‑optimised kernel, ZRAM, scheduler tweaks, and more.

---

## ⚠️ Manual OneDrive Cleanup (Only Remaining Issue)

Due to time constraints, OneDrive may still reappear after reboot. The XOS `onedrive.bat` removes it during the post‑install phase, but Windows can sneak it back.

**If you see OneDrive after reboot, simply uninstall it.**

---

## 🔐 Security & Performance Trade‑Offs

- **Defender** – fully annihilated (services disabled, IFEO blocks, scheduled task re‑kills, TamperProtection=0). If you need real‑time protection, this is not for you.
- **Edge** – completely removed (browser + updater + DevTools). WebView2 Runtime is preserved for app compatibility.
- **UAC** – disabled (`EnableLUA=0`). You run everything as admin.
- **Windows Update** – paused until 2038, WSUS nulled, driver updates blocked. You can manually check for updates if needed but that will revert tweaks.
- **VBS / HVCI** – toggles on the desktop (`VBS-ON.bat` / `VBS-OFF.bat`) for anti‑cheat games that require it. Reboot after toggling.

---

## 📜 License & Credits

- **Forged** is a personal project – use at your own risk.
- All registry and service lists are derived from the incredible work of:

- ValleyOfDoom (PC‑Tuning)
- djdallmann (GamingPCSetup)
- XOS / imribiy
- ReviOS / Revision team

---

## 🧹 Final Words

This is my last Windows project. I’ve moved full‑time to CachyOS and the Linux gaming ecosystem. Forged is meant to be the “get in, play your kernel‑level game, get out” Windows install – no fluff, no tracking, just performance.

If you find it useful, star the repo and share it with fellow dual‑booters.
If you have issues, open an issue – but I can’t promise fast replies.

— fernbacher

```
