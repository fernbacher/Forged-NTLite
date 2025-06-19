# Forged Windows 11 - Extreme Debloat & Performance 

**Forged Windows 11** is a stripped-down, aggressively optimized Windows 11 24H2 build for dedicated gaming and special-purpose PCs. This project removes bloat, disables telemetry, maximizes system performance, and applies privacy-focused settings. It is intended for isolated, non-production systems where security trade-offs are acceptable.

## Features

- **Massive Debloat**: Removes dozens of built-in apps NTLite (see `ntlite.xml`).
- **Aggressive Optimization**: Disables Spectre/Meltdown mitigations, UAC, unnecessary services, and scheduled tasks.
- **Privacy Hardening**: Applies deep anti-telemetry and anti-tracking registry tweaks.
- **Performance Tweaks**: Enables Ultimate Performance power plan, tunes NTFS, BCDEdit, and network stack.
- **UI Customization**: Sets classic Start Menu (Open-Shell), disables search/taskbar clutter, applies custom wallpaper.
- **System Cleanup**: Clears event logs, Windows Update, default themes, and temporary files.
- **Self-Destruct/Reboot**: Script wipes itself and reboots after applying all changes.

## Usage

1. **Create ISO**: Use `ntlite.xml` with NTLite to generate a Forged Windows 11 ISO.
2. **Integrate:** `MinSudo.exe`, `Forged.png` and the `Forge-PostInstall.ps1` in `C:\Windows\Tools` folder.
3. **Install Windows**: Deploy the ISO to your target PC.
4. **First Login**: Run `Forge-PostInstall.ps1` as the first user. The script will:
   - Apply user and system-wide tweaks
   - Install essentials (Open-Shell, Firefox)
   - Escalate privileges as needed
   - Reboot when finished

> **Warning:** This build disables critical security features. Do NOT use on production or daily-driver PCs.

## Requirements

- Windows 11 24H2 x64
- NTLite for ISO creation
- Isolated, disposable, or gaming system

## Files

- `ntlite.xml` – Debloat preset for NTLite
- `Forge-PostInstall.ps1` – Post-install optimization script
- `Forged.png` - For the wallpaper
---
**For advanced users only. You assume all risks.**
