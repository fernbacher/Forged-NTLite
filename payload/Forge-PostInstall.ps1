<#
    ================================================================================================================
    FORGED -- Post-Installation Optimization Script for Windows 11/10
    Version: 2.2 (Linux ISO Builder Edition)
    ================================================================================================================

    DESCRIPTION:
    Runs automatically on first logon (via autounattend.xml FirstLogonCommand).
    Applies aggressive gaming-focused optimizations merged from:
      - ValleyOfDoom (registry framework)
      - djdallmann/GamingPCSetup (services, scheduler, NTFS)
      - XOS Playbook (Defender annihilation, Edge removal, kernel tweaks)
      - Revision Playbook (comprehensive registry hardening)

    WARNING:
    Disables all security features including Defender, SmartScreen, UAC, VBS,
    Spectre/Meltdown mitigations. For dedicated gaming machines ONLY.
    The user assumes all risks.
#>

#=======================================================================================================================
# PHASE 0: PREAMBLE, LOGGING, AND TRUSTEDINSTALLER ELEVATION
#=======================================================================================================================

$ErrorActionPreference = "SilentlyContinue"
Try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop } Catch {}

$LogFile = "$env:USERPROFILE\Desktop\Forged_Optimization_Log.txt"
$ToolsPath = "C:\Windows\Setup\Scripts"
$MinSudoPath = Join-Path $ToolsPath "MinSudo.exe"
$WallpaperPath = "C:\Windows\Web\Wallpaper\Forged\Forged.png"
$ScriptName = $MyInvocation.MyCommand.Name
$ScriptPath = $MyInvocation.MyCommand.Path

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Level] - $Message"
    switch ($Level) {
        "INFO"   { Write-Host $LogEntry -ForegroundColor Green }
        "WARN"   { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"  { Write-Host $LogEntry -ForegroundColor Red }
        "HEADER" { Write-Host "`n$(('='*80))`n$Message`n$(('='*80))" -ForegroundColor Cyan }
        default  { Write-Host $LogEntry }
    }
    Try { Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue } Catch {}
}

# Initialize log
if (Test-Path $LogFile) { Remove-Item $LogFile -Force -ErrorAction SilentlyContinue }
Try { New-Item -Path $LogFile -ItemType File -Force | Out-Null } Catch {}
Write-Log -Level HEADER -Message "Initializing Forged Post-Installation Optimization Script v2.0"
Write-Log -Message "All operations logged to: $LogFile"

# --- TrustedInstaller execution helper ---
function Invoke-TI {
    param(
        [Parameter(Mandatory=$true)][string]$Command,
        [switch]$IgnoreErrors
    )
    if (-not (Test-Path $MinSudoPath)) {
        Write-Log -Level ERROR -Message "MinSudo.exe not found at $MinSudoPath."
        Start-Sleep -Seconds 10
        Exit 1
    }
    $ArgumentList = "--NoLogo -TI -P -- $Command"
    Try {
        $proc = Start-Process -FilePath $MinSudoPath -ArgumentList $ArgumentList -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
        if ($proc.ExitCode -ne 0 -and -not $IgnoreErrors) {
            Write-Log -Level WARN -Message "TI exit=$($proc.ExitCode): $($Command.Substring(0, [Math]::Min(70, $Command.Length)))"
        }
    } Catch {
        if (-not $IgnoreErrors) {
            Write-Log -Level ERROR -Message "TI crashed: $($Command.Substring(0, [Math]::Min(70, $Command.Length)))"
        }
    }
}

function Invoke-TI-Quiet {
    param([Parameter(Mandatory=$true)][string]$Command)
    Invoke-TI -Command $Command -IgnoreErrors
}

function Get-CurrentUserName {
    try { return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
    catch { return $env:USERNAME }
}

$CurrentUser = Get-CurrentUserName

function Set-RegValue {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][string]$Name,
        [Parameter(Mandatory=$true)]$Value,
        [Parameter(Mandatory=$true)][string]$Type
    )
    Try {
        if (-not (Test-Path "Registry::$Path")) {
            New-Item -Path "Registry::$Path" -Force | Out-Null
        }
        if ($Name) {
            Set-ItemProperty -Path "Registry::$Path" -Name $Name -Value $Value -Type $Type -Force -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path "Registry::$Path" -Name '(default)' -Value $Value -Type $Type -Force
        }
    } Catch {
        Try {
            if ($Name) {
                Invoke-TI "reg add `"$Path`" /v `"$Name`" /t $Type /d `"$Value`" /f"
            } else {
                Invoke-TI "reg add `"$Path`" /ve /t $Type /d `"$Value`" /f"
            }
        } Catch {}
    }
}

function Remove-RegKey {
    param([Parameter(Mandatory=$true)][string]$Path)
    Try {
        if (Test-Path "Registry::$Path") { Remove-Item -Path "Registry::$Path" -Recurse -Force -ErrorAction SilentlyContinue }
    } Catch {}
}

function Remove-RegValue {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Name)
    Try {
        if (Test-Path "Registry::$Path") { Remove-ItemProperty -Path "Registry::$Path" -Name $Name -Force -ErrorAction SilentlyContinue }
    } Catch {}
}

# --- quick version check helpers ---
$BuildNumber = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
$WinVer = $BuildNumber

function If-BuildMin([int]$Min) { return $WinVer -ge $Min }
function If-BuildMax([int]$Max) { return $WinVer -le $Max }
function If-Build([int]$Min, [int]$Max) { return $WinVer -ge $Min -and $WinVer -le $Max }

#=======================================================================================================================
# PHASE 1: RUN AS CURRENT USER (per-user tweaks, then escalate to SYSTEM)
#=======================================================================================================================

if ($CurrentUser -match "^NT AUTHORITY\\(SYSTEM|TrustedInstaller)$") {
    Write-Log -Message "Already running as $CurrentUser -- proceeding to system-wide phase."
} else {
    Write-Log -Level HEADER -Message "PHASE 1: User-Context Setup"

    # --- HKCU registry tweaks ---
    Write-Log -Message "Applying HKCU registry tweaks..."

    # Taskbar cleanup
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type "DWord"
    # Hide MeetNow (Skype meeting) icon on taskbar (Windows 10 20H1+)
    # Must use "HideSCAMeetNow" -- "HideMeetingBar" is the wrong key and doesn't work
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -Type "DWord"

    # Notification & tray: block balloon ads, prevent auto-hiding tray icons (Revision)
    Set-RegValue -Path "HKCU\Software\Policies\Microsoft\Windows\Explorer" -Name "NoBalloonFeatureAdvertisements" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Policies\Microsoft\Windows\Explorer" -Name "NoAutoTrayNotify" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0 -Type "DWord"
Get-Service -Name "WpnUserService*" | Restart-Service -Force -ErrorAction SilentlyContinue
    # Hide People bar from taskbar (Win10)
    Set-RegValue -Path "HKCU\Software\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Value 1 -Type "DWord"
    # Suppress "Let's finish setting up your device" nag (Scoobe)
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Context\CloudExperienceHostIntent\Wireless" -Name "ScoobeCheckCompleted" -Value 1 -Type "DWord"
    # Hide OneDrive sync provider ads in Explorer
    Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type "DWord"
    # Suppress unsupported hardware notification (watermark on desktop)
    Set-RegValue -Path "HKCU\Control Panel\UnsupportedHardwareNotificationCache" -Name "SV1" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Control Panel\UnsupportedHardwareNotificationCache" -Name "SV2" -Value 0 -Type "DWord"
    # Remove 3D Objects folder from This PC sidebar (XOS)
    Remove-RegKey -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    Remove-RegKey -Path "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"

    # Classic context menu
    $CCMKey = "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    Try { New-Item -Path "Registry::$CCMKey" -Force | Out-Null; Set-ItemProperty -Path "Registry::$CCMKey" -Name '(default)' -Value "" -Force } Catch {}

    # Mouse acceleration OFF
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -Type "String"
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -Type "String"
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -Type "String"

    # File extensions shown
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type "DWord"

    # Transparency off
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type "DWord"

    # Search: disable Bing, disable suggestions
    # Content Delivery Manager: block all ad suggestions (WhatsApp, LinkedIn, etc.)
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Value 0 -Type "DWord"
    # CDM master switch + additional ad channels (Revision audit)
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280815Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314563Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-202914Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280810Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-280811Enabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RemediationRequired" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -Name "DisableSearchBoxSuggestions" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type "DWord"

    # Start menu recommendations off
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_NotifyNewApps" -Value 0 -Type "DWord"

    # Clipboard history off
    Set-RegValue -Path "HKCU\Software\Microsoft\Clipboard" -Name "CloudClipboardAutomaticUpload" -Value 0 -Type "DWord"

    # Advertising ID off
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type "DWord"

    # Widgets off
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type "DWord"
    # Feeds/Widgets: use direct HKCU (NOT via TI -- that writes to SYSTEM's hive)
    Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2 -Type "DWord"

    # Sticky keys off
    Set-RegValue -Path "HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type "String"

    # --- Wallpaper ---
    if (Test-Path $WallpaperPath) {
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "Wallpaper" -Value $WallpaperPath -Type "String"
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10" -Type "String"
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "TileWallpaper" -Value "0" -Type "String"
        # Use RunOnce for reliable wallpaper apply after desktop is fully loaded
        Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ForgedWallpaper" -Value "RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters" -Type "String"
        Write-Log -Message "Wallpaper set (applies after next logon)."
    }

    # Taskbar + Start Menu cleanup (XOS approach)
    $taskbarBat = "$ToolsPath\taskbar.bat"
    if (Test-Path $taskbarBat) {
        # Copy to Startup folder so it runs on every logon
        $startupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        Try { Copy-Item $taskbarBat $startupDir -Force } Catch {}
        # Run immediately too
        Try { Start-Process $taskbarBat -Wait -NoNewWindow -ErrorAction SilentlyContinue } Catch {}
    }
    $w11sm = "$ToolsPath\W11STARTMENU.ps1"
    if (Test-Path $w11sm) {
        Try { & $w11sm } Catch {}
        Write-Log -Message "Taskbar and Start Menu cleaned."
    }

    # Disable GameDVR
    Set-RegValue -Path "HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type "DWord"

    # NVIDIA telemetry OFF (Revision)
    Set-RegValue -Path "HKCU\Software\NVIDIA Corporation\NVControlPanel2\Client" -Name "OptInOrOutPreference" -Value 0 -Type "DWord"
    # EdgeUI: disable Most Frequently Used app tracking (Revision)
    Set-RegValue -Path "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Value 1 -Type "DWord"

    # OneDrive removal: run XOS onedrive.bat
    $onedriveBat = "$ToolsPath\onedrive.bat"
    if (Test-Path $onedriveBat) {
        Try { Start-Process $onedriveBat -Wait -NoNewWindow -ErrorAction SilentlyContinue } Catch {}
        Write-Log -Message "OneDrive removal executed."
    }

    # OneDrive permanent prevention -- block reinstall via registry policy paths
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type "DWord"

    # --- Install TinyRetroPad + remove Windows Notepad (user context) ---
    $trpadSrc = "$ToolsPath\trpad.exe"
    $trpadDest = "$env:SystemRoot\System32\trpad.exe"
    if (Test-Path $trpadSrc) {
        Copy-Item $trpadSrc $trpadDest -Force
        # Register system-wide .txt association via ftype/assoc
        cmd /c "ftype trpad=$trpadDest `"%1`"" 2>$null | Out-Null
        cmd /c "assoc .txt=trpad" 2>$null | Out-Null
        Write-Log -Message "TinyRetroPad installed to System32, set as default .txt editor."
    } else {
        Write-Log -Level WARN -Message "trpad.exe not found -- TinyRetroPad skipped."
    }
    # Remove Windows Notepad AppX
    Try {
        Get-AppxPackage -AllUsers "*Microsoft.WindowsNotepad*" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.PackageName -like "*Microsoft.WindowsNotepad*" } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-Log -Message "Windows Notepad removed."
    } Catch { Write-Log -Level WARN -Message "Notepad removal failed (may already be gone)." }


    # Create VBS toggle scripts on desktop (anti-cheat games)
    @"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
bcdedit /set hypervisorlaunchtype auto
echo VBS enabled. REBOOT REQUIRED.
pause
"@ | Set-Content -Path "$env:USERPROFILE\Desktop\VBS-ON.bat" -Force
    @"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
bcdedit /set hypervisorlaunchtype off
echo VBS disabled. REBOOT REQUIRED.
pause
"@ | Set-Content -Path "$env:USERPROFILE\Desktop\VBS-OFF.bat" -Force
    Write-Log -Message "VBS toggle scripts created on desktop."

    # --- Escalate to SYSTEM/TrustedInstaller ---
    Write-Log -Message "Escalating to SYSTEM for system-wide optimizations..."
    $PowerShellPath = (Get-Command powershell.exe).Source
    Invoke-TI "`"$PowerShellPath`" -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    Exit
}

Write-Log -Message "Executing system-wide phase as: $CurrentUser"
Write-Log -Level HEADER -Message "PHASE 2: Defender Annihilation"

#=======================================================================================================================
# PHASE 2: DEFENDER ANNIHILATION (XOS approach -- full destruction)
#=======================================================================================================================

# Disable Tamper Protection (must be first)
Invoke-TI 'reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f'

# Policy disable keys
Invoke-TI 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'
Invoke-TI 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f'
Invoke-TI 'reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'
Invoke-TI 'reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f'

# Stop defender services
$DefenderServices = @("WinDefend","WdNisSvc","WdFilter","WdBoot","WdNisDrv","Sense","wscsvc","SecurityHealthService","MsSecCore","MsSecWfp","MsSecFlt","SgrmBroker","wtd","webthreatdefusersvc","webthreatdefsvc","MDCoreSvc")
foreach ($svc in $DefenderServices) {
    Invoke-TI-Quiet "sc.exe stop $svc"
    Invoke-TI "reg add `"HKLM\SYSTEM\CurrentControlSet\Services\$svc`" /v Start /t REG_DWORD /d 4 /f"
}
Write-Log -Message "Defender services stopped and disabled."

# Wait for MsMpEng.exe to exit
Write-Log -Message "Waiting for MsMpEng.exe to exit..."
$timeout = 30
while ((Get-Process -Name "MsMpEng" -ErrorAction SilentlyContinue) -and $timeout -gt 0) {
    Start-Sleep -Seconds 1; $timeout--
}
if (Get-Process -Name "MsMpEng" -ErrorAction SilentlyContinue) {
    Try { Stop-Process -Name "MsMpEng" -Force -ErrorAction SilentlyContinue } Catch {}
}

# IFEO block SmartScreen
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe" -Name "Debugger" -Value "%SYSTEMROOT%\System32\taskkill.exe" -Type "String"
Try { Stop-Process -Name "smartscreen" -Force -ErrorAction SilentlyContinue } Catch {}

# IFEO block DeviceCensus
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Name "Debugger" -Value "%SYSTEMROOT%\System32\taskkill.exe" -Type "String"

# XOS approach: rename MpCmdRun.exe to OFFmeansOFF.exe (physically prevents Defender scanner)
Invoke-TI 'cmd.exe /c "for /r "%ProgramFiles%\Windows Defender" %f in (MpCmdRun.exe) do @if exist "%f" ren "%f" OFFmeansOFF.exe"'


# Remove SecurityHealth and WindowsDefender from Run
Remove-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth"
Remove-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender"

# Disable Defender scheduled tasks
$DefenderTasks = @(
    '\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance',
    '\Microsoft\Windows\Windows Defender\Windows Defender Cleanup',
    '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan',
    '\Microsoft\Windows\Windows Defender\Windows Defender Verification',
    '\Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh'
)
foreach ($task in $DefenderTasks) {
    Invoke-TI "schtasks /change /tn `"$task`" /disable"
}

# Disable Defender ETW loggers
Invoke-TI 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v Start /t REG_DWORD /d 0 /f'
Invoke-TI 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v Start /t REG_DWORD /d 0 /f'

# WTDS Components disable
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" -Name "ServiceEnabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" -Name "NotifyMalicious" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" -Name "NotifyPasswordReuse" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" -Name "NotifyUnsafeApp" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "ServiceEnabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyMalicious" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyPasswordReuse" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyUnsafeApp" -Value 0 -Type "DWord"

# SmartScreen off
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type "String"
Set-RegValue -Path "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type "String"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type "DWord"
Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type "DWord"
# (default) value of this key -- Set-RegValue with no -Name writes to (default)
Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" -Value 0 -Type "DWord"

# Real-Time Protection policy disable (belt-and-suspenders alongside service kill)
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type "DWord"

# SpyNet: stop cloud sample submission
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0 -Type "DWord"

# VBS/HVCI off
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState" -Value 0 -Type "DWord"

# Hide Windows Security systray + suppress "Turn on" notifications
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableNotifications" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableEnhancedNotifications" -Value 1 -Type "DWord"

# Create boot-time safety task to keep defender dead + OneDrive nuked + Copilot blocked + BitLocker off
$BootSafetyScript = @'
sc.exe stop MDCoreSvc; sc.exe stop WinDefend; sc.exe stop WdNisSvc; Start-Sleep -Seconds 5;
reg add HKLM\SYSTEM\CurrentControlSet\Services\WinDefend /v Start /t REG_DWORD /d 4 /f;
reg add HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc /v Start /t REG_DWORD /d 4 /f;
reg add HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc /v Start /t REG_DWORD /d 4 /f;
reg add HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv /v Start /t REG_DWORD /d 4 /f;
reg add HKLM\SYSTEM\CurrentControlSet\Services\WdBoot /v Start /t REG_DWORD /d 4 /f;
reg add HKLM\SYSTEM\CurrentControlSet\Services\WdFilter /v Start /t REG_DWORD /d 4 /f;
rem ---- OneDrive: kill processes, block services, prevent reinstall ----
taskkill /f /im OneDrive.exe >nul 2>&1;
taskkill /f /im OneDrive.App.exe >nul 2>&1;
taskkill /f /im FileCoAuth.exe >nul 2>&1;
sc.exe stop OneDriveUpdaterService 2>nul;
sc.exe delete OneDriveUpdaterService 2>nul;
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f;
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive /v DisableFileSync /t REG_DWORD /d 1 /f;
rem ---- Copilot: kill processes, block via IFEO ----
taskkill /f /im Copilot.exe 2>nul;
taskkill /f /im CopilotNative.exe 2>nul;
taskkill /f /im CopilotHost.exe 2>nul;
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Copilot.exe" /v Debugger /t REG_SZ /d "%SYSTEMROOT%\System32\taskkill.exe" /f;
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CopilotNative.exe" /v Debugger /t REG_SZ /d "%SYSTEMROOT%\System32\taskkill.exe" /f;
rem ---- BitLocker: keep it dead ----
reg add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f;
sc.exe stop BDESVC 2>nul;
sc.exe config BDESVC start= disabled 2>nul;
rem ---- Driver updates: keep blocked ----
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f;
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f;
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f;
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f;
schtasks /delete /tn Forged-DefenderDisable /f;
Remove-Item -Path "C:\Windows\Forged-DD.ps1" -Force -ErrorAction SilentlyContinue
'@
[System.IO.File]::WriteAllText('C:\Windows\Forged-DD.ps1', $BootSafetyScript)
Invoke-TI 'schtasks /create /ru SYSTEM /rl HIGHEST /sc ONSTART /tn Forged-DefenderDisable /tr "powershell.exe -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Forged-DD.ps1" /f'
Write-Log -Message "Boot-time defender safety task created."

Write-Log -Message "Defender annihilation complete."

#=======================================================================================================================
# PHASE 3: EDGE REMOVAL (XOS approach - uses Edge own uninstaller via EU region spoof)
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 3: Microsoft Edge Removal"

$RemoveEdgeScript = "$ToolsPath\RemoveEdge.ps1"
if (Test-Path $RemoveEdgeScript) {
    # Stop Edge processes
    @("MicrosoftEdgeUpdate","msedge","msedgewebview2","setup") | ForEach-Object {
        Try { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue } Catch {}
    }
    # Delete Edge services
    @("edgeupdate","edgeupdatem","MicrosoftEdgeElevationService") | ForEach-Object {
        Invoke-TI-Quiet "sc.exe stop $_"
        Invoke-TI-Quiet "sc.exe delete $_"
    }
    # Delete Edge scheduled tasks
    @('\MicrosoftEdgeUpdateTaskMachineCore','\MicrosoftEdgeUpdateTaskMachineUA') | ForEach-Object {
        Invoke-TI-Quiet "schtasks /delete /tn `"$_`" /f"
    }

    # XOS RemoveEdge: spoof EU, run Edge own uninstaller, restore region
    Try {
        & $RemoveEdgeScript -Action SpoofRegion
        & $RemoveEdgeScript -Action Browser
        & $RemoveEdgeScript -Action Runtime
        & $RemoveEdgeScript -Action Updater
        & $RemoveEdgeScript -Action RestoreRegion
        Write-Log -Message "Edge uninstalled via XOS RemoveEdge."
    } Catch {
        Write-Log -Level WARN -Message "RemoveEdge script failed: $_"
    }

    # EdgeUpdate policies: block reinstall, allow WebView2
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "InstallDefault" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "UpdateDefault" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -Type "DWord"
    foreach ($guid in @("{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}","{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}","{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}","{65C35B14-6C1D-4122-AC46-7148CC9D6497}")) {
        Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Install$guid" -Value 0 -Type "DWord"
        Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Update$guid" -Value 0 -Type "DWord"
    }
    $WebView2GUID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Install$WebView2GUID" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Update$WebView2GUID" -Value 1 -Type "DWord"
} else {
    Write-Log -Level WARN -Message "RemoveEdge.ps1 not found at $RemoveEdgeScript"
}

Write-Log -Message "Edge removal complete. WebView2 preserved."

#=======================================================================================================================
# PHASE 4: SERVICE DEBLOAT
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 4: Service Debloat"

$ServicesToDisable = @(
    # Telemetry & diagnostics
    "DiagTrack", "diagsvc", "diagnosticshub.standardcollector.service", "dmwappushservice", "WerSvc", "wercplsupport",
    # Xbox / gaming overlay
    "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
    # Location & maps
    "lfsvc", "MapsBroker",
    # Printing (gaming machine -- no printers)
    "Spooler", "PrintNotify", "printworkflowusersvc", "stisvc",
    # Phone & mobile
    "PhoneSvc", "icssvc", "RmSvc",
    # Sensors
    "SensorDataService", "SensorService", "SensrSvc",
    # Remote
    "RemoteRegistry", "TermService", "UmRdpService", "SessionEnv", "RemoteAccess",
    # Sharing & discovery
    "SSDPSRV", "upnphost", "SharedAccess", "lltdsvc",
    # Search indexing
    "WSearch",
    # Windows Update
    "wuauserv", "UsoSvc", "WaaSMedicSvc", "wisvc",
    # Misc bloat
    "RetailDemo", "SysMain", "SEMgrSvc", "DPS", "DoSvc", "PcaSvc",
    "WdiServiceHost", "WdiSystemHost", "troubleshootingsvc", "svsvc",
    "WalletService", "MessagingService", "OneSyncSvc",
    "PeerDistSvc", "CscService", "UevAgentService", "AppVClient",
    "NetTcpPortSharing", "SCardSvr", "ScDeviceEnum", "ShellHWDetection",
    "QWAVE", "FrameServer", "wisvc", "MSDTC", "midisrv",
    "McpManagementService",
    # Kernel drivers
    "dam", "GpuEnergyDrv", "NetBT", "tcpipreg", "UCPD", "Ndu", "GraphicsPerfSvc",
    "bttflt", "gencounter", "hyperkbd", "hypervideo", "vmgid", "vpci", "vid",
    "amdfendr", "amdfendrmgr",
    # Copilot / AI
    "MicrosoftCopilotElevationService", "MicrosoftCopilotService",
    "InventorySvc", "WSAIFabricSvc",
    # BitLocker
    "BDESVC"
)

$ServicesToManual = @(
    "bthserv", "BluetoothUserService", "BthAvctpSvc", "hidserv", "TabletInputService"
)

foreach ($service in $ServicesToDisable) {
    Try {
        Invoke-TI-Quiet "sc.exe stop $service"
        Invoke-TI-Quiet "sc.exe config $service start= disabled"
        Write-Log -Message "Disabled: $service"
    } Catch { Write-Log -Level WARN -Message "Service $service not present." }
}

foreach ($service in $ServicesToManual) {
    Try {
        Invoke-TI-Quiet "sc.exe config $service start= demand"
        Write-Log -Message "Set manual: $service"
    } Catch { Write-Log -Level WARN -Message "Service $service not present." }
}

Write-Log -Message "Service debloat complete."

#=======================================================================================================================
# PHASE 5: SCHEDULED TASK DEBLOAT
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 5: Scheduled Task Debloat"

$TasksToDisable = @(
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan',
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task',
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Work',
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work',
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work',
    '\Microsoft\Windows\UpdateOrchestrator\Report policies',
    '\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan',
    '\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted',
    '\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_OobeAppReady',
    '\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask',
    '\Microsoft\Windows\UpdateOrchestrator\UIEOrchestrator',
    '\Microsoft\Windows\UpdateOrchestrator\USO_Broker_Display',
    '\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display',
    '\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot',
    '\Microsoft\Windows\UpdateOrchestrator\Universal Orchestrator Start',
    '\Microsoft\Windows\UpdateOrchestrator\Universal Orchestrator Idle Start',
    '\Microsoft\Windows\UpdateOrchestrator\Reboot',
    '\Microsoft\Windows\UpdateOrchestrator\Reboot_AC',
    '\Microsoft\Windows\UpdateOrchestrator\Reboot_Battery',
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan',
    '\Microsoft\Windows\UpdateOrchestrator\Resume On Boot',
    '\Microsoft\Windows\UpdateOrchestrator\Refresh Settings',
    '\Microsoft\Windows\UpdateOrchestrator\Policy Install',
    '\Microsoft\Windows\UpdateOrchestrator\Maintenance Install',
    '\Microsoft\Windows\UpdateOrchestrator\Driver Install',
    '\Microsoft\Windows\UpdateOrchestrator\AC Power Download',
    '\Microsoft\Windows\UpdateOrchestrator\AC Power Install',
    '\Microsoft\Windows\UpdateOrchestrator\Backup Scan',
    '\Microsoft\Windows\UpdateOrchestrator\Battery Saver Deferred Install',
    '\Microsoft\Windows\UpdateOrchestrator\MusUx_LogonUpdateResults',
    '\Microsoft\Windows\UpdateOrchestrator\MusUx_UpdateInterval',
    '\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work',
    '\Microsoft\Windows\UpdateOrchestrator\UUS Failover Task',
    '\Microsoft\Windows\UpdateOrchestrator\UpdateAssistant',
    '\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantAllUsersRun',
    '\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantCalendarRun',
    '\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantWakeupRun',
    '\Microsoft\Windows\WaaSMedic\PerformRemediation',
    '\Microsoft\Windows\WindowsUpdate\Scheduled Start',
    '\Microsoft\Windows\WindowsUpdate\AUScheduledInstall',
    '\Microsoft\Windows\WindowsUpdate\AUSessionConnect',
    '\Microsoft\Windows\WindowsUpdate\Automatic App Update',
    '\Microsoft\Windows\WindowsUpdate\RUXIM\PLUGScheduler',
    '\Microsoft\Windows\WindowsUpdate\Scheduled Start With Network',
    '\Microsoft\Windows\WindowsUpdate\sih',
    '\Microsoft\Windows\WindowsUpdate\sihboot',
    '\Microsoft\Windows\WindowsUpdate\sihpostreboot',
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Application Experience\StartupAppTask',
    '\Microsoft\Windows\Application Experience\MareBackup',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\Customer Experience Improvement Program\BthSQM',
    '\Microsoft\Windows\Customer Experience Improvement Program\Uploader',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver',
    '\Microsoft\Windows\Windows Error Reporting\QueueReporting',
    '\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner',
    '\Microsoft\Windows\Diagnosis\Scheduled',
    '\Microsoft\Windows\Diagnosis\UnexpectedCodepath',
    '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem',
    '\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents',
    '\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic',
    '\Microsoft\Windows\MemoryDiagnostic\AutomaticOfflineMemoryDiagnostic',
    '\Microsoft\Windows\Registry\RegIdleBackup',
    '\Microsoft\Windows\Feedback\Siuf\DmClient',
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
    '\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan',
    '\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan',
    '\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery',
    '\Microsoft\Windows\DiskFootprint\Diagnostics',
    '\Microsoft\Windows\WDI\ResolutionHost',
    '\Microsoft\Windows\RetailDemo\CleanupOfflineContent',
    '\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask',
    '\Microsoft\Windows\SettingSync\NetworkStateChangeTask',
    '\Microsoft\Windows\SettingSync\BackgroundUploadTask',
    '\Microsoft\Windows\Maps\MapsToastTask',
    '\Microsoft\Windows\AccountHealth\RecoverabilityToastTask',
    '\Microsoft\Windows\Maintenance\WinSAT',
    '\Microsoft\Windows\PerformanceTrace\RequestTrace',
    '\Microsoft\Windows\PerformanceTrace\WhesvcToast',
    '\Microsoft\Windows\Shell\FamilySafetyMonitor',
    '\Microsoft\Windows\Shell\FamilySafetyRefreshTask',
    '\Microsoft\Windows\InstallService\RestoreDevice',
    '\Microsoft\Windows\InstallService\ScanForUpdates',
    '\Microsoft\Windows\InstallService\ScanForUpdatesAsUser',
    '\Microsoft\Windows\InstallService\SmartRetry',
    '\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates',
    '\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates',
    '\Microsoft\Windows\CloudRestore\Backup',
    '\Microsoft\Windows\CloudRestore\Restore',
    '\Microsoft\Windows\Sustainability\PowerGridForecastTask',
    '\Microsoft\Windows\Sustainability\SustainabilityTelemetry',
    '\Microsoft\Windows\Hotpatch\Monitoring',
    '\Microsoft\Windows\Autochk\Proxy',
    '\Microsoft\Windows\CloudExperienceHost\CreateObjectTask',
    '\Microsoft\Windows\UsageAndQualityInsights\UsageAndQualityInsights-MaintenanceTask',
    # BitLocker
    '\Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives',
    '\Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh'
)

foreach ($taskPath in $TasksToDisable) {
    Try {
        Invoke-TI "schtasks /change /tn `"$taskPath`" /disable"
    } Catch { }
}

# Disable Office tasks
Invoke-TI 'powershell.exe -NoProfile -Command "Get-ScheduledTask -TaskPath ''\Microsoft\Office\*'' -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue"'

# Windows AI / Recall / Copilot tasks
$AITasks = @(
    '\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration',
    '\Microsoft\Windows\WindowsAI\Settings\InitialConfiguration',
    '\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingIdle',
    '\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingLimit',
    '\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingUpdate',
    '\Microsoft\Windows\WindowsAI\Settings\ReconcileAIDataAnalysis',
    '\Microsoft\Windows\WindowsAI\Settings\PostUpgradeCompatibilityCheck',
    '\Microsoft\Windows\WindowsAI\Recall\ReconcileEnrollment'
)
foreach ($task in $AITasks) {
    Try { Invoke-TI "schtasks /change /tn `"$task`" /disable" } Catch {}
}

# Disable UCPD velocity task
Invoke-TI 'powershell.exe -NoProfile -Command "Disable-ScheduledTask -TaskPath ''\Microsoft\Windows\AppxDeploymentClient'' -TaskName ''UCPD velocity'' -ErrorAction SilentlyContinue"'

Write-Log -Message "Scheduled task debloat complete."

#=======================================================================================================================
# PHASE 6: POWER, BCDEDIT & PERFORMANCE
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 6: Power, BCDEdit & Performance"

# --- Power plan ---
# Ultimate Performance is a hidden template on non-Workstation editions.
# powercfg -duplicatescheme creates a copy with a NEW random GUID, so we
# must search by scheme NAME ("Ultimate Performance") not by known GUID.
$UltGUID   = "e9a42b02-d5df-448d-aa00-03f14749eb61"
$HighGUID  = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

# Duplicate Ultimate Performance template (silent if it already exists)
$null = powercfg -duplicatescheme $UltGUID 2>&1 | Out-Null
Start-Sleep -Milliseconds 500

# Find ANY scheme named "Ultimate Performance" (GUID may differ from template)
$allSchemes = powercfg /l 2>&1 | Out-String
$ultLine = ($allSchemes -split '\n' | Where-Object { $_ -match 'Ultimate Performance' } | Select-Object -First 1)

if ($ultLine) {
    # Extract the GUID from the matched line
    $foundGuid = ($ultLine -replace '.*GUID:\s*([a-fA-F0-9-]+).*', '$1').Trim()
    if ($foundGuid) {
        powercfg /setactive $foundGuid
        Write-Log -Message "Ultimate Performance power plan activated ($foundGuid)."
    }
} else {
    # Fall back to High Performance
    Try {
        powercfg /setactive $HighGUID
        Write-Log -Message "High Performance power plan activated (Ultimate Performance unavailable)."
    } Catch {
        Write-Log -Level WARN -Message "Could not set any performance power plan."
    }
}

# Core parking off
Try {
    powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
    powercfg -setacvalueindex scheme_current sub_processor CPMINCORES1 100
    powercfg -setactive scheme_current
    Write-Log -Message "Core parking disabled."
} Catch {}

# Power timeouts
Try {
    powercfg /x monitor-timeout-ac 0
    powercfg /x disk-timeout-ac 0
    powercfg /x standby-timeout-ac 0
    powercfg /x hibernate-timeout-ac 0
    powercfg /hibernate off
    Write-Log -Message "Power timeouts set, hibernation off."
} Catch {}

# --- BCDEdit ---
Invoke-TI "bcdedit /set disabledynamictick yes"
Invoke-TI "bcdedit /deletevalue useplatformclock"
Invoke-TI "bcdedit /deletevalue useplatformtick"
Invoke-TI "bcdedit /set hypervisorlaunchtype off"
Invoke-TI "bcdedit /set bootmenupolicy legacy"
Invoke-TI "bcdedit /timeout 10"
Write-Log -Message "BCDEdit optimizations applied."

#=======================================================================================================================
# PHASE 7: NTFS & KERNEL OPTIMIZATIONS
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 7: NTFS & Kernel Optimizations"

# NTFS
Invoke-TI "fsutil behavior set disablelastaccess 1"
Invoke-TI "fsutil behavior set disable8dot3 1"
Invoke-TI "fsutil behavior set disabledeletenotify 0"
Invoke-TI "fsutil behavior set encryptpagingfile 0"
Invoke-TI "fsutil behavior set memoryusage 1"
Write-Log -Message "NTFS optimized."

# Memory compression off
Invoke-TI 'powershell.exe -NoProfile -Command "Disable-MMAgent -mc -ErrorAction SilentlyContinue"'
Write-Log -Message "Memory compression disabled."

# Spectre/Meltdown mitigations off
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 3 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type "DWord"

# Disable page combining
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePageCombining" -Value 1 -Type "DWord"

# Disable DMA remapping
Try {
    $dmaKey = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy'
    if (-not (Test-Path $dmaKey)) { New-Item -Path $dmaKey -Force | Out-Null }
    Set-ItemProperty -Path $dmaKey -Name 'value' -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        $paramsPath = $_.PSPath + '\Parameters'
        if (Test-Path $paramsPath) {
            Try {
                $val = (Get-ItemProperty -Path $paramsPath -Name 'DmaRemappingCompatible' -ErrorAction SilentlyContinue).DmaRemappingCompatible
                if ($null -ne $val) { Set-ItemProperty -Path $paramsPath -Name 'DmaRemappingCompatible' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue }
            } Catch {}
        }
    }
} Catch {}

# Disable unnecessary desktop devices (chassis type check from XOS)
Try {
    $chassisType = 3
    $chassis = (Get-WmiObject -Class Win32_SystemEnclosure -ErrorAction SilentlyContinue).ChassisTypes
    if ($chassis -and $chassis.Length -gt 0) { $chassisType = [int]$chassis[0] }
    if ($chassisType -le 7) {
        @("ACPI Processor Aggregator","ACPI Wake Alarm","AMD Crash Defender","High Precision Event Timer","Intel(R) Platform Monitoring Technology Device") | ForEach-Object {
            Get-WmiObject -Class Win32_PnPEntity -Filter "Name LIKE '%$_%'" -ErrorAction SilentlyContinue | ForEach-Object {
                Try { $_.Disable() | Out-Null } Catch { pnputil /disable-device $_.DeviceID 2>$null | Out-Null }
            }
        }
    }
} Catch {}

# Enable MSI mode for controllers
Try {
    function Set-MSIForClass { param([string]$WmiClass, [int]$MsiValue)
        Get-WmiObject -Class $WmiClass -ErrorAction SilentlyContinue | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_*' } | ForEach-Object {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
            Try {
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                Set-ItemProperty -Path $regPath -Name 'MSISupported' -Value $MsiValue -Type DWord -Force -ErrorAction SilentlyContinue
            } Catch {}
        }
    }
    Set-MSIForClass 'Win32_IDEController' 1
    Set-MSIForClass 'Win32_VideoController' 1
    Set-MSIForClass 'Win32_NetworkAdapter' 1
} Catch {}
Write-Log -Message "MSI mode enabled for controllers."

#=======================================================================================================================
# PHASE 8: DEEP REGISTRY HARDENING (merged from all sources)
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 8: Deep Registry Hardening"

# --- Scheduler ---
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type "DWord"

# --- Timer & coalescing ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "TimerCoalescing" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "DesktopHeapLogging" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "CoalescingTimerInterval" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" -Name "DefaultTriggerCoalescingTime" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" -Name "DisableTriggerCoalescing" -Value 1 -Type "DWord"

# --- Multimedia ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 10 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 10 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "TimerResolution" -Value 10 -Type "DWord"

# --- MMCSS "Games" task profile: boosts scheduler priority for fullscreen games (PC-Tuning / GamingPCSetup) ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Type "String"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Type "String"

# --- SvcHost split disable ---
$SvcHostServices = @("BFE","DcomLaunch","mpssvc","PlugPlay","Power","SamSs","EventSystem","CryptSvc","Dhcp","Dnscache",
    "DisplayEnhancementService","PcaSvc","WdiSystemHost","AudioEndpointBuilder","Appinfo","BITS","gpsvc","IKEEXT",
    "iphlpsvc","LanmanServer","lmhosts","NcbService","RasAuto","RasMan","SENS","ShellHWDetection","SstpSvc","TrkWks",
    "Winmgmt","EventLog","FontCache","LanmanWorkstation","NlaSvc","nsi","ProfSvc","Schedule","SessionEnv","Themes","W32Time","Wcmsvc")
foreach ($svc in $SvcHostServices) {
    Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\$svc" -Name "SvcHostSplitDisable" -Value 1 -Type "DWord"
}
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value 3489660927 -Type "DWord"

# --- Session Manager ---
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "Segment Heap" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BackgroundLoadKnownDlls" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecuteNoPnpSync" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "TaskhostTimeout" -Value 2000 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" -Name "EnableCpuQuota" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "SleepStudyDisabled" -Value 1 -Type "DWord"

# --- Disable autochk on boot ---# Crash control: no auto-reboot, small memory dump only (Revision)
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 3 -Type "DWord"

# Logon: disable first-logon animation, disable startup sound (Revision)
Set-RegValue -Path "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableStartupSound" -Value 1 -Type "DWord"

# OOBE: hide OEM registration, disable Cortana voice during setup (Revision)
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "HideOEMRegistrationScreen" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisablePrivacyExperience" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "EnableCortanaVoice" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute" -Value @("autocheck autochk /k:C*") -Type "MultiString"

# --- Disable Fault Tolerant Heap ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\FTH" -Name "Enabled" -Value 0 -Type "DWord"
Invoke-TI-Quiet "rundll32.exe fthsvc.dll,FthSysprepSpecialize"

# --- Maintenance disabled ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1 -Type "DWord"

# --- Graphics ---
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -Value 12 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "MiracastForceDisable" -Value 1 -Type "DWord"
Try { if ($WinVer -ge 19041) { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2 -Type DWord -Force } } Catch {}

# --- Disable MPO (Multi-Plane Overlay) ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Value 5 -Type "DWord"

# --- Disable DWM animations ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\Dwm" -Name "DisableProjectedShadows" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\XAML" -Name "DisableGlobalAnimations" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLogonBackgroundImage" -Value 1 -Type "DWord"

# --- Visual performance ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TurnOffSPIAnimations" -Value 1 -Type "DWord"
Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TurnOffSPIAnimations" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoLowDiskSpaceChecks" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoNetCrawling" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRemoteChangeNotify" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRemoteRecursiveEvents" -Value 1 -Type "DWord"

# --- UAC off ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0 -Type "DWord"

# --- Hiberboot off ---
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type "DWord"

# --- Fast logon ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DelayedDesktopSwitchTimeout" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunLogonScriptSync" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RunStartupScriptSync" -Value 0 -Type "DWord"

# --- Audio ---
# Audio: don't reduce volume when Windows detects communications (Revision)
Set-RegValue -Path "HKCU\Software\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" -Name "AudioHealthMonitorLimit" -Value 0 -Type "DWord"

# --- Process mitigations ---
$ExesForMitigation = @('fontdrvhost.exe','dwm.exe','lsass.exe','svchost.exe','WmiPrvSE.exe','winlogon.exe','csrss.exe','ntoskrnl.exe','services.exe')
$mask = [byte[]]::new(38)
for ($i = 0; $i -lt 38; $i++) { $mask[$i] = 0x22 }
foreach ($exe in $ExesForMitigation) {
    $ifPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
    Try {
        if (-not (Test-Path "Registry::$ifPath")) { New-Item -Path "Registry::$ifPath" -Force | Out-Null }
        Set-ItemProperty -Path "Registry::$ifPath" -Name 'MitigationOptions' -Value $mask -Type Binary -Force
        Set-ItemProperty -Path "Registry::$ifPath" -Name 'MitigationAuditOptions' -Value $mask -Type Binary -Force
    } Catch {}
}
$kernelKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
Try {
    if (-not (Test-Path $kernelKey)) { New-Item -Path $kernelKey -Force | Out-Null }
    Set-ItemProperty -Path $kernelKey -Name 'MitigationOptions' -Value $mask -Type Binary -Force
    Set-ItemProperty -Path $kernelKey -Name 'MitigationAuditOptions' -Value $mask -Type Binary -Force
} Catch {}
Write-Log -Message "Process mitigations disabled."

# --- SCfM disable ---
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\SCMConfig" -Name "EnableSvchostMitigationPolicy" -Value 0 -Type "DWord"

# --- EventSystem fast fire ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\EventSystem" -Name "ParallelFiringTimeoutEnabled" -Value 1 -Type "DWord"

# --- PowerShell telemetry off ---
# Disable PowerShell module and script block logging
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "POWERSHELL_TELEMETRY_OPTOUT" -Value "1" -Type "String"

# --- .NET telemetry off ---
Invoke-TI "setx DOTNET_CLI_TELEMETRY_OPTOUT 1 /M"

# --- Copy file buffered sync IO ---
# Disable System Restore pre-defined config (Revision)
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "RPSessionInterval" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\cfg" -Name "DiskPercent" -Value 0 -Type "DWord"

# RealTimeIsUniversal: fix clock desync when dual-booting with Linux (Revision)
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Value 1 -Type "DWord"

# Disable WPBT (Windows Platform Binary Table -- prevents OEM bloat injection at boot)
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableWpbtExecution" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "CopyFileBufferedSynchronousIo" -Value 1 -Type "DWord"

# --- Disable automatic app archiving ---
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\Appx" -Name "AllowAutomaticAppArchiving" -Value 0 -Type "DWord"

# --- Token leak detect ---
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TokenLeakDetectDelaySecs" -Value 30 -Type "DWord"

Write-Log -Message "Registry hardening complete."

#=======================================================================================================================
# PHASE 9: PRIVACY & TELEMETRY REGISTRY
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 9: Privacy & Telemetry"

# --- Telemetry = 0 (all paths) ---
$TelemetryPaths = @(
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
)
foreach ($tp in $TelemetryPaths) { Set-RegValue -Path $tp -Name "AllowTelemetry" -Value 0 -Type "DWord" }

# --- Additional telemetry blocks ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry" -Name "value" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\DevicePolicy\AllowTelemetry" -Name "DefaultValue" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\Store\AllowTelemetry" -Name "Value" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowCommercialDataPipeline" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "MicrosoftEdgeDataOptIn" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableTelemetryOptInChangeNotification" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableTelemetryOptInSettingsUx" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDesktopAnalyticsProcessing" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowWUfBCloudProcessing" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowUpdateComplianceProcessing" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableOneSettingsDownloads" -Value 1 -Type "DWord"

# --- WMI Autologger disables ---
@("Diagtrack-Listener", "SQMLogger", "SetupPlatformTel") | ForEach-Object {
    Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$_" -Name "Start" -Value 0 -Type "DWord"
}

# --- Experimentation off ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowBuildPreview" -Value 0 -Type "DWord"

# --- CEIP off ---
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Microsoft\SQMClient" -Name "UploadDisableFlag" -Value 1 -Type "DWord"

# --- Windows Error Reporting off ---
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Value 0 -Type "DWord"

# --- Cloud content off ---
# Disable search suggestions (HKLM level -- removes ads from start menu search)
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type "DWord"

# --- Advertising ID off ---
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type "DWord"

# --- Activity feed off ---
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type "DWord"

# --- Clipboard history off ---
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Type "DWord"

# --- Find My Device off ---
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Value 0 -Type "DWord"

# --- Input personalization off ---
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Value 0 -Type "DWord"

# --- Sync off ---
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value 2 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Value 1 -Type "DWord"

# --- Tailored experiences off ---
Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type "DWord"

# --- Disable logging ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration" -Name "AdapterLoggingEnabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration" -Name "EnableAt" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit" -Name "EtwDirect" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Tracing" -Name "TracingDisabled" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" -Name "WdfGlobalLogsDisabled" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" -Name "WdfGlobalSleepStudyDisabled" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance" -Name "DisableDiagnosticTracing" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "NoDebugThread" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "RsopLogging" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI" -Name "EnableMessageSQM" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit" -Name "PolicyDebugLevel" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name "EnableProtectedEventLogging" -Value 0 -Type "DWord"

# --- Disable Copilot & Recall ---
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "DisableAIDataAnalysis" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Type "DWord"
Set-RegValue -Path "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Type "DWord"
Set-RegValue -Path "HKCU\Software\Microsoft\Windows\Shell\Copilot\BingChat" -Name "IsUserEligible" -Value 0 -Type "DWord"
Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Type "DWord"
Set-RegValue -Path "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1 -Type "DWord"
Set-RegValue -Path "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" -Name "AllowRecallEnablement" -Value 0 -Type "DWord"
# Copilot IFEO blocks -- prevents Copilot.exe from ever launching
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Copilot.exe" -Name "Debugger" -Value "%SYSTEMROOT%\System32\taskkill.exe" -Type "String"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CopilotNative.exe" -Name "Debugger" -Value "%SYSTEMROOT%\System32\taskkill.exe" -Type "String"
# Disable Copilot & AI services
@("MicrosoftCopilotElevationService","MicrosoftCopilotService","WSAIFabricSvc") | ForEach-Object {
    Invoke-TI-Quiet "sc.exe stop $_"
    Invoke-TI-Quiet "sc.exe config $_ start= disabled"
}
# Kill any running Copilot processes
@("Copilot","CopilotNative","CopilotHost") | ForEach-Object {
    Try { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue } Catch {}
}

# --- BitLocker: prevent automatic device encryption (Win 11 24H2+) ---
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" -Name "PreventDeviceEncryption" -Value 1 -Type "DWord"
Invoke-TI-Quiet "sc.exe stop BDESVC"
Invoke-TI-Quiet "sc.exe config BDESVC start= disabled"
# Disable BitLocker scheduled tasks
@('\Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives','\Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh') | ForEach-Object {
    Invoke-TI "schtasks /change /tn `"$_`" /disable"
}

# --- Start Menu: HKLM PolicyManager CSP -- forces zero pins at device level (Revision) ---
# This is a machine policy, not a user tweak. ConfigureStartPins with empty
# pinnedList forces Windows to show NO pinned tiles for ALL users.
# Write to BOTH current and default policy paths for belt-and-suspenders.
@("HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start","HKLM\SOFTWARE\Microsoft\PolicyManager\default\device\Start") | ForEach-Object {
    $cspPath = $_
    Set-RegValue -Path $cspPath -Name "ConfigureStartPins" -Value '{"pinnedList":[{"packagedAppId":"windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"}]}' -Type "String"
    # Hide all start menu folder pins (Documents, Downloads, Music, etc.)
    $StartFolders = @("Documents","Downloads","FileExplorer","HomeGroup","Music","Network","PersonalFolder","Pictures","Videos")
    foreach ($f in $StartFolders) {
        Set-RegValue -Path $cspPath -Name "AllowPinnedFolder$f" -Value 0 -Type "DWord"
        Set-RegValue -Path $cspPath -Name "AllowPinnedFolder${f}_ProviderSet" -Value 1 -Type "DWord"
    }
    # Keep Settings folder visible (power users need it)
    Set-RegValue -Path $cspPath -Name "AllowPinnedFolderSettings" -Value 1 -Type "DWord"
}

# --- AppCompat: kill Program Compatibility Assistant + telemetry (Revision) ---
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableEngine" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\AppCompat" -Name "SbEnable" -Value 1 -Type "DWord"

# --- Push notifications: block cloud-sourced notification spam (Revision) ---
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type "DWord"

# --- System: EnableLinkedConnections (mapped drives in elevated context), MSA optional (Revision) ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value 1 -Type "DWord"

# --- EdgeUI: disable help tips + Windows Feeds + Chat icon + Dsh (Revision) ---
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableHelpSticker" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Name "ChatIcon" -Value 3 -Type "DWord"

# --- OOBE: bypass network requirement + unsupported hardware ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "BypassNRO" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\Setup\MoSetup" -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -Type "DWord"

# --- Upgrade notifications + Media Player auto-update OFF (Revision) ---
Set-RegValue -Path "HKLM\SYSTEM\Setup\UpgradeNotification" -Name "UpgradeAvailable" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "DisableAutoUpdate" -Value 1 -Type "DWord"

# --- WU UX: hide Media Creation Tool link, disable restart notifications ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "HideMCTLink" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "RestartNotificationsAllowed2" -Value 0 -Type "DWord"

# --- Office: disable background ClickToRun logging (Revision) ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\ClickToRun\OverRide" -Name "DisableLogManagement" -Value 1 -Type "DWord"

# --- Block Store results in Windows Search (25H2) (Revision) ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\WinStore.Tasks.WindowsSearchTask" -Name "ActivationType" -Value 4294967295 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\WinStore.Tasks.WindowsSearchTask" -Name "Server" -Value "" -Type "String"

# --- Block Xbox Gaming AI Companion DLL from loading (Revision) ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions" -Name "ActivationType" -Value 4294967295 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions" -Name "Server" -Value "" -Type "String"

# --- Block GamePresenceWriter activation (stops the "Get Xbox Game Bar" toast on first fullscreen launch) (ValleyOfDoom) ---
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType" -Value 0 -Type "DWord"

# --- Prevent WebView2 from spawning inside SearchHost (25H2) (Revision) ---
Set-RegValue -Path "HKLM\SYSTEM\ControlSet001\Policies\Microsoft\FeatureManagement\Overrides" -Name "1694661260" -Value 0 -Type "DWord"

# --- Block Outlook + DevHome pre-install via WU Orchestrator (Revision) ---
Try { Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Try { Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}

# --- Block bloatware auto-install ---
Set-RegValue -Path "HKLM\Software\Microsoft\Windows\CurrentVersion\Communications" -Name "ConfigureChatAutoInstall" -Value 0 -Type "DWord"
Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0 -Type "DWord"

Write-Log -Message "Privacy & telemetry blocking complete."

#=======================================================================================================================
# PHASE 10: WINDOWS UPDATE ANNIHILATION
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 10: Windows Update Annihilation"

$WUKeys = @(
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DisableWindowsUpdateAccess", 1),
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DisableOSUpgrade", 1),
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "SetDisableUXWUAccess", 1),
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "ExcludeWUDriversInQualityUpdate", 1),
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DoNotConnectToWindowsUpdateInternetLocations", 1),
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DisableDualScan", 1),
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "TargetReleaseVersion", 1),
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 1),
    @("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "UseWUServer", 1)
)
foreach ($k in $WUKeys) { Set-RegValue -Path $k[0] -Name $k[1] -Value $k[2] -Type "DWord" }

# WSUS to null
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value " " -Type "String"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value " " -Type "String"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "UpdateServiceUrlAlternate" -Value " " -Type "String"

# Driver update blocks
# Disable Co-Installers (prevents Razer Synapse etc. auto-install on device plug)
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" -Name "DisableCoInstallers" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type "DWord"

# Store update blocks
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Name "AutoDownload" -Value 2 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1 -Type "DWord"

# Reserved storage off
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" -Name "ShippedWithReserves" -Value 0 -Type "DWord"

# Pause updates until 2038
$PauseValues = @(
    @("PauseFeatureUpdatesStartTime", "2025-01-01T00:00:00Z"),
    @("PauseFeatureUpdatesEndTime", "2038-01-19T03:14:07Z"),
    @("PauseQualityUpdatesStartTime", "2025-01-01T00:00:00Z"),
    @("PauseQualityUpdatesEndTime", "2038-01-19T03:14:07Z"),
    @("PauseUpdatesStartTime", "2025-01-01T00:00:00Z"),
    @("PauseUpdatesExpiryTime", "2038-01-19T03:14:07Z"),
    @("PausedQualityDate", "2025-01-01T00:00:00Z"),
    @("PausedFeatureDate", "2025-01-01T00:00:00Z")
)
foreach ($pv in $PauseValues) { Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name $pv[0] -Value $pv[1] -Type "String" }
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "FlightSettingsMaxPauseDays" -Value 5269 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "PausedFeatureStatus" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "PausedQualityStatus" -Value 1 -Type "DWord"

# MRT updates off
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Type "DWord"

# Delivery optimization off
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 -Type "DWord"

Write-Log -Message "Windows Update annihilation complete."

#=======================================================================================================================
# PHASE 11: NETWORK OPTIMIZATION
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 11: Network Optimization"

# Disable NetBIOS on all adapters
Try {
    Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
        $regPath = "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($_.SettingID)"
        Set-RegValue -Path $regPath -Name "NetbiosOptions" -Value 2 -Type "DWord"
    }
} Catch {}

# Disable WPAD
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" -Value 1 -Type "DWord"

# DNS optimization
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "MaxNegativeCacheTtl" -Value 5 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableNetbios" -Value 0 -Type "DWord"

# BFE network event collection off
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Options" -Name "CollectNetEvents" -Value 0 -Type "DWord"

# DHCP optimization
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\Dhcp" -Name "PdcActivationDisabled" -Value 1 -Type "DWord"

Write-Log -Message "Network optimization complete."

#=======================================================================================================================
# PHASE 12: APPX & PACKAGE REMOVAL
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 12: AppX Bloat Removal"

$AppxToRemove = @(
    'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.BingSearch',
    'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.MicrosoftStickyNotes',
    'Microsoft.People', 'Microsoft.Todos', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
    'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps', 'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo', 'Microsoft.WindowsSoundRecorder', 'Microsoft.WindowsAlarms',
    'Microsoft.WindowsCamera', 'Microsoft.Windows.PeopleExperienceHost',
    'Microsoft.Windows.SecureAssessmentBrowser', 'Microsoft.MicrosoftOfficeHub',
    'Microsoft.549981C3F5F10', 'MicrosoftCorporationII.QuickAssist',
    'MicrosoftCorporationII.MicrosoftFamily', 'Microsoft.PowerAutomateDesktop',
    'Microsoft.Advertising.Xaml', 'Microsoft.Microsoft3DViewer',
    'Microsoft.MixedReality.Portal', 'Microsoft.Windows.DevHome',
    'Microsoft.OutlookForWindows', 'Microsoft.SkypeApp', 'Microsoft.YourPhone',
    'Microsoft.Windows.ContentDeliveryManager', 'Microsoft.Windows.Notepad',
    'Microsoft.Windows.ParentalControls', 'Microsoft.Windows.Photos',
    'Microsoft.StorePurchaseApp', 'Microsoft.WebMediaExtensions',
    'Microsoft.WindowsCommunicationsApps', 'Microsoft.XboxApp',
    'Microsoft.Xbox.TCUI', 'Microsoft.XboxGameCallableUI',
    'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.GamingApp',
    'Microsoft.XboxGamingOverlay', 'Microsoft.XboxIdentityProvider',
    'Clipchamp.Clipchamp', 'Microsoft.StartExperiencesApp',
    'Microsoft.Windows.AI.Copilot.Provider', 'Microsoft.Whiteboard',
    'Microsoft.WidgetsPlatformRuntime', 'MicrosoftWindows.Client.WebExperience',
    'Microsoft.MicrosoftEdgeDevToolsClient',
    'Microsoft.WindowsStore', 'Microsoft.Services.Store.Engagement',
    # User-reported survivors:
    'Microsoft.OneDriveSync', 'microsoft.microsoftskydrive',
    'MSTeams', 'MicrosoftTeams', 'Microsoft.MicrosoftTeams',
    '5319275A.WhatsAppDesktop', 'Microsoft.LinkedIn',
    '7EE7776C.LinkedInforWindows',
    # Windows 10-specific bloat:
    'Microsoft.Office.OneNote', 'Microsoft.MSPaint'
)

$StorePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'

# Provisioned package removal only -- works from SYSTEM context without crashing.
# Per-user Remove-AppxPackage fails under SYSTEM; provisioning removal prevents
# packages from installing for new users.
foreach ($nameFragment in $AppxToRemove) {
    Try {
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.PackageName -like "*$nameFragment*" } |
            Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    } Catch {}
    # Deprovision to prevent Windows from reinstalling
    Try {
        $pkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
            Where-Object { $_.PackageFullName -like "*$nameFragment*" }
        foreach ($p in $pkgs) {
            $dp = "$StorePath\Deprovisioned\$($p.PackageFamilyName)"
            if (-not (Test-Path $dp)) { New-Item -Path $dp -Force | Out-Null }
        }
    } Catch {}
}

Write-Log -Message "AppX removal complete."

#=======================================================================================================================
# PHASE 13: CLEANUP & REBOOT
#=======================================================================================================================

Write-Log -Level HEADER -Message "PHASE 13: Cleanup & Reboot"


# --- Re-run start menu cleanup after reboot (pins survive OOBE, need post-reboot sweep) ---
# Inline script runs W11STARTMENU.ps1 then self-destructs the entire Scripts folder
$startMenuRunOnce = @'
C:\Windows\Setup\Scripts\W11STARTMENU.ps1
Remove-Item -Path "C:\Windows\Setup\Scripts" -Recurse -Force -ErrorAction SilentlyContinue
'@
$startMenuRunOncePath = "$env:TEMP\ForgedStartMenu.ps1"
[System.IO.File]::WriteAllText($startMenuRunOncePath, $startMenuRunOnce)
Set-RegValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ForgedStartMenu" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $startMenuRunOncePath" -Type "String"
Write-Log -Message "Start menu cleanup scheduled to re-run after reboot."

# Remove PC Health Check
Try {
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        Get-ItemProperty | Where-Object { $_.DisplayName -like "*PC Health Check*" } | ForEach-Object {
            if ($_.UninstallString) { Start-Process cmd.exe -ArgumentList "/c $($_.UninstallString) /quiet /norestart" -Wait -NoNewWindow -ErrorAction SilentlyContinue }
        }
    Remove-Item -Path "${env:ProgramFiles}\PCHealthCheck" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\Desktop\PC Health Check.lnk" -Force -ErrorAction SilentlyContinue
} Catch {}

# Clear WINEVT channels
Try {
    $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels', $true)
    if ($root) {
        foreach ($name in $root.GetSubKeyNames()) {
            $sub = $null
            Try { $sub = $root.OpenSubKey($name, $true); if ($sub -and ($sub.GetValue('Enabled') -eq 1)) { $sub.SetValue('Enabled', 0, 'DWord') } } Catch {} finally { if ($sub) { $sub.Close() } }
        }
        $root.Close()
    }
} Catch {}

# Clear temp files
Try { Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Try { Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Try { Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}

# Clear event logs
Try { wevtutil el 2>&1 | ForEach-Object { wevtutil cl "$_" 2>$null } } Catch {}

# DISM component cleanup
Invoke-TI "dism.exe /online /cleanup-image /startcomponentcleanup"
Write-Log -Message "Component store cleanup initiated."

# Remove NewApp prompt
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_NotifyNewApps" -Value 0 -Type "DWord"

Write-Log -Level HEADER -Message "OPTIMIZATION COMPLETE. SYSTEM WILL REBOOT IN 10 SECONDS."

    # Self-destruct (keep W11STARTMENU.ps1 for RunOnce start menu re-clean)
    Try {
        $cleanupCmd = "Start-Sleep -Seconds 10; Remove-Item -Path '$ScriptPath' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\Windows\Setup\Scripts\Forge-PostInstall.ps1' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\Windows\Setup\Scripts\RemoveEdge.ps1' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\Windows\Setup\Scripts\onedrive.bat' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\Windows\Setup\Scripts\taskbar.bat' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\Windows\Setup\Scripts\driver-exclude.reg' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\Windows\Setup\Scripts\services-disable.reg' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\Windows\Setup\Scripts\trpad.exe' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\Windows\Setup\Scripts\Forged.png' -Force -ErrorAction SilentlyContinue; shutdown /r /f /t 3"
        Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -Command $cleanupCmd" -NoNewWindow -ErrorAction SilentlyContinue
    } Catch {
        shutdown /r /f /t 5
    }

# End of Script
