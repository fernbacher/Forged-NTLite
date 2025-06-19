<#
    ================================================================================================================
    FORGED - Post-Installation Optimization Script for Windows 11 24H2
    Version: 1.0
    ================================================================================================================

    DESCRIPTION:
    This script applies an aggressive, performance-centric, and privacy-focused configuration to a debloated
    Windows 11 24H2 environment. It is to be executed once, immediately following the first user login
    on the Forged ISO created with NTLite.

    WARNING:
    EXTREME CAUTION ADVISED. This script disables critical security features like Spectre/Meltdown
    mitigations and UAC. This is suitable ONLY for a dedicated, isolated gaming or special-purpose machine.
    The user assumes all risks associated with operating a system in this state.
#>

#=======================================================================================================================
# SECTION 0: PREAMBLE, LOGGING, and ELEVATION LOGIC
#=======================================================================================================================

Try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop } Catch {}

$LogFile = "$env:USERPROFILE\Desktop\Forged_Optimization_Log.txt"
$ToolsPath = "C:\Windows\Tools"
$MinSudoPath = Join-Path $ToolsPath "MinSudo.exe"
$WallpaperPath = Join-Path $ToolsPath "Forged.png"
$ScriptName = $MyInvocation.MyCommand.Name

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Level] - $Message"
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor Green }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "HEADER"  { Write-Host "`n" + ("="*80) + "`n$Message`n" + ("="*80) -ForegroundColor Cyan }
        default   { Write-Host $LogEntry }
    }
    Try { Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue } Catch {}
}

if (Test-Path $LogFile) { Remove-Item $LogFile -Force -ErrorAction SilentlyContinue }
Try { New-Item -Path $LogFile -ItemType File -Force | Out-Null } Catch {}
Write-Log -Level HEADER -Message "Initializing Forged Post-Installation Optimization Script"
Write-Log -Message "Script Name: $ScriptName"
Write-Log -Message "All operations will be logged to: $LogFile"

function Invoke-TrustedInstaller {
    param(
        [Parameter(Mandatory=$true)][string]$Command
    )
    if (-not (Test-Path $MinSudoPath)) {
        Write-Log -Level ERROR -Message "MinSudo.exe not found at $MinSudoPath. Cannot proceed with privileged operations."
        Start-Sleep -Seconds 10
        Exit 1
    }
    $ArgumentList = "-TI -P -- $Command"
    Try {
        Start-Process -FilePath $MinSudoPath -ArgumentList $ArgumentList -Wait -NoNewWindow -ErrorAction Stop
    } Catch {
        Write-Log -Level ERROR -Message "Failed to run TrustedInstaller command: $Command"
    }
}

function Get-CurrentUserName {
    try {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        return $user
    } catch {
        return $env:USERNAME
    }
}

$CurrentUser = Get-CurrentUserName

# Improved Set-RegValue supporting default value
function Set-RegValue {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][string]$Name,
        [Parameter(Mandatory=$true)]$Value,
        [Parameter(Mandatory=$true)][string]$Type
    )
    Write-Log -Message "Setting Registry: $Path | $Name = $Value"
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
                Invoke-TrustedInstaller "reg add `"$Path`" /v `"$Name`" /t $Type /d `"$Value`" /f"
            } else {
                Invoke-TrustedInstaller "reg add `"$Path`" /ve /t $Type /d `"$Value`" /f"
            }
        } Catch {}
    }
}

#=======================================================================================================================
# PHASE 1: Run as Current User (per-user tweaks, UI, wallpaper, etc.)
#=======================================================================================================================

if ($CurrentUser -notmatch "^(NT AUTHORITY\\SYSTEM|NT AUTHORITY\\TrustedInstaller)$") {

    # --- SECTION 1: Essential Application Deployment (winget in user context only) ---
    Write-Log -Level HEADER -Message "SECTION 1: Essential Application Deployment (winget in user context only)"
    function Ensure-Winget {
        try {
            $wingetPath = (Get-Command winget.exe -ErrorAction Stop).Source
            if (-not (Test-Path $wingetPath)) { throw "winget.exe not found on disk." }
            return $true
        } catch {
            Write-Log -Level ERROR -Message "winget is not available or not installed. Aborting as per user requirement."
            Exit 2
        }
    }
    if (Ensure-Winget) {
        Write-Log -Message "Installing Open-Shell (Classic Start Menu) via winget..."
        try {
            winget install -e --id Open-Shell.Open-Shell-Menu --silent --accept-package-agreements --accept-source-agreements
            Write-Log -Message "-> Open-Shell installed via winget."
        } catch {
            Write-Log -Level ERROR -Message "Open-Shell installation failed via winget: $_"
            Exit 3
        }
        Write-Log -Message "Installing Mozilla Firefox via winget..."
        try {
            winget install -e --id Mozilla.Firefox --silent --accept-package-agreements --accept-source-agreements
            Write-Log -Message "-> Mozilla Firefox installed via winget."
        } catch {
            Write-Log -Level ERROR -Message "Mozilla Firefox installation failed via winget: $_"
            Exit 4
        }
    }

    # --- SECTION: User-Context UI, Taskbar, Wallpaper, and HKCU Tweaks ---
    Write-Log -Level HEADER -Message "SECTION: User-Context UI, Taskbar, Wallpaper, and HKCU Tweaks"

    # Taskbar, Start, and Search Buttons (all HKCU!)
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Type "DWord"

    # Unpin all taskbar items for current user (works for 22H2+)
    try {
        $taskbandKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
        if (Test-Path $taskbandKey) {
            Remove-ItemProperty -Path $taskbandKey -Name "Favorites" -ErrorAction SilentlyContinue
            Write-Log -Message "-> Cleared taskbar pins for current user."
        }
    } catch { Write-Log -Level WARN -Message "Could not clear taskbar pins: $_" }

    # Classic Context Menu for user (removes "Show more options")
    $CCMKey = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    try {
        if (-not (Test-Path $CCMKey)) {
            New-Item -Path $CCMKey -Force | Out-Null
        }
        Set-ItemProperty -Path $CCMKey -Name '(default)' -Value "" -Force
        Write-Log -Message "-> Classic context menu enabled for current user."
    } catch { Write-Log -Level WARN -Message "Could not set classic context menu: $_" }

    # Wallpaper for current user (persisted)
    if (Test-Path $WallpaperPath) {
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "Wallpaper" -Value $WallpaperPath -Type "String"
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10" -Type "String"
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "TileWallpaper" -Value "0" -Type "String"
        # Update desktop wallpaper immediately
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
        [Wallpaper]::SystemParametersInfo(0x0014, 0, $WallpaperPath, 0x01 -bor 0x02) | Out-Null
        Write-Log -Message "-> Custom wallpaper set for current user."
        # Clear wallpaper cache files for current user
        $Transcoded = "$env:APPDATA\Microsoft\Windows\Themes\TranscodedWallpaper"
        $CachedFilesDir = "$env:APPDATA\Microsoft\Windows\Themes\CachedFiles"
        Try {
            if (Test-Path $Transcoded) { Remove-Item $Transcoded -Force -ErrorAction SilentlyContinue }
            if (Test-Path $CachedFilesDir) { Remove-Item "$CachedFilesDir\*" -Force -Recurse -ErrorAction SilentlyContinue }
            Write-Log -Message "-> Cleared wallpaper cache files for current user."
        } Catch {
            Write-Log -Level WARN -Message "Could not clear wallpaper cache files: $_"
        }
    } else {
        Write-Log -Level WARN -Message "Custom wallpaper not found at '$WallpaperPath'"
    }

    # Hide "Learn about this picture" desktop icon
    $IconPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    $IconName = "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}"
    Set-RegValue -Path $IconPath -Name $IconName -Value 1 -Type "DWord"

    # --- DISABLE MOUSE ACCELERATION FOR CURRENT USER ---
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -Type "String"
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -Type "String"
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -Type "String"
    Write-Log -Message "-> Mouse acceleration (Enhance Pointer Precision) disabled for current user."

    # --- Now escalate for SYSTEM/hardening tweaks ---
    $PowerShellPath = (Get-Command powershell.exe).Source
    $ScriptPath = $MyInvocation.MyCommand.Path
    Write-Log -Message "Escalating script to SYSTEM/TrustedInstaller for system-wide tweaks..."
    Invoke-TrustedInstaller "`"$PowerShellPath`" -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    Exit
}

Write-Log -Message "Executing as: $CurrentUser"

#=======================================================================================================================
# PHASE 2: SYSTEM/TrustedInstaller context (system-wide tweaks)
#=======================================================================================================================

# --- SECTION II: FOUNDATIONAL SYSTEM & KERNEL OPTIMIZATIONS ---

Write-Log -Level HEADER -Message "SECTION II: Foundational System & Kernel Optimizations"

Write-Log -Message "Disabling Spectre and Meltdown CPU mitigations for performance."
Invoke-TrustedInstaller 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f'
Invoke-TrustedInstaller 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f'

Write-Log -Message "Applying BCDEdit tweaks for low latency."
Invoke-TrustedInstaller "bcdedit /set disabledynamictick yes"
Write-Log -Message "-> Dynamic Tick disabled."
Invoke-TrustedInstaller "bcdedit /set tscsyncpolicy enhanced"
Write-Log -Message "-> TSC Sync Policy set to Enhanced."
Invoke-TrustedInstaller "bcdedit /deletevalue useplatformclock"
Write-Log -Message "-> Ensured 'useplatformclock' is not enabled."
Invoke-TrustedInstaller "bcdedit /set hypervisorlaunchtype off"
Write-Log -Message "-> Hypervisor launch disabled."

Write-Log -Message "Tuning NTFS for improved performance."
Invoke-TrustedInstaller "fsutil behavior set disablelastaccess 1"
Write-Log -Message "-> Last Access Timestamps disabled."
Invoke-TrustedInstaller "fsutil behavior set disable8dot3 1"
Write-Log -Message "-> 8.3 Short Filename Creation disabled."
Invoke-TrustedInstaller "fsutil behavior set memoryusage 1"
Write-Log -Message "-> NTFS paged pool memory usage increased."

# --- SECTION III: POWER & PERFORMANCE CONFIGURATION ---

Write-Log -Level HEADER -Message "SECTION III: Power Settings for Max Performance"

Write-Log -Message "Importing 'Ultimate Performance' power plan."
$UltGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"
Try {
    $existingPlan = powercfg /l | Select-String $UltGUID
    if (-not $existingPlan) {
        powercfg -duplicatescheme $UltGUID | Out-Null
    }
    powercfg /setactive $UltGUID
    Write-Log -Message "-> 'Ultimate Performance' power plan activated."
} Catch {
    Write-Log -Level WARN -Message "Unable to set Ultimate Performance plan."
}
function Set-PowerCfgValue {
    param($Guid, $SubGroup, $Setting, $Value)
    Try { powercfg -setacvalueindex $Guid $SubGroup $Setting $Value; powercfg -setdcvalueindex $Guid $SubGroup $Setting $Value } Catch {}
}
Set-PowerCfgValue $UltGUID "0012ee47-9041-4b5d-9b77-535fba8b1442" "6738e2c4-e8a5-4a42-b16a-e040e769756e" 0
Set-PowerCfgValue $UltGUID "2a737441-1930-4402-8d77-b2bebba308a3" "48e6b7a6-50f5-4782-a5d4-53bb8f07e226" 0
Set-PowerCfgValue $UltGUID "501a4d13-42af-4429-9fd1-a8218c268e20" "ee12f906-d277-404b-b6da-e5fa1a576df5" 0
Set-PowerCfgValue $UltGUID "54533251-82be-4824-96c1-47b60b740d00" "893dee8e-2bef-41e0-89c6-b55d0929964c" 100
Set-PowerCfgValue $UltGUID "54533251-82be-4824-96c1-47b60b740d00" "bc5038f7-23e0-4960-96da-33abaf5935ec" 100
Set-PowerCfgValue $UltGUID "7516b95f-f776-4464-8c53-06167f40cc99" "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" 0
Set-PowerCfgValue $UltGUID "238c9fa8-0aad-41ed-83f4-97be242c8f20" "29f6c1db-86da-48c5-9fdb-f2b67b1f44da" 0
Try { powercfg /hibernate off } Catch {}
Write-Log -Message "-> Hibernation disabled."

# --- SECTION IV: SERVICE & SCHEDULED TASK ANNIHILATION ---

Write-Log -Level HEADER -Message "SECTION IV: Services and Scheduled Tasks Debloat"

$ServicesToDisable = @(
    "DiagTrack", "diagsvc", "diagnosticshub.standardcollector.service", "dmwappushservice", "WerSvc",
    "AJRouter", "AssignedAccessManagerSvc", "BcastDVRUserService", "DevicePickerUserSvc", "DevicesFlowUserSvc", "Fax", "icssvc", "lfsvc",
    "MapsBroker", "MessagingService", "OneSyncSvc", "PcaSvc", "PeerDistSvc", "PhoneSvc", "PrintNotify", "Spooler", "RetailDemo",
    "SensorDataService", "SensorService", "SensrSvc", "SharedRealitySvc", "WalletService", "WbioSrvc", "WdiServiceHost", "WdiSystemHost",
    "wisvc", "workfolderssvc", "WwanSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
    "RemoteRegistry", "TermService", "UmRdpService", "SecurityHealthService", "wscsvc", "Sense",
    "SysMain", "SEMgrSvc", "spectrum", "DoSvc"
)
$ServicesToSetManual = @(
    "bthserv", "BluetoothUserService", "BthAvctpSvc", "hidserv", "TabletInputService"
)
foreach ($service in $ServicesToDisable) {
    Try {
        $svc = Get-Service -Name $service -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') { Invoke-TrustedInstaller "sc.exe stop $service" }
        Invoke-TrustedInstaller "sc.exe config $service start= disabled"
        Write-Log -Message "-> Disabled service: $service"
    } Catch { Write-Log -Level WARN -Message "Service $service not present or already removed." }
}
foreach ($service in $ServicesToSetManual) {
    Try {
        $svc = Get-Service -Name $service -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') { Invoke-TrustedInstaller "sc.exe stop $service" }
        Invoke-TrustedInstaller "sc.exe config $service start= demand"
        Write-Log -Message "-> Set service to manual: $service"
    } Catch { Write-Log -Level WARN -Message "Service $service not present or already removed." }
}

$TasksToDisable = @(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Application Experience\StartupAppTask',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
    '\Microsoft\Windows\Windows Error Reporting\QueueReporting',
    '\Microsoft\Windows\CloudExperienceHost\CreateObjectTask'
)
foreach ($task in $TasksToDisable) {
    Try {
        $taskObj = Get-ScheduledTask -TaskPath ([System.IO.Path]::GetDirectoryName($task)) -TaskName ([System.IO.Path]::GetFileName($task)) -ErrorAction Stop
        Invoke-TrustedInstaller "schtasks /change /tn `"$task`" /disable"
        Write-Log -Message "-> Disabled scheduled task: $task"
    } Catch { Write-Log -Level WARN -Message "Task $task not present or already removed." }
}

# --- AGGRESSIVE WINDOWS UPDATE DESTRUCTION ---
Write-Log -Level HEADER -Message "AGGRESSIVE WINDOWS UPDATE DESTRUCTION"

$WU_Services = @("wuauserv", "UsoSvc", "WaaSMedicSvc")
foreach ($svc in $WU_Services) {
    Try {
        $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($svcObj -and $svcObj.Status -ne 'Stopped') {
            Invoke-TrustedInstaller "sc.exe stop $svc"
        }
        Invoke-TrustedInstaller "sc.exe config $svc start= disabled"
        Write-Log -Message "-> Disabled Windows Update related service: $svc"
    } Catch {
        Write-Log -Level WARN -Message "Windows Update service $svc not present or already stopped."
    }
    $svcRegKey = "HKLM\SYSTEM\CurrentControlSet\Services\$svc"
    Try {
        if (Test-Path "Registry::$svcRegKey") {
            Invoke-TrustedInstaller "reg delete `"$svcRegKey`" /f"
            Write-Log -Message "-> Registry key deleted for Windows Update service: $svc"
        }
    } Catch {
        Write-Log -Level WARN -Message "Could not delete registry key for $svc (possibly already removed)."
    }
}

# --- SECTION V: DEEP REGISTRY & POLICY HARDENING ---

Write-Log -Level HEADER -Message "SECTION V: Deep Registry & Policy Modifications"

Write-Log -Message "Applying privacy and anti-telemetry registry settings..."
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableDeviceDelete" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoGeneralAppLaunchTracking" -Value 1 -Type "DWord"

Write-Log -Message "Applying performance and responsiveness registry settings..."
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\FTH" -Name "Enabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type "DWord"

Write-Log -Message "Applying system behavior modifications..."
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type "DWord"
Write-Log -Message "-> User Account Control (UAC) disabled."
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type "DWord"

# --- SECTION VI: NETWORK STACK OPTIMIZATION ---

Write-Log -Level HEADER -Message "SECTION VI: Network Stack & Hosts File"

Write-Log -Message "Applying network adapter and protocol tweaks..."
Try { Invoke-TrustedInstaller "netsh int tcp set global autotuninglevel=disabled" } Catch {}
Write-Log -Message "-> TCP Auto-Tuning disabled."
Try { Invoke-TrustedInstaller "netsh int tcp set global rss=disabled" } Catch {}
Write-Log -Message "-> Receive-Side Scaling (RSS) disabled."
Try {
    Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
        $regPath = "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($_.SettingID)"
        Set-RegValue -Path $regPath -Name "NetbiosOptions" -Value 2 -Type "DWord"
        Write-Log -Message "-> NetBIOS disabled for adapter: $($_.Description)"
    }
} Catch { Write-Log -Level WARN -Message "Failed to enumerate adapters for NetBIOS tweak." }

# --- MUCH SIMPLER HOSTS FILE ---
Write-Log -Message "Deploying ultra-simple hosts file for compatibility and privacy..."
$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$TempHosts = "$env:TEMP\forged-hosts.txt"
@"
# Forged Windows 11 - Minimal Hosts File
127.0.0.1       localhost
::1             localhost

# Optional: Block a couple privacy/telemetry domains (commented out for safety)
#0.0.0.0        telemetry.microsoft.com
#0.0.0.0        vortex.data.microsoft.com
"@ | Set-Content -Path $TempHosts -Encoding ASCII

if (Test-Path $HostsPath) {
    Copy-Item -Path $HostsPath -Destination "$HostsPath.bak" -Force
    Write-Log -Message "-> Original hosts file backed up."
}
Invoke-TrustedInstaller "takeown /f `"$HostsPath`""
Invoke-TrustedInstaller "icacls `"$HostsPath`" /grant `"$env:USERNAME`":F"
Copy-Item -Path $TempHosts -Destination $HostsPath -Force
Write-Log -Message "-> Minimal hosts file deployed."
Try { ipconfig /flushdns | Out-Null } Catch {}
Write-Log -Message "-> DNS cache flushed."
Remove-Item $TempHosts -Force

# --- SECTION VII: UI Sterilization & Branding for DefaultUser (wallpaper, LayoutModification.xml) ---

Write-Log -Level HEADER -Message "SECTION VII: UI Sterilization & Branding (DefaultUser)"

# LayoutModification.xml for new users
$LayoutXml = @'
<LayoutModificationTemplate xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList />
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
  <StartLayoutCollection>
    <defaultlayout:StartLayout GroupCellWidth="6" />
  </StartLayoutCollection>
</LayoutModificationTemplate>
'@
$DefaultUserLayoutDir = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell"
$DefaultUserLayoutXml = Join-Path $DefaultUserLayoutDir "LayoutModification.xml"
Try {
    if (-not (Test-Path $DefaultUserLayoutDir)) {
        New-Item -ItemType Directory -Path $DefaultUserLayoutDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllLines($DefaultUserLayoutXml, $LayoutXml -split "`r?`n", [System.Text.Encoding]::UTF8)
    Write-Log -Message "-> Clean LayoutModification.xml deployed to Default User profile."
} Catch {
    Write-Log -Level ERROR -Message "Failed to deploy LayoutModification.xml for Start/Menu reset: $_"
}

# Persistent wallpaper for all new users (DefaultUser hive)
if (Test-Path $WallpaperPath) {
    $DefaultUserHive = "C:\Users\Default\ntuser.dat"
    $MountKey = "HKLM\DefaultUser"
    Try {
        reg load $MountKey $DefaultUserHive | Out-Null
        Set-RegValue -Path "$MountKey\Control Panel\Desktop" -Name "Wallpaper" -Value $WallpaperPath -Type "String"
        Set-RegValue -Path "$MountKey\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10" -Type "String"
        Set-RegValue -Path "$MountKey\Control Panel\Desktop" -Name "TileWallpaper" -Value "0" -Type "String"
        Write-Log -Message "-> Wallpaper and style set for Default User hive."
    } Catch {
        Write-Log -Level WARN -Message "Failed to mount or set wallpaper in Default User hive: $_"
    } finally {
        Try { reg unload $MountKey | Out-Null } Catch {}
    }
} else {
    Write-Log -Level WARN -Message "Custom wallpaper not found at '$WallpaperPath'. Skipping."
}

# --- Remove default Windows themes (system-wide) ---
Write-Log -Message "Removing default Windows themes..."
$ThemePaths = @("$env:SystemRoot\Resources\Themes", "$env:SystemRoot\Resources\Ease of Access Themes")
foreach ($path in $ThemePaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter "*.theme" -File -ErrorAction SilentlyContinue | ForEach-Object {
            Try {
                Invoke-TrustedInstaller "takeown /f `"$($_.FullName)`""
                Invoke-TrustedInstaller "icacls `"$($_.FullName)`" /grant `"$env:USERNAME`":F"
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Log -Message "-> Removed theme: $($_.FullName)"
            } Catch {
                Write-Log -Level WARN -Message "Could not remove theme $($_.Name). May be in use or protected."
            }
        }
    }
}

# --- SECTION VIII: UI Hardening for all new users (DefaultUser) ---

Write-Log -Level HEADER -Message "SECTION VIII: Advanced UI and Driver Hardening (DefaultUser)"

Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowClassicMode" -Value 1 -Type "DWord"
# Classic context menu for all new users
$CCMKeyDefaultUser = "HKLM\DefaultUser\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
Try {
    $DefaultUserHive = "C:\Users\Default\ntuser.dat"
    $MountKey = "HKLM\DefaultUser"
    reg load $MountKey $DefaultUserHive | Out-Null
    if (-not (Test-Path "Registry::$CCMKeyDefaultUser")) {
        New-Item -Path "Registry::$CCMKeyDefaultUser" -Force | Out-Null
    }
    Set-ItemProperty -Path "Registry::$CCMKeyDefaultUser" -Name '(default)' -Value "" -Force
    Write-Log -Message "-> Classic context menu enabled for DefaultUser (future users)."
    reg unload $MountKey | Out-Null
} Catch { Write-Log -Level WARN -Message "Could not set classic context menu for DefaultUser: $_" }

$BlockedShellExtPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
Set-RegValue -Path $BlockedShellExtPath -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "" -Type "String"
Write-Log -Message "-> 'Cast to device' context menu blocked."

# --- SECTION IX: FINALIZATION & SELF-DESTRUCTION ---

Write-Log -Level HEADER -Message "SECTION IX: Finalization & Reboot Prep"

Write-Log -Message "Performing final system cleanup..."
Try { Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Try { Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Write-Log -Message "-> Temporary file directories cleared."
Try { Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Write-Log -Message "-> Prefetch directory cleared."
Try {
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
        Try { wevtutil.exe cl $_.LogName } Catch {}
        Write-Log -Message "-> Cleared event log: $($_.LogName)"
    }
    Write-Log -Message "-> All system event logs cleared."
} Catch { Write-Log -Level WARN -Message "Could not clear all event logs." }
Write-Log -Message "Cleaning up component store (WinSxS)..."
Invoke-TrustedInstaller "dism.exe /online /cleanup-image /startcomponentcleanup"
Write-Log -Message "-> Component store cleanup complete."

Write-Log -Level HEADER -Message "OPTIMIZATION COMPLETE. SYSTEM WILL REBOOT IN 5 SECONDS."

$ScriptPathToDelete = $MyInvocation.MyCommand.Path
$SelfDestructCommand = "Start-Sleep -Seconds 5; Remove-Item -Path `"$ScriptPathToDelete`" -Force; shutdown /r /f /t 1"
Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -Command `"$SelfDestructCommand`"" -NoNewWindow

# End of Script
