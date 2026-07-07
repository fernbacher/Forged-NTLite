<#
    ================================================================================================================
    FORGED - Post-Installation Optimization Script for Windows 11
    Version: 2.0
    ================================================================================================================

    DESCRIPTION:
    Applies aggressive performance, privacy, and latency optimizations to a debloated Windows 11
    environment. Designed for single-use execution immediately after first login on a Forged ISO.

    WARNING:
    Disables critical security features (Spectre/Meltdown mitigations, UAC, Defender). For dedicated gaming
    or low‑latency machines only. User assumes all risk.
#>

#=======================================================================================================================
# SECTION 0: PREAMBLE, LOGGING, ELEVATION
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
Write-Log -Level HEADER -Message "Initializing Forged Post-Installation Optimization Script v2.0"
Write-Log -Message "Script Name: $ScriptName"
Write-Log -Message "All operations will be logged to: $LogFile"

function Invoke-TrustedInstaller {
    param(
        [Parameter(Mandatory=$true)][string]$Command
    )
    if (-not (Test-Path $MinSudoPath)) {
        Write-Log -Level ERROR -Message "MinSudo.exe not found at $MinSudoPath. Cannot proceed."
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
# PHASE 1: CURRENT USER (UI, wallpapers, per‑user tweaks)
#=======================================================================================================================

if ($CurrentUser -notmatch "^(NT AUTHORITY\\SYSTEM|NT AUTHORITY\\TrustedInstaller)$") {

    Write-Log -Level HEADER -Message "SECTION 1: Essential Application Deployment (winget)"
    function Ensure-Winget {
        try {
            $wingetPath = (Get-Command winget.exe -ErrorAction Stop).Source
            if (-not (Test-Path $wingetPath)) { throw "winget.exe not found on disk." }
            return $true
        } catch {
            Write-Log -Level ERROR -Message "winget is not available. Aborting."
            Exit 2
        }
    }
    if (Ensure-Winget) {
        Write-Log -Message "Installing Open-Shell and Firefox..."
        try { winget install -e --id Open-Shell.Open-Shell-Menu --silent --accept-package-agreements --accept-source-agreements } catch { Write-Log -Level ERROR -Message "Open-Shell failed: $_" ; Exit 3 }
        try { winget install -e --id Mozilla.Firefox --silent --accept-package-agreements --accept-source-agreements } catch { Write-Log -Level ERROR -Message "Firefox failed: $_" ; Exit 4 }
    }

    Write-Log -Level HEADER -Message "SECTION: User‑Context UI and Registry Tweaks"
    # Taskbar, Start, Search
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Type "DWord"

    try {
        $taskbandKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
        if (Test-Path $taskbandKey) { Remove-ItemProperty -Path $taskbandKey -Name "Favorites" -ErrorAction SilentlyContinue }
    } catch { Write-Log -Level WARN -Message "Could not clear taskbar pins: $_" }

    # Classic context menu
    $CCMKey = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    try {
        if (-not (Test-Path $CCMKey)) { New-Item -Path $CCMKey -Force | Out-Null }
        Set-ItemProperty -Path $CCMKey -Name '(default)' -Value "" -Force
    } catch { Write-Log -Level WARN -Message "Could not set classic context menu: $_" }

    # Wallpaper
    if (Test-Path $WallpaperPath) {
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "Wallpaper" -Value $WallpaperPath -Type "String"
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10" -Type "String"
        Set-RegValue -Path "HKCU\Control Panel\Desktop" -Name "TileWallpaper" -Value "0" -Type "String"
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
        [Wallpaper]::SystemParametersInfo(0x0014, 0, $WallpaperPath, 0x01 -bor 0x02) | Out-Null
        $Transcoded = "$env:APPDATA\Microsoft\Windows\Themes\TranscodedWallpaper"
        $CachedFilesDir = "$env:APPDATA\Microsoft\Windows\Themes\CachedFiles"
        Try {
            if (Test-Path $Transcoded) { Remove-Item $Transcoded -Force -ErrorAction SilentlyContinue }
            if (Test-Path $CachedFilesDir) { Remove-Item "$CachedFilesDir\*" -Force -Recurse -ErrorAction SilentlyContinue }
        } Catch {}
    } else {
        Write-Log -Level WARN -Message "Custom wallpaper not found at '$WallpaperPath'"
    }

    # Hide "Learn about this picture"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" -Value 1 -Type "DWord"

    # Mouse acceleration off
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -Type "String"
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -Type "String"
    Set-RegValue -Path "HKCU\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -Type "String"

    # Additional HKCU tweaks
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type "String"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" -Name "DiscontinueEOS" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\input\Settings" -Name "InsightsEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type "DWord"
    Set-RegValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type "DWord"

    Write-Log -Message "Per‑user tweaks applied. Escalating to SYSTEM/TrustedInstaller..."
    $PowerShellPath = (Get-Command powershell.exe).Source
    $ScriptPath = $MyInvocation.MyCommand.Path
    Invoke-TrustedInstaller "`"$PowerShellPath`" -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    Exit
}

Write-Log -Message "Executing as: $CurrentUser"

#=======================================================================================================================
# PHASE 2: SYSTEM CONTEXT (system‑wide optimizations)
#=======================================================================================================================

Write-Log -Level HEADER -Message "SECTION II: Foundational System & Kernel Optimizations"

# Spectre/Meltdown
Invoke-TrustedInstaller 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f'
Invoke-TrustedInstaller 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f'

# BCDEdit
Invoke-TrustedInstaller "bcdedit /set disabledynamictick yes"
Invoke-TrustedInstaller "bcdedit /deletevalue useplatformclock"
Invoke-TrustedInstaller "bcdedit /set hypervisorlaunchtype off"
Invoke-TrustedInstaller "bcdedit /timeout 10"

# NTFS
Invoke-TrustedInstaller "fsutil behavior set disablelastaccess 1"
Invoke-TrustedInstaller "fsutil behavior set disable8dot3 1"
Invoke-TrustedInstaller "fsutil behavior set memoryusage 1"

#=======================================================================================================================
# SECTION III: Power Plan – Ultimate Performance
#=======================================================================================================================

Write-Log -Level HEADER -Message "SECTION III: Power Settings"
$UltGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"
Try {
    $existingPlan = powercfg /l | Select-String $UltGUID
    if (-not $existingPlan) { powercfg -duplicatescheme $UltGUID | Out-Null }
    powercfg /setactive $UltGUID
} Catch { Write-Log -Level WARN -Message "Unable to set Ultimate Performance plan." }

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

#=======================================================================================================================
# SECTION IV: Services and Scheduled Tasks Debloat
#=======================================================================================================================

Write-Log -Level HEADER -Message "SECTION IV: Services and Scheduled Tasks"

$ServicesToDisable = @(
    "DiagTrack","diagsvc","diagnosticshub.standardcollector.service","dmwappushservice","WerSvc",
    "AJRouter","AssignedAccessManagerSvc","BcastDVRUserService","DevicePickerUserSvc","DevicesFlowUserSvc","Fax","icssvc","lfsvc",
    "MapsBroker","MessagingService","OneSyncSvc","PcaSvc","PeerDistSvc","PhoneSvc","PrintNotify","Spooler","RetailDemo",
    "SensorDataService","SensorService","SensrSvc","SharedRealitySvc","WalletService","WbioSrvc","WdiServiceHost","WdiSystemHost",
    "wisvc","workfolderssvc","WwanSvc","XblAuthManager","XblGameSave","XboxGipSvc","XboxNetApiSvc",
    "RemoteRegistry","TermService","UmRdpService","SecurityHealthService","wscsvc","Sense",
    "SysMain","SEMgrSvc","spectrum","DoSvc","DPS"
)
$ServicesToSetManual = @(
    "bthserv","BluetoothUserService","BthAvctpSvc","hidserv","TabletInputService"
)
foreach ($service in $ServicesToDisable) {
    Try {
        $svc = Get-Service -Name $service -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') { Invoke-TrustedInstaller "sc.exe stop $service" }
        Invoke-TrustedInstaller "sc.exe config $service start= disabled"
    } Catch { Write-Log -Level WARN -Message "Service $service not present." }
}
foreach ($service in $ServicesToSetManual) {
    Try {
        $svc = Get-Service -Name $service -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') { Invoke-TrustedInstaller "sc.exe stop $service" }
        Invoke-TrustedInstaller "sc.exe config $service start= demand"
    } Catch {}
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
    } Catch { Write-Log -Level WARN -Message "Task $task not present." }
}

# Aggressive Windows Update destruction
Write-Log -Level HEADER -Message "AGGRESSIVE WINDOWS UPDATE DESTRUCTION"
$WU_Services = @("wuauserv","UsoSvc","WaaSMedicSvc")
foreach ($svc in $WU_Services) {
    Try {
        $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($svcObj -and $svcObj.Status -ne 'Stopped') { Invoke-TrustedInstaller "sc.exe stop $svc" }
        Invoke-TrustedInstaller "sc.exe config $svc start= disabled"
    } Catch {}
    $svcRegKey = "HKLM\SYSTEM\CurrentControlSet\Services\$svc"
    Try {
        if (Test-Path "Registry::$svcRegKey") { Invoke-TrustedInstaller "reg delete `"$svcRegKey`" /f" }
    } Catch {}
}

#=======================================================================================================================
# SECTION V: Deep Registry & Policy Hardening
#=======================================================================================================================

Write-Log -Level HEADER -Message "SECTION V: Registry & Policy Modifications"

# Telemetry and privacy
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableDeviceDelete" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoGeneralAppLaunchTracking" -Value 1 -Type "DWord"

# Performance
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\FTH" -Name "Enabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type "DWord"

# UAC off
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type "DWord"
# Administrator Protection legacy mode (explicit)
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "TypeOfAdminApprovalMode" -Value 1 -Type "DWord"

Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type "DWord"

# Additional PC‑Tuning tweaks
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Type "DWord"

# MMCSS tuning
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 10 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Type "String"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8 -Type "DWord"

# Global timer resolution (Windows 11+)
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Value 1 -Type "DWord"

# Disable GameBarPresenceWriter (activatable class)
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType" -Value 0 -Type "DWord"

# Windows Defender aggressive disable (PC‑Tuning additions)
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type "DWord"
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" -Name "ServiceEnabled" -Value 0 -Type "DWord"
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState" -Value 0 -Type "DWord"

# NVIDIA DisableDynamicPstate (lock P‑state 0 for all NVIDIA adapters)
$displayClass = "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
$subKeys = Get-ChildItem "Registry::$displayClass" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }
foreach ($sub in $subKeys) {
    $driverDesc = (Get-ItemProperty -Path $sub.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue).DriverDesc
    if ($driverDesc -and $driverDesc -like "*NVIDIA*") {
        Set-RegValue -Path "$displayClass\$($sub.PSChildName)" -Name "DisableDynamicPstate" -Value 1 -Type "DWord"
        Write-Log -Message "NVIDIA DisableDynamicPstate applied for subkey $($sub.PSChildName)"
    }
}

#=======================================================================================================================
# SECTION VI: Network Stack & Hosts
#=======================================================================================================================

Write-Log -Level HEADER -Message "SECTION VI: Network Stack & Hosts"
Try { Invoke-TrustedInstaller "netsh int tcp set global autotuninglevel=disabled" } Catch {}
Try { Invoke-TrustedInstaller "netsh int tcp set global rss=disabled" } Catch {}
Try {
    Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
        $regPath = "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($_.SettingID)"
        Set-RegValue -Path $regPath -Name "NetbiosOptions" -Value 2 -Type "DWord"
    }
} Catch {}

$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$TempHosts = "$env:TEMP\forged-hosts.txt"
@"# Forged Windows 11 - Minimal Hosts File
127.0.0.1       localhost
::1             localhost
"@ | Set-Content -Path $TempHosts -Encoding ASCII
if (Test-Path $HostsPath) { Copy-Item -Path $HostsPath -Destination "$HostsPath.bak" -Force }
Invoke-TrustedInstaller "takeown /f `"$HostsPath`""
Invoke-TrustedInstaller "icacls `"$HostsPath`" /grant `"$env:USERNAME`":F"
Copy-Item -Path $TempHosts -Destination $HostsPath -Force
Try { ipconfig /flushdns | Out-Null } Catch {}
Remove-Item $TempHosts -Force

#=======================================================================================================================
# SECTION VII: UI Sterilization & Branding (DefaultUser)
#=======================================================================================================================

Write-Log -Level HEADER -Message "SECTION VII: UI Sterilization (DefaultUser)"
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
    if (-not (Test-Path $DefaultUserLayoutDir)) { New-Item -ItemType Directory -Path $DefaultUserLayoutDir -Force | Out-Null }
    [System.IO.File]::WriteAllLines($DefaultUserLayoutXml, $LayoutXml -split "`r?`n", [System.Text.Encoding]::UTF8)
} Catch {}

if (Test-Path $WallpaperPath) {
    $DefaultUserHive = "C:\Users\Default\ntuser.dat"
    $MountKey = "HKLM\DefaultUser"
    Try {
        reg load $MountKey $DefaultUserHive | Out-Null
        Set-RegValue -Path "$MountKey\Control Panel\Desktop" -Name "Wallpaper" -Value $WallpaperPath -Type "String"
        Set-RegValue -Path "$MountKey\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10" -Type "String"
        Set-RegValue -Path "$MountKey\Control Panel\Desktop" -Name "TileWallpaper" -Value "0" -Type "String"
    } Catch {}
    Finally { Try { reg unload $MountKey | Out-Null } Catch {} }
}

# Remove default themes
$ThemePaths = @("$env:SystemRoot\Resources\Themes", "$env:SystemRoot\Resources\Ease of Access Themes")
foreach ($path in $ThemePaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter "*.theme" -File -ErrorAction SilentlyContinue | ForEach-Object {
            Try {
                Invoke-TrustedInstaller "takeown /f `"$($_.FullName)`""
                Invoke-TrustedInstaller "icacls `"$($_.FullName)`" /grant `"$env:USERNAME`":F"
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            } Catch {}
        }
    }
}

# Classic context menu for new users
$CCMKeyDefaultUser = "HKLM\DefaultUser\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
Try {
    $DefaultUserHive = "C:\Users\Default\ntuser.dat"
    $MountKey = "HKLM\DefaultUser"
    reg load $MountKey $DefaultUserHive | Out-Null
    if (-not (Test-Path "Registry::$CCMKeyDefaultUser")) { New-Item -Path "Registry::$CCMKeyDefaultUser" -Force | Out-Null }
    Set-ItemProperty -Path "Registry::$CCMKeyDefaultUser" -Name '(default)' -Value "" -Force
    reg unload $MountKey | Out-Null
} Catch {}

Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "" -Type "String"

#=======================================================================================================================
# SECTION VIII: Finalization & Self‑Destruction
#=======================================================================================================================

Write-Log -Level HEADER -Message "SECTION VIII: Finalization & Reboot Prep"
Try { Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Try { Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Try { Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue } Catch {}
Try {
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
        Try { wevtutil.exe cl $_.LogName } Catch {}
    }
} Catch {}
Invoke-TrustedInstaller "dism.exe /online /cleanup-image /startcomponentcleanup"

Write-Log -Level HEADER -Message "OPTIMIZATION COMPLETE. REBOOT IN 5 SECONDS."
$ScriptPathToDelete = $MyInvocation.MyCommand.Path
$SelfDestructCommand = "Start-Sleep -Seconds 5; Remove-Item -Path `"$ScriptPathToDelete`" -Force; shutdown /r /f /t 1"
Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -Command `"$SelfDestructCommand`"" -NoNewWindow
