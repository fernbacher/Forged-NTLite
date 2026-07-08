param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("SpoofRegion", "Browser", "Runtime", "Updater", "RestoreRegion")]
    [string]$Action
)

$Components = @{
    Browser = @{
        Guid         = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
        UninstallKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge'
        Shortcuts    = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
            "$env:PUBLIC\Desktop\Microsoft Edge.lnk"
            "$env:USERPROFILE\Desktop\Microsoft Edge.lnk"
        )
        EnableDevPolicy = $true
    }
    Runtime = @{
        Guid         = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
        UninstallKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView'
        Shortcuts    = @()
        EnableDevPolicy = $false
    }
}

$GeoKey        = 'HKEY_USERS\.DEFAULT\Control Panel\International\Geo'
$RegionKey     = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\DeviceRegion'
$EdgeUpdateRoot = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate'

function Run-AsTrustedInstaller {
    param([string]$Command)
    $ti = Join-Path $PSScriptRoot "MinSudo.exe"
    if (Test-Path $ti) {
        Start-Process $ti -ArgumentList "--TrustedInstaller --NoLogo $Command" -Wait -WindowStyle Hidden
    }
}

switch ($Action) {

    "SpoofRegion" {
        $nation = [Microsoft.Win32.Registry]::GetValue($GeoKey, 'Nation', $null)
        if ($null -ne $nation) {
            [Microsoft.Win32.Registry]::SetValue($GeoKey, 'XOS_SavedNation', $nation, [Microsoft.Win32.RegistryValueKind]::String)
        }
        Run-AsTrustedInstaller "reg.exe add `"$RegionKey`" /v DeviceRegion /t REG_DWORD /d 244 /f"
        [Microsoft.Win32.Registry]::SetValue($GeoKey, 'Nation', '244', [Microsoft.Win32.RegistryValueKind]::String)
    }

    "RestoreRegion" {
        $saved = [Microsoft.Win32.Registry]::GetValue($GeoKey, 'XOS_SavedNation', $null)
        $restoreTo = if ($null -ne $saved) { $saved } else { '244' }

        Run-AsTrustedInstaller "reg.exe add `"$RegionKey`" /v DeviceRegion /t REG_DWORD /d $restoreTo /f"
        [Microsoft.Win32.Registry]::SetValue($GeoKey, 'Nation', $restoreTo, [Microsoft.Win32.RegistryValueKind]::String)

        if ($null -ne $saved) {
            $key = [Microsoft.Win32.Registry]::Users.OpenSubKey('.DEFAULT\Control Panel\International\Geo', $true)
            if ($key) { $key.DeleteValue('XOS_SavedNation', $false); $key.Close() }
        }
    }

    { $_ -in "Browser", "Runtime" } {
        $comp = $Components[$Action]
        $clientState = "$EdgeUpdateRoot\ClientState\$($comp.Guid)"

        Remove-ItemProperty -Path $comp.UninstallKey -Name "NoRemove" -ErrorAction SilentlyContinue | Out-Null

        if ($comp.EnableDevPolicy) {
            $dk = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev')
            $dk.SetValue('AllowUninstall', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
            $dk.Close()
        }

        if (-not (Test-Path $clientState)) { return }
        Remove-ItemProperty -Path $clientState -Name "experiment_control_labels" -ErrorAction SilentlyContinue | Out-Null

        # Plant stub so Windows recognizes an alternative browser, required for non-EU uninstall
        $stubPath = "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
        try {
            if (-not (Test-Path $stubPath)) { New-Item -ItemType Directory -Path $stubPath -Force | Out-Null }
            New-Item -ItemType File -Path (Join-Path $stubPath "MicrosoftEdge.exe") -Force | Out-Null
        } catch { return }

        $info = Get-ItemProperty -Path $clientState
        if ([string]::IsNullOrEmpty($info.UninstallString) -or [string]::IsNullOrEmpty($info.UninstallArguments)) { return }
        if (-not (Test-Path $info.UninstallString)) { return }

        # Older Edge builds refuse to uninstall when windir is set
        $origWinDir = $env:windir
        try {
            $env:windir = ""
            Start-Process -FilePath $info.UninstallString -ArgumentList "$($info.UninstallArguments) --force-uninstall --delete-profile" -Wait -NoNewWindow
        } finally {
            $env:windir = $origWinDir
        }

        foreach ($lnk in $comp.Shortcuts) {
            if (Test-Path $lnk) { Remove-Item $lnk -Force }
        }
    }

    "Updater" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" -Name "NoRemove" -ErrorAction SilentlyContinue | Out-Null
        if (-not (Test-Path $EdgeUpdateRoot)) { return }
        $cmd = (Get-ItemProperty -Path $EdgeUpdateRoot).UninstallCmdLine
        if (-not [string]::IsNullOrEmpty($cmd)) {
            Start-Process cmd.exe "/c $cmd" -WindowStyle Hidden -Wait
        }
    }
}
