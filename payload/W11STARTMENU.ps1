# Clear W11/W10 Start Menu pins -- XOS-derived surgical approach
# Handles both Windows 10 and Windows 11 start menu layouts

# Blank layout with DefaultLayoutOverride to force zero tiles
$blankLayoutXml = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6">
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

# Kill StartMenuExperienceHost so it releases its file/registry locks
Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# --- Write blank layout to Default user profile (new accounts get zero pins) ---
$defaultShell = "$env:SystemDrive\Users\Default\AppData\Local\Microsoft\Windows\Shell"
if (-not (Test-Path $defaultShell)) { New-Item -Path $defaultShell -ItemType Directory -Force | Out-Null }
$blankLayoutXml | Out-File -FilePath "$defaultShell\LayoutModification.xml" -Encoding UTF8 -Force
# Delete any stale DefaultLayouts.xml so it can't override our blank layout
$defaultLayouts = "$defaultShell\DefaultLayouts.xml"
if (Test-Path $defaultLayouts) { Remove-Item $defaultLayouts -Force -ErrorAction SilentlyContinue }

# --- Write blank layout to current user ---
$userShell = "$env:LOCALAPPDATA\Microsoft\Windows\Shell"
if (-not (Test-Path $userShell)) { New-Item -Path $userShell -ItemType Directory -Force | Out-Null }
$blankLayoutXml | Out-File -FilePath "$userShell\LayoutModification.xml" -Encoding UTF8 -Force

# --- Apply blank layout to running system via Import-StartLayout ---
$tempLayout = "$env:TEMP\BlankStartLayout.xml"
$blankLayoutXml | Out-File -FilePath $tempLayout -Encoding UTF8 -Force
try { Import-StartLayout -LayoutPath $tempLayout -MountPath "$env:SystemDrive\" -ErrorAction SilentlyContinue } catch {}
Remove-Item $tempLayout -Force -ErrorAction SilentlyContinue

# --- Surgical CloudStore cleanup: only delete tile entries, not the whole cache ---
$cloudStorePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount'
if (Test-Path $cloudStorePath) {
    Get-ChildItem -Path $cloudStorePath -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -like '*start.tilegrid$windows.data.primarytilecollection*' -or
        $_.PSChildName -like '*start.tilegrid$windows.data.curatedtilecollection*' -or
        $_.PSChildName -like '*start.tilegrid$windows.data.startmenupinned*'
    } | ForEach-Object {
        Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Delete any cached start .bin files ---
Get-ChildItem -Path "$userShell\*.bin" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# Also wipe any .bin files from the StartMenuExperienceHost package localstate
$startLocalState = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
if (Test-Path $startLocalState) {
    Get-ChildItem -Path "$startLocalState\*.bin" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

# --- Lock/unlock trick: force Windows to re-read the layout ---
New-Item -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Force -ErrorAction SilentlyContinue | Out-Null
try {
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'LockedStartLayout' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'StartLayoutFile' -Value "$userShell\LayoutModification.xml" -Type ExpandString -Force
    Start-Process 'explorer.exe' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}
finally {
    # Always unlock so the user isn't stuck with a locked (uneditable) start menu
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'LockedStartLayout' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
}

# Final explorer restart for clean state
Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process 'explorer.exe'
