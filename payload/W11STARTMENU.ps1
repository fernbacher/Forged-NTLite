# Clear W11 Start Menu pins

Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue

# Remove CloudStore Cache
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Recurse -Force -ErrorAction SilentlyContinue

# Remove LocalState bins
$localState = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
Remove-Item -Path "$localState\start.bin" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$localState\start2.bin" -Force -ErrorAction SilentlyContinue

Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process 'explorer.exe'
