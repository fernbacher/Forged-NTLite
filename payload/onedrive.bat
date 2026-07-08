@echo off
SETLOCAL EnableDelayedExpansion

taskkill /f /im OneDrive.exe > nul 2>&1
taskkill /f /im OneDrive.App.exe > nul 2>&1
taskkill /f /im FileCoAuth.exe > nul 2>&1

:: Run the registry uninstaller before deleting files (per-machine install)
for %%k in (
	"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDrive"
	"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDrive"
	"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDrive"
) do (
	for /f "tokens=2,*" %%a in ('reg query %%k /v UninstallString 2^>nul ^| findstr /i "UninstallString"') do (
		%%b > nul 2>&1
	)
)

:: Run any remaining OneDriveSetup.exe
for %%a in (
	"%windir%\System32\OneDriveSetup.exe"
	"%windir%\SysWOW64\OneDriveSetup.exe"
) do (
	if exist "%%a" "%%a" /uninstall > nul 2>&1
)
for %%r in (
	"%ProgramFiles%\Microsoft OneDrive"
	"%ProgramFiles(x86)%\Microsoft OneDrive"
	"%LOCALAPPDATA%\Microsoft\OneDrive"
) do (
	if exist "%%~r" (
		for /f "delims=" %%f in ('dir /b /s "%%~r\OneDriveSetup.exe" 2^>nul') do "%%f" /uninstall > nul 2>&1
	)
)

rmdir /q /s "%ProgramData%\Microsoft OneDrive" > nul 2>&1
rmdir /q /s "%ProgramFiles%\Microsoft OneDrive" > nul 2>&1
rmdir /q /s "%ProgramFiles(x86)%\Microsoft OneDrive" > nul 2>&1
rmdir /q /s "%LOCALAPPDATA%\Microsoft\OneDrive" > nul 2>&1

for /f "usebackq delims=" %%a in (`dir /b /a:d "%SystemDrive%\Users"`) do (
	rmdir /q /s "%SystemDrive%\Users\%%a\AppData\Local\Microsoft\OneDrive" > nul 2>&1
	rmdir /q /s "%SystemDrive%\Users\%%a\OneDrive" > nul 2>&1
	del /q /f "%SystemDrive%\Users\%%a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" > nul 2>&1
	del /q /f "%SystemDrive%\Users\%%a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive*.lnk" > nul 2>&1
)
del /q /f "%ProgramData%\Microsoft\Windows\Start Menu\Programs\OneDrive*.lnk" > nul 2>&1

:: Remove the per-machine Uninstall entries (Installed apps list)
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDrive" /f > nul 2>&1
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDrive" /f > nul 2>&1

for /f "usebackq delims=" %%a in (`reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" ^| findstr /i /c:"OneDrive"`) do reg delete "%%a" /f > nul 2>&1

for /f "tokens=2 delims=\" %%a in ('schtasks /query /fo list /v ^| findstr /c:"\OneDrive Reporting Task" /c:"\OneDrive Standalone Update Task"') do (
	schtasks /delete /tn "%%a" /f > nul 2>&1
)

for /f "usebackq delims=" %%s in (`reg query HKU 2^>nul ^| findstr /r "S-1-5-21-[0-9]*-[0-9]*-[0-9]*$"`) do (
	for /f "usebackq delims=" %%a in (`reg query "%%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BannerStore" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
		reg delete "%%a" /f > nul 2>&1
	)
	for /f "usebackq delims=" %%a in (`reg query "%%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
		reg delete "%%a" /f > nul 2>&1
	)
	for /f "usebackq delims=" %%a in (`reg query "%%s\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
		reg delete "%%a" /f > nul 2>&1
	)
	for /f "usebackq delims=" %%a in (`reg query "%%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
		reg delete "%%a" /f > nul 2>&1
	)
	for /f "usebackq delims=" %%a in (`reg query "%%s\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
		reg delete "%%a" /f > nul 2>&1
	)
	reg add "%%s\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f > nul 2>&1
	reg add "%%s\SOFTWARE\Classes\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f > nul 2>&1
	reg delete "%%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
	reg delete "%%s\Environment" /v "OneDrive" /f > nul 2>&1
	reg delete "%%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > nul 2>&1
	reg delete "%%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f > nul 2>&1
	:: Clear the tray icon cache
	reg delete "%%s\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify" /v "IconStreams" /f > nul 2>&1
	reg delete "%%s\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify" /v "PastIconsStream" /f > nul 2>&1
)

:: Clean the Default profile so new accounts don't get OneDrive
reg load "HKU\XOSDefault" "%SystemDrive%\Users\Default\NTUSER.DAT" > nul 2>&1
if not errorlevel 1 (
	reg delete "HKU\XOSDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > nul 2>&1
	reg delete "HKU\XOSDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f > nul 2>&1
	reg add "HKU\XOSDefault\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f > nul 2>&1
	reg add "HKU\XOSDefault\SOFTWARE\Classes\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f > nul 2>&1
	reg delete "HKU\XOSDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
	reg unload "HKU\XOSDefault" > nul 2>&1
)

exit /b
