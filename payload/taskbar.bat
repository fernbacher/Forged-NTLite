@echo off
SETLOCAL EnableExtensions

taskkill /f /im explorer.exe >nul 2>&1
set "TaskbarPath=%AppData%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
if exist "%TaskbarPath%\Outlook.lnk" del /F /Q "%TaskbarPath%\Outlook.lnk"
if exist "%TaskbarPath%\Outlook (new).lnk" del /F /Q "%TaskbarPath%\Outlook (new).lnk"
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v Favorites /f >nul 2>&1
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v FavoritesResolve /f >nul 2>&1
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v FavoritesChanges /f >nul 2>&1
REG ADD "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f >nul 2>&1
start explorer.exe

del /q/f/s %TEMP%\*
start /b "" cmd /c del "%~f0"&exit /b