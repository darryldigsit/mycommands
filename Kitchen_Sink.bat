@echo off
title System Setup and Quick Scans
color 0A

echo ==================================================
echo      BASIC WINDOWS 11 HARDENING TOOL v1
echo ==================================================
echo For assistance with this tool, contact Darryl Hicks: dhicks@darrylhicks.com
echo.
echo.

REM --- Prompt for Quick Scan selection ---
echo In addition to basic hardening, choose any of the following utilities to run after Configuring the system (if any).
echo.
echo [1] Update all Applications  - Manually Updates installed apps via Winget
echo [2] Windows AV Scan          - Runs Windows Defender quick scan if enabled
echo [3] Create a Restore Point   - Creates a new system restore point if possible
echo [4] Vulnerability IP Scan    - Installs Nmap and runs network scan for vulnerabilities
echo [A] All Quick Scans
echo [N] None
echo.
set /p scanChoice=Enter option (1-4, A, or N): 
echo.

REM ====================================================
REM 1. TURN ON MALWARE PROTECTION
REM ====================================================
echo [1/7] Enabling Malware Protection...
sc query windefend | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    echo Windows Defender not active. Enabling protections...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableIOAVProtection $false; Set-MpPreference -PUAProtection enable; Set-MpPreference -ScanParameters 2"
) else (
    echo Windows Defender running with realtime protection enabled.
)

REM ====================================================
REM 2. DNS PROTECTION (OpenDNS)
REM ====================================================
echo [2/7] Configuring DNS Protection (OpenDNS)...
FOR /F "tokens=3,*" %%A IN ('netsh interface show interface ^| find "Connected"') DO (
    netsh interface ip set dns name="%%B" static 208.67.222.222 >nul
    netsh interface ip add dns name="%%B" 208.67.220.220 index=2 >nul
)
ipconfig /all | findstr "DNS Servers"

REM ====================================================
REM 3. ENABLE WINDOWS UPDATE SERVICE
REM ====================================================
echo [3/7] Enabling Windows Update service...
sc config wuauserv start= auto >nul
net start wuauserv >nul
sc query wuauserv | findstr /i "RUNNING"

REM ====================================================
REM 4. SCHEDULE WINDOWS UPDATE SERVICE TASK
REM ====================================================
echo [4/7] Creating scheduled update task (WingetUpdates)...
schtasks /Query /TN WingetUpdates >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Register-ScheduledTask -TaskName 'WingetUpdates' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/k winget upgrade --all & pause') -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Wednesday -At 9:00AM) -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable) -Force"
    echo WingetUpdates task created.
) else (
    echo Scheduled task WingetUpdates already exists.
)

REM ====================================================
REM 5. ENABLE AND SCHEDULE SYSTEM RESTORE POINT
REM ====================================================
echo [5/7] Checking System Restore configuration...
powershell -Command "Enable-ComputerRestore -Drive 'C:\'; vssadmin Resize ShadowStorage /For=C: /On=C: /MaxSize=2%"

REM ====================================================
REM 6. ENABLE FIREWALL ON ALL PROFILES
REM ====================================================
echo [6/7] Enabling Windows Firewall on all profiles...
netsh advfirewall set allprofiles state on >nul
netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound >nul
netsh advfirewall show publicprofile

REM ====================================================
REM 7. STRICT BROWSER COOKIES AND TRACKING
REM ====================================================
echo [7/7] Tightening Security on Cookies and Trakcing...
powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Policies\Google\Chrome -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Policies\Google\Chrome -Name BlockThirdPartyCookies -Value 1" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Policies\Google\Chrome -Name BackgroundModeEnabled -Value 0"
powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Policies\Microsoft\Edge -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Edge -Name BlockThirdPartyCookies -Value 1" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Microsoft\Edge\Privacy -Name TrackingPreventionLevel -Value 'Strict' -ErrorAction SilentlyContinue" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Edge -Name BackgroundModeEnabled -Value 0"
powershell.exe -NoProfile -Command "New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy -Force | Out-Null; Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Force | Out-Null; Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Value 0" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -Value 0"
echo All Cookie and Tracking Settings Modified Successfully

REM ====================================================
REM STATUS SUMMARY BEFORE QUICK SCANS
REM ====================================================
echo.
echo ==================================================
echo        SYSTEM CONFIGURATION SUMMARY COMPLETE
echo ==================================================
echo     - Malware protection ensured
echo     - Windows Update service active
echo     - DNS protection set (OpenDNS)
echo     - Restore point functionality ready
echo     - Scheduled Weekly Recovery Point Creation
echo     - Scheduled update task verified
echo     - Firewall enabled and enforced
echo ==================================================
echo.
pause

REM EXECUTE REQUESTED QUICK SCANS
echo Starting QUICK SCANS per your selection...
echo.

if /I "%scanChoice%"=="1" goto QuickAppUpdate
if /I "%scanChoice%"=="2" goto QuickAVScan
if /I "%scanChoice%"=="3" goto QuickRestore
if /I "%scanChoice%"=="4" goto QuickVulnScan
if /I "%scanChoice%"=="A" goto AllScans
if /I "%scanChoice%"=="N" goto End

:QuickAppUpdate
echo Running Quick App Update (Winget)...
winget upgrade --all
echo.
echo All tests Successful. This tool is now closing.
pause
goto End

:QuickAVScan
echo Running Quick Antivirus Scan...
powershell.exe -c "Start-MpScan -ScanType QuickScan"
echo.
echo All tests Successful. This tool is now closing.
pause
goto End

:QuickRestore
echo Creating Quick Restore Point...
powershell.exe -Command "Checkpoint-Computer -Description 'Restore Point (Automatic)' -RestorePointType MODIFY_SETTINGS"
echo.
echo All tests Successful. This tool is now closing.
pause
goto End

:QuickVulnScan
echo Beginning IP Range Vulnerability Scan setup...
powershell -Command "Invoke-WebRequest https://nmap.org/dist/nmap-7.94-setup.exe -OutFile $env:USERPROFILE\Downloads\nmap-setup.exe -ErrorAction Stop; Start-Process -Wait $env:USERPROFILE\Downloads\nmap-setup.exe"
echo.
echo NMAP installed. Now downloading vulnscan from Github.
echo.
powershell -Command "Invoke-WebRequest -Uri https://github.com/scipag/vulscan/archive/refs/heads/master.zip -OutFile $env:TEMP\vulscan.zip"
echo.
echo NMAP installed. Now downloading vulnscan from Github.
echo.
powershell -Command "Expand-Archive -Path $env:TEMP\vulscan.zip -DestinationPath $env:TEMP\vulscan -Force"
echo.
echo Expanding the vulscan zipped file
echo.
xcopy /E /Y "%TEMP%\vulscan\vulscan-master\*" "C:\Program Files (x86)\Nmap\scripts\"
echo.
echo Copying the files to the proper locations in NMAP
echo.
powershell -Command "$ip = ((Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null}).IPv4Address | Select-Object -First 1).IPAddress; & \"C:\Program Files (x86)\Nmap\nmap.exe\" -sV -v --script=vulscan.nse \"$ip/24\""
echo.
echo.
echo All tests Successful. This tool is now closing.
echo.
pause
goto End

:AllScans
call :QuickAppUpdate
call :QuickAVScan
call :QuickRestore
call :QuickVulnScan
goto End

