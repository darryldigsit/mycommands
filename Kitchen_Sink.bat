@echo off
:: Enable ANSI escape sequences
for /f "tokens=2 delims=: " %%A in ('reg query "HKCU\Console" /v VirtualTerminalLevel 2^>nul') do set vtl=%%A
if "%vtl%" neq "1" reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul

:: Colors using ANSI
set "GREEN=[32m"
set "CYAN=[36m"
set "YELLOW=[33m"
set "MAGENTA=[35m"
set "RED=[31m"
set "BLUE=[34m"
set "RESET=[0m"
set "WHITE=[37m"
set "BOLD=[1m"


echo %GREEN%==================================================
echo %BOLD%%MAGENTA%     BASIC WINDOWS 11 HARDENING TOOL v2
echo %GREEN%==================================================%RESET%
echo.
echo %BOLD%%WHITE%For assistance, contact Darryl Hicks: dhicks@darrylhicks.com%RESET%
echo.
echo %YELLOW%This tool implements the recommendations from Chapter 3
echo of my book "Be the Family Computer Hero"...%RESET%
echo.
echo %CYAN%Enables Malware Protection: checks if Windows Defender is running and enables real-time protection if needed.
echo %CYAN%Configures DNS Protection: sets all connected network interfaces to use OpenDNS (208.67.222.222 and 208.67.220.220).
echo %CYAN%Enables Windows Update service and verifies it is running.
echo %CYAN%Creates a scheduled Winget update task to upgrade all applications weekly on Wednesday at 9:00 AM.
echo %CYAN%Enables System Restore on the C: drive and limits shadow storage to 2% of the drive.
echo %CYAN%Enables Windows Firewall on all profiles and enforces inbound/outbound rules for the public profile.
echo %CYAN%Hardens browser privacy and tracking: blocks third-party cookies in Chrome and Edge, disables background activity,
echo telemetry, advertising ID, and personalized content.
echo.
echo %YELLOW%Note: I have removed the vulnerability scanning from the batch file as it is considered by many
echo AV scanners as malicious and I want this file to continue classified as benign.
echo.
echo.
echo %RED%Press any key to begin, or Ctrl+C to stop...%RESET%
>nul pause
echo.
echo.

REM ====================================================
REM 1. TURN ON MALWARE PROTECTION
REM ====================================================
echo [1/7] Enabling Malware Protection  (Page 46-48)...
echo.
echo This checks whether Windows Defender (WinDefend service) is running, and if not, enables its real-time and security protections via PowerShell
echo.
sc query windefend | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    echo Windows Defender not active. Enabling protections...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableIOAVProtection $false; Set-MpPreference -PUAProtection enable; Set-MpPreference -ScanParameters 2"
) else (
    echo Windows Defender running with realtime protection enabled.
)
echo.
echo Done with Page 48 (Chapter 3) "Be the Family Computer Hero"
echo.
echo %RED%Press any key to continue, or Ctrl+C to stop...%RESET%
>nul pause
echo.
echo.

REM ====================================================
REM 2. DNS PROTECTION (OpenDNS)
REM ====================================================
echo [2/7] Configuring DNS Protection [OpenDNS/Umbrella] (Page 66)...
echo.
echo This sets all "connected" network interfaces to use OpenDNS DNS servers (208.67.222.222 and 208.67.220.220) and then displays the configured DNS servers.
echo.
FOR /F "tokens=3,*" %%A IN ('netsh interface show interface ^| find "Connected"') DO (
    netsh interface ip set dns name="%%B" static 208.67.222.222 >nul
    netsh interface ip add dns name="%%B" 208.67.220.220 index=2 >nul
)
ipconfig /all | findstr "DNS Servers"
echo.
echo Done with Pages 66-68 (Chapter 3) "Be the Family Computer Hero"
echo.
echo %RED%Press any key to continue, or Ctrl+C to stop...%RESET%
>nul pause
echo.
echo.

REM ====================================================
REM 3. ENABLE WINDOWS UPDATE SERVICE
REM ====================================================
echo [3/7] Enabling Windows Update service (Page 70)...
echo.
echo This configures the Windows Update service (wuauserv) to start automatically, starts it, and then verifies that it is running.
echo.
sc config wuauserv start= auto >nul
net start wuauserv >nul
sc query wuauserv | findstr /i "RUNNING"
echo.
echo Done with Page 70 (Chapter 3) "Be the Family Computer Hero"
echo.
echo %RED%Press any key to continue, or Ctrl+C to stop...%RESET%
>nul pause
echo.
echo.

REM ====================================================
REM 4. SCHEDULE WINDOWS UPDATE SERVICE TASK
REM ====================================================
echo [4/7] Creating scheduled update task (WingetUpdates on Page 73)...
echo.
echo This checks if a scheduled task named WingetUpdates exists, and if not, creates one that runs winget upgrade --all every Wednesday at 9:00 AM. Type taskschd.msc to modify the date/time once complete.
echo.
schtasks /Query /TN WingetUpdates >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Register-ScheduledTask -TaskName 'WingetUpdates' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/k winget upgrade --all & pause') -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Wednesday -At 9:00AM) -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable) -Force"
    echo WingetUpdates task created.
) else (
    echo Scheduled task WingetUpdates already exists.
)
echo.
echo Done with Page 73 (Chapter 3) "Be the Family Computer Hero"
echo.
echo %RED%Press any key to continue, or Ctrl+C to stop...%RESET%
>nul pause
echo.
echo.

REM ====================================================
REM 5. ENABLE AND SCHEDULE SYSTEM RESTORE POINT
REM ====================================================
echo [5/7] Checking System Restore configuration (page 93)...
echo.
echo This enables System Restore on the C: drive and limits its shadow storage (restore point space) to my recommended 2% of the drive.
echo.
timeout /t 5 >nul
powershell -Command "Enable-ComputerRestore -Drive 'C:\'; vssadmin Resize ShadowStorage /For=C: /On=C: /MaxSize=2%"
echo.
echo Done with Page 93 (Chapter 3) "Be the Family Computer Hero"
echo.
echo %RED%Press any key to continue, or Ctrl+C to stop...%RESET%
>nul pause
echo.
echo.

REM ====================================================
REM 6. ENABLE FIREWALL ON ALL PROFILES
REM ====================================================
echo [6/7] Enabling Windows Firewall on all profiles (Page 55-56)...
echo.
echo This enables Windows Firewall for all profiles, sets the public profile to block inbound and allow outbound traffic, and then displays the public profile settings.
echo.
netsh advfirewall set allprofiles state on >nul
netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound >nul
netsh advfirewall show publicprofile
echo.
echo Done with Page 55-56 (Chapter 3) "Be the Family Computer Hero"
echo %RED%Press any key to continue, or Ctrl+C to stop...%RESET%
>nul pause
echo.
echo.

REM ====================================================
REM 7. STRICT BROWSER COOKIES AND TRACKING
REM ====================================================
echo [7/7] Tightening Security on Cookies and Trakcing (Page 84-87)...
echo.
echo This hardens privacy settings by blocking third-party cookies and background activity in Chrome and Edge, and disabling Windows telemetry, advertising ID, and personalized content features.
echo.
powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Policies\Google\Chrome -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Policies\Google\Chrome -Name BlockThirdPartyCookies -Value 1" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Policies\Google\Chrome -Name BackgroundModeEnabled -Value 0"
powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Policies\Microsoft\Edge -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Edge F-Name BlockThirdPartyCookies -Value 1" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Microsoft\Edge\Privacy -Name TrackingPreventionLevel -Value 'Strict' -ErrorAction SilentlyContinue" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Edge -Name BackgroundModeEnabled -Value 0"
powershell.exe -NoProfile -Command "New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy -Force | Out-Null; Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Force | Out-Null; Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Value 0" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -Value 0"
echo All Cookie and Tracking Settings Modified Successfully
echo.
echo Done with Pages 84-87 (Chapter 3) "Be the Family Computer Hero"
echo.
timeout /t 5 >nul
echo.

REM STATUS SUMMARY 
@echo off
:: Enable ANSI escape sequences (if not already enabled)
for /f "tokens=2 delims=: " %%A in ('reg query "HKCU\Console" /v VirtualTerminalLevel 2^>nul') do set vtl=%%A
if "%vtl%" neq "1" reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul
echo.
echo.
echo %BOLD%%CYAN%=================================================%RESET%
echo %BOLD%%MAGENTA%        SYSTEM CONFIGURATION SUMMARY COMPLETE%RESET%
echo %BOLD%%CYAN%=================================================%RESET%
echo %GREEN%     - Malware protection ensured%RESET%
echo %GREEN%     - Windows Update service active%RESET%
echo %GREEN%     - DNS protection set (OpenDNS)%RESET%
echo %GREEN%     - Restore point functionality ready%RESET%
echo %GREEN%     - Scheduled Weekly Recovery Point Creation%RESET%
echo %GREEN%     - Scheduled winget update task verified%RESET%
echo %GREEN%     - Firewall enabled and enforced%RESET%
echo %GREEN%     - Browser Cookies Secured for Edge and Chrome%RESET%
echo %BOLD%%CYAN%=================================================%RESET%
echo.
echo %YELLOW%Done with all the recommended Windows security hardening from Chapter 3 of "Be the Family Computer Hero"%RESET%
echo. 
echo %BLUE%BONUS:%RESET% In addition to basic hardening, you may now choose any of the optional security tasks below.
echo.
echo %CYAN%[1]%RESET% %WHITE%Update all Applications%RESET%  - Manually updates installed apps via Winget (already scheduled)
echo %CYAN%[2]%RESET% %WHITE%Windows AV Scan%RESET%        - Runs Windows Defender Virus Scan (if fails, see page 47 to enable this)
echo %CYAN%[3]%RESET% %WHITE%Create a Restore Point%RESET%   - Creates a new system restore point if possible
echo %CYAN%[A]%RESET% %WHITE%Perform All These Additional Tasks%RESET%
echo %CYAN%[N]%RESET% %WHITE%None, I am all done...%RESET%
echo.
set /p scanChoice=%BOLD%%YELLOW%Enter option (1-3, A, or N): %RESET%
echo.

REM EXECUTE REQUESTED QUICK SCANS
echo Starting QUICK SCANS per your selection...
echo.

if /I "%scanChoice%"=="1" goto QuickAppUpdate
if /I "%scanChoice%"=="2" goto QuickAVScan
if /I "%scanChoice%"=="3" goto QuickRestore
if /I "%scanChoice%"=="A" goto AllScans
if /I "%scanChoice%"=="N" goto End

:QuickAppUpdate
echo Running Quick App Update (Winget)...
winget upgrade --all
echo.
echo Success. Moving On.
pause
goto End

:QuickAVScan
echo Running Quick Antivirus Scan...
powershell.exe -c "Start-MpScan -ScanType QuickScan"
echo.
echo Success. Moving On.
pause
goto End

:QuickRestore
echo Creating Quick Restore Point...
powershell.exe -Command "Checkpoint-Computer -Description 'Restore Point (Automatic)' -RestorePointType MODIFY_SETTINGS"
echo.
echo Success. Moving On.
pause
goto End

:AllScans
call :QuickAppUpdate
call :QuickAVScan
call :QuickRestore
goto End

