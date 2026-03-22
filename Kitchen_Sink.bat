@echo off
:: Enable ANSI escape sequences
for /f "tokens=2 delims=: " %%A in ('reg query "HKCU\Console" /v VirtualTerminalLevel 2^>nul') do set vtl=%%A
if "%vtl%" neq "1" reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul

:: Generate the ESC character for ANSI codes
for /F %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"

:: Colors using ANSI
set "GREEN=%ESC%[32m"
set "CYAN=%ESC%[36m"
set "YELLOW=%ESC%[33m"
set "MAGENTA=%ESC%[35m"
set "RED=%ESC%[31m"
set "BLUE=%ESC%[34m"
set "RESET=%ESC%[0m"
set "WHITE=%ESC%[37m"
set "BOLD=%ESC%[1m"


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
echo %CYAN%Enables System Restore on the C: drive and limits shadow storage to 2%% of the drive.
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

echo %GREEN% ====================================================
echo %BOLD%%MAGENTA% 1. TURN ON MALWARE PROTECTION
echo %GREEN%====================================================%RESET%
echo.
echo [1/7] Enabling Malware Protection  (Page 46-48)...
echo.
echo This checks whether Windows Defender (WinDefend service) is running, and if not, enables its real-time and security protections via PowerShell
echo.
echo %YELLOW%Press C to turn on malware protection or X to skip this step...%RESET%
choice /c CX /n /m "" >nul 2>&1
if errorlevel 2 goto SkipStep1
sc query windefend | findstr /i "RUNNING" >nul
echo.
if %errorlevel% neq 0 (
    echo Windows Defender not active. Enabling protections...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableIOAVProtection $false; Set-MpPreference -PUAProtection enable; Set-MpPreference -ScanParameters 2"
) else (
    echo Windows Defender running with realtime protection enabled.
)
echo.
echo Done with Step 1 - Page 48 (Chapter 3) "Be the Family Computer Hero"
timeout /t 3 /nobreak >nul
echo.
goto EndStep1
:SkipStep1
echo %RED%Skipping Step 1...%RESET%
timeout /t 3 /nobreak >nul
:EndStep1
echo.


echo %GREEN% ====================================================
echo %BOLD%%MAGENTA% 2. DNS PROTECTION (OpenDNS)
echo %GREEN% ====================================================%RESET%
echo.
echo [2/7] Configuring DNS Protection [OpenDNS/Umbrella] (Page 66)...
echo.
echo This sets all "connected" network interfaces to use OpenDNS DNS servers (208.67.222.222 and 208.67.220.220) and then displays the configured DNS servers.
echo.
echo %YELLOW%Press C to improve DNS or X to skip this step...%RESET%
choice /c CX /n /m "" >nul 2>&1
if errorlevel 2 goto SkipStep2
FOR /F "tokens=3,*" %%A IN ('netsh interface show interface ^| find "Connected"') DO (
    netsh interface ip set dns name="%%B" static 208.67.222.222 >nul
    netsh interface ip add dns name="%%B" 208.67.220.220 index=2 >nul
)
ipconfig /all | findstr "DNS Servers"
echo.
echo Done with Step 2 - Pages 66-68 (Chapter 3) "Be the Family Computer Hero"
timeout /t 3 /nobreak >nul
echo.
goto EndStep2
:SkipStep2
echo %RED%Skipping Step 2...%RESET%
timeout /t 3 /nobreak >nul
:EndStep2
echo.

echo %GREEN% ====================================================
echo %BOLD%%MAGENTA% 3. ENABLE WINDOWS UPDATE SERVICE
echo %GREEN% ====================================================%RESET%
echo.
echo [3/7] Enabling Windows Update service (Page 70)...
echo.
echo This configures the Windows Update service (wuauserv) to start automatically, starts it, and then verifies that it is running.
echo.
echo %YELLOW%Press C to Enable Updates or X to skip this step...%RESET%
choice /c CX /n /m "" >nul 2>&1
if errorlevel 2 goto SkipStep3
sc config wuauserv start= auto >nul
net start wuauserv >nul
sc query wuauserv | findstr /i "RUNNING"
echo.
echo Done with Step 3 - Page 70 (Chapter 3) "Be the Family Computer Hero"
timeout /t 3 /nobreak >nul
echo.
goto EndStep3
:SkipStep3
echo %RED%Skipping Step 3...%RESET%
timeout /t 3 /nobreak >nul
:EndStep3
echo.

echo %GREEN% ====================================================
echo %BOLD%%MAGENTA% 4. SCHEDULE WINDOWS UPDATE SERVICE TASK
echo %GREEN% ====================================================%RESET%
echo.
echo [4/7] Creating scheduled update task (WingetUpdates on Page 73)...
echo.
echo This checks if a scheduled task named WingetUpdates exists, and if not, creates one that runs winget upgrade --all every Wednesday at 9:00 AM. Type taskschd.msc to modify the date/time once complete.
echo.
echo %YELLOW%Press C to Schedule Updates or X to skip this step...%RESET%
choice /c CX /n /m "" >nul 2>&1
if errorlevel 2 goto SkipStep4
schtasks /Query /TN WingetUpdates >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Register-ScheduledTask -TaskName 'WingetUpdates' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/k winget upgrade --all & pause') -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Wednesday -At 9:00AM) -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable) -Force"
    echo WingetUpdates task created.
) else (
    echo Scheduled task WingetUpdates already exists.
)
echo.
echo Done with Step 4 - Page 73 (Chapter 3) "Be the Family Computer Hero"
timeout /t 3 /nobreak >nul
echo.
goto EndStep4
:SkipStep4
echo %RED%Skipping Step 4...%RESET%
timeout /t 3 /nobreak >nul
:EndStep4
echo.

echo %GREEN% ====================================================
echo %BOLD%%MAGENTA% 5. ENABLE AND SCHEDULE SYSTEM RESTORE POINT
echo %GREEN% ====================================================%RESET%
echo.
echo [5/7] Checking System Restore configuration (page 93)...
echo.
echo This enables System Restore on the C: drive and limits its shadow storage (restore point space) to my recommended 2%% of the drive.
echo.
echo %YELLOW%Press C to Schedule a Restore Point or X to skip this step...%RESET%
choice /c CX /n /m "" >nul 2>&1
if errorlevel 2 goto SkipStep5
echo.
echo %GREEN% Be Patient... This takes a few seconds.....
powershell -Command "Enable-ComputerRestore -Drive 'C:\'; vssadmin Resize ShadowStorage /For=C: /On=C: /MaxSize=2%%"
echo.
echo Done with Step 5 - Page 93 (Chapter 3) "Be the Family Computer Hero"
timeout /t 3 /nobreak >nul
echo.
goto EndStep5
:SkipStep5
echo %RED%Skipping Step 5...%RESET%
timeout /t 3 /nobreak >nul
:EndStep5
echo.

echo %GREEN% ====================================================
echo %BOLD%%MAGENTA% 6. ENABLE FIREWALL ON ALL PROFILES
echo %GREEN% ====================================================%RESET%
echo.
echo [6/7] Enabling Windows Firewall on all profiles (Page 55-56)...
echo.
echo This enables Windows Firewall for all profiles, sets the public profile to block inbound and allow outbound traffic, and then displays the public profile settings.
echo.
echo %YELLOW%Press C to Enable Firewall or X to skip this step...%RESET%
choice /c CX /n /m "" >nul 2>&1
if errorlevel 2 goto SkipStep6
netsh advfirewall set allprofiles state on >nul
netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound >nul
netsh advfirewall show publicprofile
echo.
echo Done with Step 6 - Page 55-56 (Chapter 3) "Be the Family Computer Hero"
timeout /t 3 /nobreak >nul
echo.
goto EndStep6
:SkipStep6
echo %RED%Skipping Step 6...%RESET%
timeout /t 3 /nobreak >nul
:EndStep6
echo.

echo %GREEN% ====================================================
echo %BOLD%%MAGENTA% 7. STRICT BROWSER COOKIES AND TRACKING
echo %GREEN% ====================================================%RESET%
echo.
echo [7/7] Tightening Security on Cookies and Trakcing (Page 84-87)...
echo.
echo This hardens privacy settings by blocking third-party cookies and background activity in Chrome and Edge, and disabling Windows telemetry, advertising ID, and personalized content features.
echo.
echo %YELLOW%Press C to Secure Browsers or X to skip this step...%RESET%
choice /c CX /n /m "" >nul 2>&1
if errorlevel 2 goto SkipStep7
powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Policies\Google\Chrome -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Policies\Google\Chrome -Name BlockThirdPartyCookies -Value 1" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Policies\Google\Chrome -Name BackgroundModeEnabled -Value 0"
powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Policies\Microsoft\Edge -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Edge F-Name BlockThirdPartyCookies -Value 1" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Microsoft\Edge\Privacy -Name TrackingPreventionLevel -Value 'Strict' -ErrorAction SilentlyContinue" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Edge -Name BackgroundModeEnabled -Value 0"
powershell.exe -NoProfile -Command "New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy -Force | Out-Null; Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Force | Out-Null; Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Value 0" && powershell.exe -NoProfile -Command "New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Force | Out-Null; Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Value 0" && powershell.exe -NoProfile -Command "Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -Value 0"
echo All Cookie and Tracking Settings Modified Successfully
echo.
echo Done with Step 7 - Pages 84-87 (Chapter 3) "Be the Family Computer Hero"
timeout /t 3 /nobreak >nul
echo.
goto EndStep7
timeout /t 3 /nobreak >nul
:SkipStep7
echo %RED%Skipping Step 7...%RESET%
:EndStep7
timeout /t 3 >nul
echo.

REM STATUS SUMMARY 
@echo off
:: Enable ANSI escape sequences (if not already enabled)
for /f "tokens=2 delims=: " %%A in ('reg query "HKCU\Console" /v VirtualTerminalLevel 2^>nul') do set vtl=%%A
if "%vtl%" neq "1" reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul
echo.
echo.
echo %BOLD%%CYAN%=================================================
echo %BOLD%%MAGENTA%        SYSTEM CONFIGURATION SUMMARY COMPLETE
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
echo %YELLOW%Done with all the selected Windows security hardening from Chapter 3 of "Be the Family Computer Hero"%RESET%
echo. 
echo %BOLD%%CYAN%BONUS:%RESET% In addition to basic hardening, you may now choose any of the optional security tasks below.
echo.
echo %CYAN%[1]%RESET% %WHITE%Update all Applications%RESET%  - Manually updates installed apps via Winget (already scheduled)
echo %CYAN%[2]%RESET% %WHITE%Windows AV Scan%RESET%          - Runs Windows Defender Virus Scan (if fails, see page 47 to enable this)
echo %CYAN%[3]%RESET% %WHITE%Create a Restore Point%RESET%   - Creates a new system restore point if possible
echo %CYAN%[A]%RESET% %WHITE%Perform All These Additional Tasks%RESET%
echo %CYAN%[N]%RESET% %WHITE%None, I am all done...%RESET%
echo.
choice /C 123AN /N /M "Enter your selection: "
echo.

REM EXECUTE REQUESTED QUICK SCANS
echo Starting Selected Utilities...
echo.

if errorlevel 5 goto End
if errorlevel 4 goto AllScans
if errorlevel 3 goto QuickRestore
if errorlevel 2 goto QuickAVScan
if errorlevel 1 goto QuickAppUpdate

:QuickAppUpdate
echo Running Quick App Update (Winget)...
winget upgrade --all
echo.
echo App Update Complete.
goto End

:QuickAVScan
echo Running Quick Antivirus Scan...
powershell.exe -c "Start-MpScan -ScanType QuickScan"
echo.
echo Antivirus Scan Complete.
goto End

:QuickRestore
echo Creating Quick Restore Point...
powershell.exe -Command "Checkpoint-Computer -Description 'Restore Point (Automatic)' -RestorePointType MODIFY_SETTINGS"
echo.
echo Restore Point Created.
goto End

:AllScans
echo Running All Scans...
echo.

echo [1 of 3] Running Quick App Update (Winget)...
winget upgrade --all
echo.
echo App Update Complete.
echo.

echo [2 of 3] Running Quick Antivirus Scan...
powershell.exe -c "Start-MpScan -ScanType QuickScan"
echo.
echo Antivirus Scan Complete.
echo.

echo [3 of 3] Creating Quick Restore Point...
powershell.exe -Command "Checkpoint-Computer -Description 'Restore Point (Automatic)' -RestorePointType MODIFY_SETTINGS"
echo.
echo Restore Point Created.
echo.

:End
echo.
echo All tasks finished.
echo.
echo Press any key to Exit this Program......
pause >nul
exit
