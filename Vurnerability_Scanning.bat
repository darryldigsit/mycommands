@echo off
setlocal EnableDelayedExpansion

:: सुनिश्चित ANSI support (Windows Server 2022)
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1

:: Define ESC character (must be literal ESC - already embedded here)
set "ESC="

:: Color definitions
set "RED=%ESC%[91m"
set "GREEN=%ESC%[92m"
set "YELLOW=%ESC%[93m"
set "CYAN=%ESC%[96m"
set "RESET=%ESC%[0m"

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% This script must be run as Administrator.
    pause
    exit /b
)

echo.
echo %CYAN%=====================================================%RESET%
echo %CYAN%   IP Range Vulnerability Scan Setup & Execution     %RESET%
echo %CYAN%=====================================================%RESET%
echo.

echo %YELLOW%[WARNING]%RESET% This script will:
echo   - Download and install Nmap
echo   - Download vulnscan scripts from GitHub
echo   - Copy files into Program Files
echo   - Scan your local /24 network
echo.

set /p confirm=Proceed? (Y/N): 
if /I not "%confirm%"=="Y" (
    echo %RED%[ABORTED]%RESET% User cancelled operation.
    exit /b
)

echo.
echo %CYAN%[INFO]%RESET% Downloading and installing Nmap...

powershell -Command ^
"Invoke-WebRequest https://nmap.org/dist/nmap-7.94-setup.exe -OutFile $env:USERPROFILE\Downloads\nmap-setup.exe -ErrorAction Stop; ^
Start-Process -Wait $env:USERPROFILE\Downloads\nmap-setup.exe"

if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% Nmap installation failed.
    pause
    exit /b
)

echo %GREEN%[SUCCESS]%RESET% Nmap installed successfully.
echo.

echo %CYAN%[INFO]%RESET% Downloading vulnscan from GitHub...

powershell -Command ^
"Invoke-WebRequest -Uri https://github.com/scipag/vulscan/archive/refs/heads/master.zip -OutFile $env:TEMP\vulscan.zip"

if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% Failed to download vulnscan.
    pause
    exit /b
)

echo %GREEN%[SUCCESS]%RESET% Download complete.
echo.

echo %CYAN%[INFO]%RESET% Extracting vulnscan...

powershell -Command ^
"Expand-Archive -Path $env:TEMP\vulscan.zip -DestinationPath $env:TEMP\vulscan -Force"

if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% Extraction failed.
    pause
    exit /b
)

echo %GREEN%[SUCCESS]%RESET% Extraction complete.
echo.

echo %CYAN%[INFO]%RESET% Copying scripts into Nmap directory...

xcopy /E /Y "%TEMP%\vulscan\vulscan-master\*" "C:\Program Files (x86)\Nmap\scripts\" >nul

if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% Failed to copy files.
    pause
    exit /b
)

echo %GREEN%[SUCCESS]%RESET% Files copied successfully.
echo.

echo %YELLOW%[WARNING]%RESET% About to scan your local network (/24 range).
echo This may take several minutes and generate network traffic.
echo.

set /p scanconfirm=Start scan now? (Y/N): 
if /I not "%scanconfirm%"=="Y" (
    echo %RED%[ABORTED]%RESET% Scan cancelled.
    exit /b
)

echo.
echo %CYAN%[INFO]%RESET% Detecting local IP range and starting scan...

powershell -Command ^
"$ip = ((Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null}).IPv4Address | Select-Object -First 1).IPAddress; ^
Write-Host 'Scanning network:' ($ip + '/24'); ^
& 'C:\Program Files (x86)\Nmap\nmap.exe' -sV -v --script=vulscan.nse ($ip + '/24')"

if %errorlevel% neq 0 (
    echo %RED%[ERROR]%RESET% Scan encountered an issue.
    pause
    exit /b
)

echo.
echo %GREEN%=====================================================%RESET%
echo %GREEN% All tests completed successfully.                   %RESET%
echo %GREEN%=====================================================%RESET%
echo.

pause
exit /b
