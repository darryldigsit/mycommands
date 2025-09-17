@echo off
#Turns on Defender for Endpoint
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableIOAVProtection $false; Set-MpPreference -PUAProtection enable"
pause
#Determine interface varable
netsh interface show interface
#Secures DNS
netsh interface ip set dns name="Wi-Fi" static 208.67.222.222
netsh interface ip add dns name="Wi-Fi" 208.67.220.220 index=2
pause
# Backup Service Running 
sc config wuauserv start= auto & net start wuauserv & sc query wuauserv
pause
#secure the firewall
netsh advfirewall set allprofiles state on & netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound & netsh advfirewall show publicprofile
pause
#Updates all Applications
winget upgrade --all
pause
#Schedules the winget update
powershell -Command "Register-ScheduledTask -TaskName 'WingetUpdates' -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/k winget upgrade --all & pause') -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Wednesday -At 9:00AM) -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable) -Force"
pause
#Displays the results of task scheduler
schtasks /query /tn "wingetupdates" /fo LIST /v
pause
#Displays vssadmin
vssadmin list shadowstorage
pause
#Create restorepoint
wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Restore Point Name", 100, 7
pause
#Schedule full backup every day at 8:00AM
SCHTASKS /Create /SC DAILY /TN DailyFullBackup /RL HIGHEST /st 08:00 /TR "wbAdmin Start Backup -backupTarget:F: -include:C: -allCritical -quiet"
pause
#Put system manufacture in variable for report
systeminfo
pause
#opens Windows Hello to setup 
start ms-settings:signinoptions
#opens up password checker
start HTTPS://WWW.GRC.COM/HAYSTACK.HTM
#opens up grc.com for security
start HTTPS://WWW.GRC.COM/X/NE.DLL?BH0BKYD2
#opens up browser security test
start HTTPS://BROWSERAUDIT.COM
#opens Adblocker to download
start HTTPS://ADBLOCKULTIMATE.NET/BROWSERS
#opens up google password manager
start HTTPS://PASSWORDS.GOOGLE.COM
@echo.
@echo.
@echo completed
@echo.
pause
