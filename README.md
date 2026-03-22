Helper Scripts referenced by the book "Be the Family Computer Hero" – Darryl Hicks
This repository contains three Windows-focused helper scripts based on content from Chapter 3 and Chapter 4 of Be the Family Computer Hero.

Kitchen_Sink.txt – an interactive Windows 11 hardening batch script
commands.txt – a cross‑platform command reference for Windows, Linux, and macOS.
Vulnerability-Scanning.txt – an interactive Nmap + vulscan setup and local subnet vulnerability scanner (rename to Vulnerability-Scanning.bat).

Note: The “kitchen sink” hardening script intentionally does not include vulnerability scanning to avoid antivirus false positives. Use the 
separate vulnerability script when you explicitly want that behavior.

1. KITCHEN_SINK.BAT – Windows 11 Hardening Tool
Overview
Kitchen_Sink-3.txt is a menu‑driven batch file that implements the book’s basic Windows 11 hardening recommendations with colorized console
output and clear prompts.

It performs up to seven hardening steps plus a small “bonus” menu of quick maintenance tasks:
Turn on malware protection (Windows Defender).
Improve DNS protection using OpenDNS.
Enable and start the Windows Update service.
Create a scheduled weekly winget update task.
Enable System Restore and limit shadow storage to 2% of C:.
Enable and harden Windows Firewall profiles (especially Public).
Tighten browser cookies, tracking, telemetry, and ad settings for Edge/Chrome and Windows.

Afterwards, it offers a bonus menu to:
Run winget upgrade --all (quick app update).
Run a Windows Defender quick scan.
Create a restore point.
Or perform all three.

What it does (step by step)
For each numbered step the script:
Explains what will be configured and references the relevant book pages.
Prompts the user: Press C to ... or X to skip this step.
Executes the configuration only if the user presses C.

Key actions:
Malware Protection
Checks the WinDefend service state.
If not running, uses PowerShell Set-MpPreference to enable real‑time monitoring, IOAV protection, PUA protection, and scan parameters.

DNS Protection (OpenDNS)
Enumerates all “Connected” network interfaces via netsh interface show interface.
Sets primary and secondary DNS to 208.67.222.222 and 208.67.220.220 via netsh interface ip set dns / add dns.
Displays DNS configuration via ipconfig /all.

Windows Update Service
Sets wuauserv start type to automatic via sc config.
Starts the service and confirms it is RUNNING.

Scheduled winget Updates
Checks for an existing WingetUpdates scheduled task.
If missing, registers a weekly Wednesday 9:00 AM task that runs cmd.exe /k "winget upgrade --all & pause".
System Restore / Shadow Storage
Enables System Restore on C: using PowerShell Enable-ComputerRestore.
Uses vssadmin Resize ShadowStorage to cap restore storage at 2% of the drive.

Firewall Hardening
Enables Windows Firewall on all profiles with netsh advfirewall set allprofiles state on.
Sets the public profile policy to blockinbound,allowoutbound and shows the public profile settings.

Browser & Telemetry Hardening
For Chrome: creates/updates HKCU\Software\Policies\Google\Chrome to block third‑party cookies and disable background mode.
For Edge: creates/updates HKCU\Software\Policies\Microsoft\Edge and HKCU\Software\Microsoft\Edge\Privacy to block third‑party cookies, set strict 
tracking prevention, and disable background mode.
For Windows: updates various HKLM and HKCU privacy and advertising keys to disable telemetry, tailored experiences, and content recommendations.
Finally, it prints a colorized “System Configuration Summary” showing which categories have been configured and then offers the bonus quick tasks menu.

How to use
Save Kitchen_Sink.txt as Kitchen_Sink.bat.
Right‑click Kitchen_Sink.bat and choose Run as administrator (required for most steps).
Follow the instructions!  RTFM - That's it. This script takes ~5 minutes to complete.

----------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------

2. COMMANDS.TXT – Cross‑Platform Command Reference
Overview:  commands.txt is a structured command cheat‑sheet keyed to book chapters and sections, listing Windows commands
alongside Linux and macOS equivalents (where practical). It is a documentation/learning aid, not an executable script.

Contents
The file is organized by chapter/section headings:
Command‑line basics (opening an elevated prompt).
Malware protection (Windows Defender, ClamAV, XProtect).
DNS protection (checking and setting DNS, OpenDNS).
Patching systems (Windows Update service, winget, apt, Homebrew).
Backups & restore (shadow copies, VSS, Timeshift, Time Machine/APFS).
Firewall configuration (Windows Firewall, UFW, macOS application firewall).
Resource checks (RAM and disk free space).
Vulnerability tooling (Nmap install, vuln script install, example scans).
Bonus scripts (show all saved Wi‑Fi SSIDs/passwords; “kitchen sink” loader).

Each section describes:
Intended functionality in plain language.
The exact Windows command(s).
One or more Linux and macOS equivalents or recommended tools.
Any important discrepancies between platforms.

How to use
Open the file in any text editor and copy‑paste commands as needed.
Use it as companion documentation when explaining what the batch files are doing.
For Linux/macOS commands, adjust distribution‑specific or interface names as needed.
If you want, you can link to it from your README as a “Command Reference Appendix” or include selected sections directly within the README.

----------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------
3. VULNERABILITY-SCANNING.BAT – Nmap + vulscan Helper
Overview: Vulnerability-Scanning-3.txt is an interactive batch script that installs Nmap, deploys the vulscan Nmap script bundle, and then scans your local /24 network range for service versions and known vulnerabilities.

What it does:
Environment & permissions
Enables ANSI escape sequences via VirtualTerminalLevel under HKCU\Console.
Verifies it is running with Administrator privileges using net session; exits if not.

Displays a warning that it will:
Download and install Nmap.
Download vulnscan from GitHub.
Scan the local /24 network.
Execute nmap.exe -sV -v --script=vulscan.nse <ip>/24 from the Nmap install path.

How to use:  WARNING: You will need to disable your AV or put anti-malware in audit mode to use this file.
Save Vulnerability-Scanning.txt as Vulnerability-Scanning.bat.
Right‑click and choose Run as administrator on a Windows system.
Read the warnings and type Y at prompts if you agree to proceed.
Allow Nmap to install when its GUI installer appears.
When prompted, confirm the scan; monitor Nmap output in the same console window.

Completion
Copy the entire content in the command prompt. 
     (CTRL+SHIFT+A to select all and CTRL+C to copy)
Paste this into an AI with the following prompt:
    "explain to a novice any vulnerabilities found and how to resolve them"

WARNING: Use this Vulnerability-Scanning.txt only on networks you own or are explicitly authorized to test. 
Unauthorized scanning may violate policies or laws.

