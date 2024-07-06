<#

.VERSION 1.0

.GUID 07e4ef9f-8341-4dc4-bc73-fc277eb6b4e6

.AUTHOR Don Fernandes

.COMPANYNAME CBC Technologies

.COPYRIGHT

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
Version 1.0 2023-11-07
Modification of Michael Niehaus' Intune app for OS updates
https://github.com/mtniehaus/UpdateOS/blob/main/UpdateOS/UpdateOS.ps1

.SYNOPSIS
Installs the latest Windows 10/11 quality updates.

.DESCRIPTION
This script uses the PSWindowsUpdate module to install the latest cumulative update for Windows 10/11.

.EXAMPLE
.\Get-OSupdates.ps1
#>

[CmdletBinding()]
Param(
     [ValidateSet('Soft', 'Hard', 'None', 'Delayed')] [String] $Reboot = 'Soft',
     [int] $RebootTimeout = 120
)

Process
{

# If running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne 'ARM64')
{
    if (Test-Path -Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File ('{0}' -f $PSCommandPath) -Reboot $Reboot -RebootTimeout $RebootTimeout
        Exit $lastexitcode
    }
}


# Start logging
Start-Transcript -Path "$env:HOMEDRIVE\scripts\Get-OSupdates.log"

# Main logic
$needReboot = $False

# Load module from PowerShell Gallery
$ts = Get-Date -Format 'yyyy/MM/dd hh:mm:ss tt'
# Write-Host "$ts Importing NuGet and PSWindowsUpdate"
$null = Install-PackageProvider -Name NuGet -Force
$null = Install-Module -Name PSWindowsUpdate -Force
Import-Module -Name PSWindowsUpdate

# Opt into Microsoft Update
Add-WUServiceManager -ServiceID '7971f918-a847-4430-9279-4a52d1efe18d' -AddServiceFlag 7 -Confirm:$False

# Install all available updates
$ts = Get-Date -Format 'yyyy/MM/dd hh:mm:ss tt'
Get-WindowsUpdate -AcceptAll -IgnoreReboot -Hide

$needReboot = (Get-WURebootStatus -Silent).RebootRequired
if($needReboot)
{
                    Write-Information -MessageData 'Reboot required'
                    & "$env:windir\system32\shutdown.exe" /r /t $RebootTimeout /c
                    Stop-Transcript
                    exit 0
                    }
else
{
                    Write-Information -MessageData 'No reboot required'
                    Stop-Transcript
                    exit 0
                    }
}
