<#
    .SYNOPSIS
     General cleanup and maintenance duties

    .DESCRIPTION
     Use as part of regular maintenance routine and in new build process
     Script will clear:
        Scripts dir
        Event Logs
        Windows.old
        temp dir
        cleans DISM
        empty recycle bin

    .USAGE
     can be run as scheduled task, through RMM, dot source, etc.
     
    .LINK
    
    .NOTES
    Don Fernandes
    don@cbctech.net
    www.cbctech.net 
    20221006 refactored for consolidated codebase  
#>

$ErrorActionPreference = 'SilentlyContinue'
$script:cname = $env:COMPUTERNAME
$script:days = (Get-Date).AddHours(-24)
$script:date = (Get-Date).ToShortDateString().Replace('/', '-')
$script:scrdir = "$env:homedrive\scripts"
$script:invdir = "$scrdir\inventory"
$script:csvdir = "$invdir\csv"
$script:rptdir = "$scrdir\reports"
$script:logdir = "$env:HOMEDRIVE\scriptlogs"
$script:logname = "$cname-myCleanup.log"

if (!(Get-EventLog -LogName Application -Source cbctech)) { New-EventLog -LogName Application -Source cbctech > $null }
if (!(Test-Path -Path $logdir)) { mkdir $logdir -Force > $null }

#----------------------------------------------
# CLEAR EVT LOGS
#----------------------------------------------
function Clear-EventLogs {
  Add-Content -Path "$logdir\$logname" -Value "$date Clearing log files"
     
  Get-EventLog -LogName * | 
  ForEach-Object { Clear-EventLog $_.Log
    Add-Content -Path "$logdir\$logname" -Value $_.LogDisplayName
  }
  sleep 5
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup logs cleared' -EventId 4444 -EntryType information
}
Clear-EventLogs

#----------------------------------------------
# REMOVE SCRDIR
#----------------------------------------------
function Remove-Scripts {
  if (Test-Path -Path "$scrdir") {
    Remove-Item -Recurse -Force "$scrdir"
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup deleted scripts directory' -EventId 4444 -EntryType information
  }
  else { Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup scripts directory not found' -EventId 4444 -EntryType information }
  if (!(Test-Path -Path "$csvdir")) { mkdir $csvdir -Force > $null }
  if (!(Test-Path -Path "$rptdir")) { mkdir $rptdir -Force > $null }
            
} 
Remove-Scripts
 
#----------------------------------------------
# REMOVE WIN>OLD
#----------------------------------------------
function Remove-WinOld {
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup checking for windows.old' -EventId 4444 -EntryType information
  if (Test-Path -Path "$env:homedrive\Windows.old") {
    $regpath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations' 
    New-ItemProperty -Path $regpath -Name 'StateFlags1221' -PropertyType DWORD  -Value 2 -Force > $null
    & "$env:windir\system32\cleanmgr.exe" /SAGERUN:1221 
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup windows.old removed' -EventId 4444 -EntryType information
  }
  else { Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup windows.old not found' -EventId 4444 -EntryType information }
}
Remove-WinOld

#----------------------------------------------
# CLEAN TMP FILES
#----------------------------------------------
function Clear-Tmp {
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup clearing temp' -EventId 4444 -EntryType information

  Remove-Item -Path 'C:\' -Include *.tmp, *.etl -Recurse > $null
  Remove-Item -Path "$env:TEMP\*" -Recurse > $null
  Remove-Item -Path "$env:windir\Temp\*.*" -Recurse -Force > $null
}
Clear-Tmp

#----------------------------------------------
# DISM REPAIR
#----------------------------------------------
function Clear-DISM {
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup cleaning DISM' -EventId 4444 -EntryType information
  Dism.exe /Online /Cleanup-Image /RestoreHealth 
}
Clear-DISM

#----------------------------------------------
# EMPTY TRASH
#----------------------------------------------
function Clear-Recycle {
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup empty trash' -EventId 4444 -EntryType information
  $recycleBin = (New-Object -ComObject Shell.Application).NameSpace(0xa)
  $recycleBin.Items() | ForEach-Object -Process { Remove-Item -Path $_.Path -Force -Recurse }
} 
Clear-Recycle

#----------------------------------------------
# FIX id455
#----------------------------------------------
function Clear-ID455
{  
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup fixing ID455 errors' -EventId 4444 -EntryType information   
    if(!(Test-Path 'C:\Windows\System32\config\systemprofile\AppData\Local\TileDataLayer'))
        {  
          Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup creating ID455 directories' -EventId 4444 -EntryType information
            mkdir 'C:\Windows\System32\config\systemprofile\AppData\Local\TileDataLayer' -Force > $null
            mkdir 'C:\Windows\System32\config\systemprofile\AppData\Local\TileDataLayer\Database' -Force > $null
        }
    else {Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup ID455 directories already exist' -EventId 4444 -EntryType information}
      
} 
clear-ID455

#----------------------------------------------
# FIX PERF COUNTERS
#----------------------------------------------
function Clear-LodCtr
{
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'resetting perf counters' -EventId 4444 -EntryType information     
    & C:\Windows\system32\Lodctr /R
    & C:\Windows\SysWOW64\Lodctr /R
    & C:\Windows\system32\lodctr /T:TermService
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'perf counters reset' -EventId 4444 -EntryType information
} 
Clear-LodCtr
 
#----------------------------------------------
# REBOOT
#----------------------------------------------
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup complete, restarting now' -EventId 4444 -EntryType information
$win32OS = get-wmiobject win32_operatingsystem -computername $cname -EnableAllPrivileges
$win32OS.win32shutdown(6)
