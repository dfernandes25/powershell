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
    THIS WILL CLEAR LOG FILES!!!

    .USAGE
    can be run as scheduled task, through RMM, dot source, etc.
     
    .LINK
    
    .NOTES
    Don Fernandes
    don@cbctech.net
    www.cbctech.net 
    20221006 refactored for consolidated codebase
    20240706 modified  
#>

$ErrorActionPreference = 'SilentlyContinue'
$script:cname = $env:COMPUTERNAME
$script:days = (Get-Date).AddHours(-24)
$script:date = (Get-Date).ToShortDateString().Replace('/', '-')
$script:scrdir = "$env:homedrive\scripts"
$script:invdir = ('{0}\inventory' -f $scrdir)
$script:csvdir = ('{0}\csv' -f $invdir)
$script:rptdir = ('{0}\reports' -f $scrdir)
$script:logdir = "$env:homedrive\scriptlogs"
$script:logname = ('{0}-myCleanup.log' -f $cname)

if (!(Get-EventLog -LogName Application -Source cbctech)) 
{
  New-EventLog -LogName Application -Source cbctech > $null 
}
if (!(Test-Path -Path $logdir)) 
{
  mkdir -Path $logdir -Force > $null 
}

#----------------------------------------------
# CLEAR EVT LOGS
#----------------------------------------------
function Clear-EventLogs 
{
  Add-Content -Path ('{0}\{1}' -f $logdir, $logname) -Value ('{0} Clearing log files' -f $date)
     
  Get-EventLog -LogName * | 
  ForEach-Object -Process {
    Clear-EventLog -LogName $_.Log
    Add-Content -Path ('{0}\{1}' -f $logdir, $logname) -Value $_.LogDisplayName
  }
  Start-Sleep -Seconds 5
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup logs cleared' -EventId 4444 -EntryType information
}
Clear-EventLogs

#----------------------------------------------
# REMOVE SCRDIR
#----------------------------------------------
function Remove-Scripts 
{
  if (Test-Path -Path ('{0}' -f $scrdir)) 
  {
    Remove-Item -Recurse -Force -Path ('{0}' -f $scrdir)
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup deleted scripts directory' -EventId 4444 -EntryType information
  }
  else 
  {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup scripts directory not found' -EventId 4444 -EntryType information 
  }
  if (!(Test-Path -Path ('{0}' -f $csvdir))) 
  {
    mkdir -Path $csvdir -Force > $null 
  }
  if (!(Test-Path -Path ('{0}' -f $rptdir))) 
  {
    mkdir -Path $rptdir -Force > $null 
  }
} 
Remove-Scripts
 
#----------------------------------------------
# REMOVE WIN>OLD
#----------------------------------------------
function Remove-WinOld 
{
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup checking for windows.old' -EventId 4444 -EntryType information
  if (Test-Path -Path "$env:homedrive\Windows.old") 
  {
    $regpath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations' 
    New-ItemProperty -Path $regpath -Name 'StateFlags1221' -PropertyType DWORD  -Value 2 -Force > $null
    & "$env:windir\system32\cleanmgr.exe" /SAGERUN:1221 
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup windows.old removed' -EventId 4444 -EntryType information
  }
  else 
  {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup windows.old not found' -EventId 4444 -EntryType information 
  }
}
Remove-WinOld

#----------------------------------------------
# CLEAN TMP FILES
#----------------------------------------------
function Clear-Tmp 
{
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup clearing temp' -EventId 4444 -EntryType information

  Remove-Item -Path "$env:HOMEDRIVE\" -Include *.tmp, *.etl -Recurse > $null
  Remove-Item -Path "$env:TEMP\*" -Recurse > $null
  Remove-Item -Path "$env:windir\Temp\*.*" -Recurse -Force > $null
}
Clear-Tmp

#----------------------------------------------
# DISM REPAIR
#----------------------------------------------
function Clear-DISM 
{
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup cleaning DISM' -EventId 4444 -EntryType information
  & "$env:windir\system32\dism.exe" /Online /Cleanup-Image /RestoreHealth 
}
Clear-DISM

#----------------------------------------------
# EMPTY TRASH
#----------------------------------------------
function Clear-Recycle 
{
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup empty trash' -EventId 4444 -EntryType information
  $recycleBin = (New-Object -ComObject Shell.Application).NameSpace(0xa)
  $recycleBin.Items() | ForEach-Object -Process {
    Remove-Item -Path $_.Path -Force -Recurse 
  }
} 
Clear-Recycle

#----------------------------------------------
# FIX id455
#----------------------------------------------
function Clear-ID455
{  
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup fixing ID455 errors' -EventId 4444 -EntryType information   
  if(!(Test-Path -Path "$env:windir\System32\config\systemprofile\AppData\Local\TileDataLayer"))
  {  
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup creating ID455 directories' -EventId 4444 -EntryType information
    mkdir -Path "$env:windir\System32\config\systemprofile\AppData\Local\TileDataLayer" -Force > $null
    mkdir -Path "$env:windir\System32\config\systemprofile\AppData\Local\TileDataLayer\Database" -Force > $null
  }
  else 
  {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup ID455 directories already exist' -EventId 4444 -EntryType information
  }
} 
Clear-ID455

#----------------------------------------------
# FIX PERF COUNTERS
#----------------------------------------------
function Clear-LodCtr
{
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'resetting perf counters' -EventId 4444 -EntryType information     
  & $env:windir\system32\Lodctr /R
  & $env:windir\SysWOW64\Lodctr /R
  & $env:windir\system32\lodctr /T:TermService
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'perf counters reset' -EventId 4444 -EntryType information
} 
Clear-LodCtr
 
#----------------------------------------------
# REBOOT
#----------------------------------------------
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myCleanup complete, restarting now' -EventId 4444 -EntryType information
$win32OS = Get-WmiObject -Class win32_operatingsystem -ComputerName $cname -EnableAllPrivileges
$win32OS.win32shutdown(6)
