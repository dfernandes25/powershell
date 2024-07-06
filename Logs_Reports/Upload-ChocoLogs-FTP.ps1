<#
    .SYNOPSIS
    upload chocolatey log files to an ftp server
    
    .DESCRIPTION
    nothing fancy here except using native commands, (no external modules) to do an ftp server upload
    and if you think ftp uploads in ps are easy, give it a whirl -- lemme know how it goes
 
    .EXAMPLE
     
    .LINK
    
    .NOTES
    Don Fernandes
    don@cbctech.net
    cbc technologies llc
    created:
    update: 20221008 refactored
    modified: 20240706 
     
    .INPUTS
    List of input types that are accepted by this function
    
    .OUTPUTS
    List of output types produced by this function
#>


#----------------------------------------------
# VARIABLES
#----------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'
$script:cname = $env:COMPUTERNAME
$script:days = (Get-Date).AddHours(-24)
$script:date = (Get-Date).ToShortDateString().Replace('/', '-')
$script:scrdir = "$env:homedrive\scripts"
$script:invdir = ('{0}\inventory' -f $scrdir)
$script:csvdir = ('{0}\csv' -f $invdir)
$script:rptdir = ('{0}\reports' -f $scrdir)
$script:logdir = "$env:homedrive\scriptlogs"
$script:logname = ('{0}-myInventory.log' -f $cname)
$chocosrcdir = "$env:ChocolateyInstall\logs"

#----------------------------------------------
# DIR SETUP
#----------------------------------------------
if (!(Get-EventLog -LogName Application -Source cbctech)) 
{
  New-EventLog -LogName Application -Source cbctech > $null 
}
if (!(Test-Path -Path $csvdir)) 
{
  mkdir -Path $csvdir -Force > $null 
}
else 
{
  Remove-Item -Recurse -Force -Path ('{0}\*' -f $csvdir) 
}
if (!(Test-Path -Path $rptdir)) 
{
  mkdir -Path $rptdir -Force 
}
if (!(Test-Path -Path $logdir)) 
{
  mkdir -Path $logdir -Force 
}

Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs initialized' -EventId 4444 -EntryType information
Start-Sleep -Seconds 3

#----------------------------------------------
# CHECK FOR LOGS
#----------------------------------------------
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs checking for logs' -EventId 4444 -EntryType information
if (Test-Path -Path $chocosrcdir) 
{
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs compressing choco logs' -EventId 4444 -EntryType information
  Compress-Archive -Path ('{0}' -f $chocosrcdir) -DestinationPath ('{0}\{1}-chocologs.zip' -f $rptdir, $cname) -Update
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs choco logs compressed' -EventId 4444 -EntryType information
  & "$env:ChocolateyInstall\bin\choco.exe" list --localonly | Out-File -FilePath ('{0}/{1}-choco-apps.txt' -f $rptdir, $cname) -Force
}
else 
{
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs no choco logs found' -EventId 4444 -EntryType information
  exit
}

#----------------------------------------------
# SEND LOGS
#----------------------------------------------
function Send-FTP 
{ 
  $ftp = 'ftp://xxx.xx.xxx.xxx/uploads/BuildInventory/'
  $user = 'username'
  $pass = 'password'
  
  $webclient = New-Object -TypeName System.Net.WebClient  
  $webclient.Credentials = New-Object -TypeName System.Net.NetworkCredential -ArgumentList ($user, $pass)  
 
  foreach ($item in (Get-ChildItem -Path ('{0}' -f $rptdir) -Filter '*choco*')) 
  {
    $uri = New-Object -TypeName System.Uri -ArgumentList ($ftp + $item.Name) 
    $webclient.UploadFile($uri, $item.FullName) 
  }
}
Send-FTP
