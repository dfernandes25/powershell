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
$script:invdir = "$scrdir\inventory"
$script:csvdir = "$invdir\csv"
$script:rptdir = "$scrdir\reports"
$script:logdir = "$env:HOMEDRIVE\scriptlogs"
$script:logname = "$cname-myInventory.log"
$chocosrcdir = 'C:\ProgramData\chocolatey\logs'

#----------------------------------------------
# DIR SETUP
#----------------------------------------------
if (!(Get-EventLog -LogName Application -Source cbctech)) { New-EventLog -LogName Application -Source cbctech > $null }
if (!(Test-Path $csvdir)) { mkdir $csvdir -Force > $null }
else { Remove-Item -Recurse -Force -Path "$csvdir\*" }
if (!(Test-Path -Path $rptdir)) { mkdir $rptdir -Force }
if (!(Test-Path -Path $logdir)) { mkdir $logdir -Force }

Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs initialized' -EventId 4444 -EntryType information
Start-Sleep -Seconds 3

#----------------------------------------------
# CHECK FOR LOGS
#----------------------------------------------
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs checking for logs' -EventId 4444 -EntryType information
if (Test-Path $chocosrcdir) {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs compressing choco logs' -EventId 4444 -EntryType information
    Compress-Archive -Path "$chocosrcdir" -DestinationPath "$rptdir\$cname-chocologs.zip" -Update
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs choco logs compressed' -EventId 4444 -EntryType information
    choco list --localonly | Out-File -FilePath "$rptdir/$cname-choco-apps.txt" -Force
}
else {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoLogs no choco logs found' -EventId 4444 -EntryType information
    exit
}

#----------------------------------------------
# SEND LOGS
#----------------------------------------------
function Send-FTP { 
    $ftp = 'ftp://xxx.xx.xxx.xxx/uploads/BuildInventory/'
    $user = 'username'
    $pass = 'password'
  
    $webclient = New-Object -TypeName System.Net.WebClient  
    $webclient.Credentials = New-Object -TypeName System.Net.NetworkCredential -ArgumentList ($user, $pass)  
 
    foreach ($item in (Get-ChildItem -Path "$rptdir" -Filter '*choco*')) {
        $uri = New-Object -TypeName System.Uri -ArgumentList ($ftp + $item.Name) 
        $webclient.UploadFile($uri, $item.FullName) 
    }
}
Send-FTP
