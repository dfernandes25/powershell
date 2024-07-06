<#
    .SYNOPSIS
    install/upgrade choco user apps

    .DESCRIPTION
    check if choco installed
    install/upgrade userspace apps

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
    List of input types that are accepted by this function.

    .OUTPUTS
    List of output types produced by this function.
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
$script:logname = ('{0}-mychocoapps.log' -f $cname)
# $ci = Get-ComputerInfo


if (!(Get-EventLog -LogName Application -Source cbctech)) 
{
  New-EventLog -LogName Application -Source cbctech > $null 
}
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoApps initialized' -EventId 4444 -EntryType information

#----------------------------------------------
# CHECK/INSTALL CHOCO
#----------------------------------------------

<# install choco #>
function Install-Choco 
{
  if (!(Test-Path -Path "$env:ChocolateyInstall\logs")) 
  {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoApps installing chocolatey' -EventId 4444 -EntryType information
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression -Command ((New-Object -TypeName System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  }
  else 
  {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoApps updating chocolatey' -EventId 4444 -EntryType information
    & "$env:ChocolateyInstall\bin\choco.exe" upgrade all -y > $null
  }
}
Install-Choco
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoApps loading packages' -EventId 4444 -EntryType information

 
# Basic Utils
& "$env:ChocolateyInstall\bin\choco.exe" upgrade 7zip -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade adobereader -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade brave -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade bulkrenameutility -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade ccleaner.portable -y
#choco upgrade drawio -y
#choco upgrade dropbox -y
#choco upgrade expressvpn -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade firefoxesr -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade googlechrome -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade https-everywhere-chrome -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade ublockorigin-chrome -y
#choco upgrade imageresizerapp -y
#choco upgrade keepass.upgrade -y
#choco upgrade keybase -y
#choco upgrade microsoft-teams -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade notepadplusplus -y
#choco upgrade opera -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade paint.net -y
#choco upgrade powerbi -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade powershell -y
#choco upgrade powershell-core -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade revo-uninstaller -y
#choco upgrade signal -y
#choco upgrade skype -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade slack
#choco upgrade spotify -y
#choco upgrade todoist -y
#choco upgrade toggl -y
#choco upgrade xmind -y
 
#choco upgrade teamviewer -y
#choco upgrade virtualbox -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade vlc -y
#choco upgrade wireshark -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade zerotier-one -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade zoom -y
 
# Developer Tools
#choco upgrade atom -y
#choco upgrade azurestorageexplorer -y
#choco upgrade azure-data-studio -y
#choco upgrade docker-desktop -y
#choco upgrade fiddler -y
#choco upgrade filezilla -y
# choco upgrade git -y
# choco upgrade nodejs.upgrade -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade nuget.commandline -y
# choco upgrade postman -y
# choco upgrade ServiceBusExplorer -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade smartftp -y
# choco upgrade sql-server-management-studio -y
# choco upgrade sqlitebrowser.upgrade -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade visualstudiocode -y
& "$env:ChocolateyInstall\bin\choco.exe" upgrade vscode-powershell -y
 
# Optional
# choco upgrade foobar2000 -y
# choco upgrade mysql.workbench -y
# choco upgrade tortoisesvn -y
 
<# Pin packages that are automatically updated
    $pin = 'azure-data-studio', 'brave', 'drawio', 'dropbox', 'expressvpn', 'firefox', 'googlechrome', 'microsoft-teams', 'opera', 'paint.net', 'signal', 'skype', 'spotify', 'atom', 'visualstudiocode'
    $pin | ForEach-Object -Process {
    choco pin add -n $_ 
    }
#>
Get-ChildItem -Path $env:Public\Desktop\*.lnk | ForEach-Object -Process {
  Remove-Item -Path $_ 
}
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoApps load complete' -EventId 4444 -EntryType information
