<#
    .SYNOPSIS
    install/upgrade choco

    .DESCRIPTION
    check if choco installed
    if not install choco
    if already installed, upgrade choco apps

    .EXAMPLE
     
    .LINK
    
    .NOTES
    Don Fernandes
    don@cbctech.net
    cbc technologies llc
    created:
    update: 20221008 refactored 

    .INPUTS
    List of input types that are accepted by this function.

    .OUTPUTS
    List of output types produced by this function.
#>

<# create a log file #>
if (!(Get-EventLog -LogName Application -Source cbctech)) 
{
  New-EventLog -LogName Application -Source cbctech > $null 
}
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoInstall initialized' -EventId 4444 -EntryType information

#----------------------------------------------
# CHECK/INSTALL CHOCO
#----------------------------------------------

<# install choco #>
function Install-Choco 
{
  if (!(Test-Path -Path "$env:ChocolateyInstall\logs")) 
  {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoInstall installing chocolatey' -EventId 4444 -EntryType information
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression -Command ((New-Object -TypeName System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  }
  else 
  {
    Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoInstall updating chocolatey' -EventId 4444 -EntryType information
    & "$env:ChocolateyInstall\bin\choco.exe" upgrade all -y > $null
  }
}
Install-Choco
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myChocoInstall complete' -EventId 4444 -EntryType information
