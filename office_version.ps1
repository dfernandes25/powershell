#requires -Version 1.0
<#
    .SYNOPSIS
    gets currently installed version of Microsoft Office

    .DESCRIPTION
    gets M365 version and outputs to text file

    .USAGE

    .LINK

    .NOTES
    Don Fernandes
    don@cbctech.net
    20240110 created

#>

Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' |
Select-Object -ExpandProperty VersionToReport |
Out-File -FilePath 'C:\tech_stuff\office_version.txt' -Force