<#
    .SYNOPSIS
    example scripts to find and delete an email

    .DESCRIPTION
    uses ExchangeOnlne and Security & Compliance Powwershell

    .USAGE
    runs interactively. to run unattended, use app-only authentication

    .LINK
    https://learn.microsoft.com/en-us/purview/ediscovery-search-for-and-delete-email-messages
    https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps
    https://learn.microsoft.com/en-us/powershell/exchange/scc-powershell?view=exchange-ps

    .NOTES
    Don Fernandes
    don@cbctech.net
    20240110 created

#>


<# import EOL module and connect to Security & Compliance Powershell #>
Import-Module -Name ExchangeOnlineManagement

$upn = 'user@domain.com' # edit upn variable with authorized user
Connect-IPPSSession -UserPrincipalName $upn

<# search mail from specific sender #>
$search = New-ComplianceSearch -Name 'Test' -ExchangeLocation All -ContentMatchQuery 'From:jessica@devacc.today'
Start-ComplianceSearch -Identity $search

<# soft or hard delete results of sender search #>
New-ComplianceSearchAction -SearchName 'Test' -Purge -PurgeType SoftDelete -Force
#New-ComplianceSearchAction -SearchName "Test" -Purge -PurgeType HardDelete -Force

<# Remove search from portal, otherwise it remains #>
Remove-ComplianceSearch -Identity 'Test' -Confirm:$false

<# sample search for all emails received on specific date #>
New-ComplianceSearch -Name 'ReceivedToday' -ExchangeLocation All -ContentMatchQuery 'Received:1/10/2024' | Start-ComplianceSearch


<# end session #>
Disconnect-ExchangeOnline -Confirm:$false






 



