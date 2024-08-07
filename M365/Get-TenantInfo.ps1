﻿<#
    .SYNOPSIS
    Collect M365 tenant information

    .DESCRIPTION
    Multiple functions to collect Microsoft 365 tenant data
    Modified for Powershell 7.x module compatibility

    .USAGE
    Interactive requirement to enter credentials
    The variable $dirdata requires your specific directory to store output
    The variable $spurl requires your specific Sharepoint admin url

    .LINK

    .NOTES
    Don Fernandes
    don@cbctech.net
    20240110 created
    20240706 modified

#>

<# variables #>
$dirdata = 'C:\scripts\m365Pros'
#$spurl = 'https://xxxxx-admin.sharepoint.com'
$credentials = Get-Credential

<# directory check and delete old data #>
if(!(Test-Path -Path $dirdata))
{
  mkdir -Path $dirdata
}
Get-ChildItem -Path $dirdata | Remove-Item -Force

<# m365 modules - compatibility for PSv7 #>
Import-Module -Name AzureAD
#Import-Module Microsoft.Online.Sharepoint.Powershell
Import-Module -Name MSOnline

<# connect to services #>
Connect-ExchangeOnline -Credential $credentials
Connect-AzureAD -Credential $credentials
#Connect-SPOService -Url $spurl -Credential $credentials
Connect-MsolService -Credential $credentials

<# exchange online mailbox info #>
Get-EXOCasMailbox | Export-Csv -Path ('{0}\CAS-MailboxInfo.csv' -f $dirdata) -NoTypeInformation -Force
Get-EXOMailbox    | Export-Csv -Path ('{0}\EXO-MailboxInfo.csv' -f $dirdata) -NoTypeInformation -Force
 
<# msol info #>  
Get-MsolCompanyInformation |
Select-Object -Property * |
Export-Csv -Path $dirdata\MSOL-Company-Info.csv -Force -NoTypeInformation

Get-MsolAccountSku  |
Select-Object -Property 'AccountSkuId', 'ActiveUnits', 'ConsumedUnits' |
Export-Csv -Path $dirdata\MSOL-AccountSKU.csv -Force -NoTypeInformation

<# AAD info #>
# tenant details #
Get-AzureADTenantDetail | Export-Csv -Path ('{0}\AAD-Tenant.csv' -f $dirdata) -Force -NoTypeInformation
# user details #
function Get-AADUser
{
  Get-AzureADUser |
  ForEach-Object -Process {
    [PSCustomObject]@{
      enabled = $_.AccountEnabled
      type    = $_.userType
      name    = $_.DisplayName
      upn     = $_.UserPrincipalName
      mail    = $_.Mail
    }
  } |
  Export-Csv -Path ('{0}\AAD-Users.csv' -f $dirdata) -Force -NoTypeInformation
} 
Get-AADUser

# group info #
function Get-AADGroups
{
  <# groups #>
  $groups = Get-AzureADGroup
  #$gcount = $groups.Count
     
  foreach($group in $groups)
  {
    $members = Get-AzureADGroupMember -ObjectId $group.ObjectId 
    $owner   = Get-AzureADGroupOwner -ObjectId $group.ObjectId | Select-Object -Property 'UserPrincipalName'
    $owners  = ($owner.UserPrincipalName -join ',')
   
    [PSCustomObject]@{
      name        = $group.DisplayName
      type        = $group.ObjectType 
      members     = $members.count
      mailenabled = $group.MailEnabled
      secenabled  = $group.SecurityEnabled
      deleted     = $group.DeletionTimestamp    
      owner       = $owners
      description = $group.Description
    } | Export-Csv -Path ('{0}\AAD-Groups.csv' -f $dirdata) -Append -NoTypeInformation
  }
} 
Get-AADGroups

# domain info #
function Get-AADDomains
{
  <# domains #>
  Get-AzureADDomain | ForEach-Object -Process {
    [PSCustomObject]@{
      name     = $_.Name
      authType = $_.AuthenticationType
      managed  = $_.IsAdminManaged
      default  = $_.IsDefault
      verified = $_.IsVerified
      root     = $_.IsRoot
      services = ($_.supportedservices -join ',')
    }       | Export-Csv -Path ('{0}\AAD-Domains.csv' -f $dirdata) -NoTypeInformation -Append
  }
}
Get-AADDomains

# role info #
function Get-AADRoles
{
  $roles = Get-AzureADDirectoryRole | Select-Object -Property 'Objectid', 'DisplayName'
  foreach ($role in $roles)
  {
    $id = $role.ObjectId
   
    <# object with noteproperty needs to be converted for csv export #>
    $members = Get-AzureADDirectoryRoleMember -ObjectId $id | Select-Object -Property 'DisplayName'
    $names = $members.displayname -join ','
   
    foreach($i in $id)
    {
      [PSCustomObject]@{
        role = $role.DisplayName
        name = $names
      } | Export-Csv -Path ('{0}\AAD-Roles.csv' -f $dirdata) -NoTypeInformation -Append
    }
  }
}
Get-AADRoles

# apps #
function Get-AADApps
{
  Get-AzureADApplication |
  Select-Object -Property 'DisplayName' |
  Export-Csv -Path ('{0}\AAD-Apps.csv' -f $dirdata) -NoTypeInformation -Append
} 
Get-AADApps
 
# contacts # 
function Get-AADContacts
{     
  Get-AzureADContact |
  Select-Object -Property 'DisplayName', 'Mail' |
  Export-Csv -Path ('{0}\AAD-Contacts.csv' -f $dirdata) -NoTypeInformation -Append
}
Get-AADContacts

<# Sharepoint #>
# site collections #
<# $Sites = Get-SPOSite -Limit ALL
 
    # get site owners for each collection #
    # need to add some error handling for sites with no owner #
    $SiteOwners = @()
    $Sites | ForEach-Object {
    If($_.Template -like 'GROUP*')  
    {
    $Site = Get-SPOSite -Identity $_.URL
    #Get Group Owners
    $GroupOwners = (Get-AzureADGroupOwner -ObjectId $Site.GroupID | Select-Object -ExpandProperty UserPrincipalName) -join "; "      
    }
    Else
    {
    $GroupOwners = $_.Owner 
    }
    #Collect Data
    $SiteOwners += New-Object PSObject -Property @{
    'Site Title' = $_.Title
    'URL' = $_.Url
    'Owner(s)' = $GroupOwners
    }
    }
    $SiteOwners | Export-Csv -Path "$dirdata\SP-SiteOwners.csv" -NoTypeInformation -Force
 
    # get members of each collection #
    # need to add error handling for sites with no members #
    $SiteMembers = @()
    $Sites | ForEach-Object {
    If($_.Template -like 'GROUP*')
    {
    $Site = Get-SPOSite -Identity $_.URL
    #Get Group Owners
    $GroupMembers = (Get-AzureADGroupMember -ObjectId $Site.GroupID | Select-Object -ExpandProperty UserPrincipalName) -join "; "      
    }
    Else
    {
    $GroupMembers = $_.Member
    }
    #Collect Data
    $SiteMembers += New-Object PSObject -Property @{
    'Site Title' = $_.Title
    'URL' = $_.Url
    'Member(s)' = $GroupMembers
    }
    }
    $SiteMembers | Export-Csv -Path "$dirdata\SP-SiteMembers.csv" -NoTypeInformation -Append

#>

function New-AuditReport
{
  #$dirdata = "$dirData"
  $fileout = 'M365-TENANT-OVERVIEW.xlsx'
  $outpath = Join-Path -Path $dirdata -ChildPath $fileout
  if($outpath)
  {
    Remove-Item -Path $outpath -Force -ErrorAction SilentlyContinue
  }
  Start-Sleep -Seconds 3

  $files = Get-ChildItem -Path ('{0}\*.csv' -f $dirdata) |
  Where-Object -FilterScript {
    $_.Length -ne 0
  } |
  ForEach-Object -Process {
    $sheetname = $_.basename
    Import-Csv -Path $_.fullname  | 
    Export-Excel -Path ('{0}' -f $outpath) -AutoSize -AutoFilter -FreezeTopRow -WorksheetName $sheetname -Title 'M365 TENANT OVERVIEW'
  }
}
New-AuditReport 