<#
    .SYNOPSIS
    Get MFA status of M365 tenant users
    
    .DESCRIPTION
    creates grid view and csv file listing tenant users and their MFA status
    
    .PARAMETER

    .EXAMPLE
     
    .LINK
    
    .NOTES
    Don Fernandes
    don@cbctech.net
    cbc technologies llc
    created:20201109
    update: 20240706
     
#>

Connect-MsolService

$Users = Get-MsolUser -All | Where-Object -FilterScript {
  $_.UserType -ne 'Guest' 
}
$Report = [System.Collections.Generic.List[Object]]::new() # Create output file
Write-Host 'Processing' $Users.Count 'accounts...' 
ForEach ($User in $Users) 
{
  $MFADefaultMethod = ($User.StrongAuthenticationMethods | Where-Object -FilterScript {
      $_.IsDefault -eq 'True' 
  }).MethodType
  $MFAPhoneNumber = $User.StrongAuthenticationUserDetails.PhoneNumber
  $PrimarySMTP = $User.ProxyAddresses |
  Where-Object -FilterScript {
    $_ -clike 'SMTP*' 
  } |
  ForEach-Object -Process {
    $_ -replace 'SMTP:', '' 
  }
  $Aliases = $User.ProxyAddresses |
  Where-Object -FilterScript {
    $_ -clike 'smtp*' 
  } |
  ForEach-Object -Process {
    $_ -replace 'smtp:', '' 
  }

  If ($User.StrongAuthenticationRequirements) 
  {
    $MFAState = $User.StrongAuthenticationRequirements.State
  }
  Else 
  {
    $MFAState = 'Disabled'
  }

  If ($MFADefaultMethod) 
  {
    Switch ($MFADefaultMethod) {
      'OneWaySMS' 
      {
        $MFADefaultMethod = 'Text code authentication phone' 
      }
      'TwoWayVoiceMobile' 
      {
        $MFADefaultMethod = 'Call authentication phone' 
      }
      'TwoWayVoiceOffice' 
      {
        $MFADefaultMethod = 'Call office phone' 
      }
      'PhoneAppOTP' 
      {
        $MFADefaultMethod = 'Authenticator app or hardware token' 
      }
      'PhoneAppNotification' 
      {
        $MFADefaultMethod = 'Microsoft authenticator app' 
      }
    }
  }
  Else 
  {
    $MFADefaultMethod = 'Not enabled'
  }
  
  $ReportLine = [PSCustomObject] @{
    UserPrincipalName = $User.UserPrincipalName
    DisplayName       = $User.DisplayName
    MFAState          = $MFAState
    MFADefaultMethod  = $MFADefaultMethod
    MFAPhoneNumber    = $MFAPhoneNumber
    PrimarySMTP       = ($PrimarySMTP -join ',')
    Aliases           = ($Aliases -join ',')
  }
                 
  $Report.Add($ReportLine)
}

Write-Host -Object 'Report is in c:\scripts\m365Pros\MFAUsers.csv'
$Report |
    Select-Object -Property UserPrincipalName, DisplayName, MFAState, MFADefaultMethod, MFAPhoneNumber, PrimarySMTP, Aliases |
      Sort-Object -Property UserPrincipalName | Out-GridView
$Report |
    Sort-Object -Property UserPrincipalName |
      Export-Csv -Encoding UTF8 -NoTypeInformation -Force -Path 'c:\scripts\m365Pros\MFAUsers.csv'
