<#
    .SYNOPSIS
    Collect M365 user last login using msgraph

    .DESCRIPTION
    Multiple functions to collect Microsoft 365 tenant data
    Modified for Powershell 7.x module compatibility

    .USAGE
    Interactive requirement to enter credentials
    Default output is current user's Desktop (macOS)

    .LINK
    https://github.com/12Knocksinna/Office365itpros/tree/master

    .NOTES
    Don Fernandes
    don@cbctech.net
    20240221 created

#>

# Connect to the Graph SDK with the correct permissions
Connect-MgGraph -NoWelcome -Scopes AuditLog.Read.All, Directory.Read.All

# Find user accounts
$Headers = @{ConsistencyLevel = "Eventual" }  
$Uri = "https://graph.microsoft.com/beta/users?`$count=true&`$filter=(assignedLicenses/`$count ne 0 and userType eq 'Member')&$`top=999&`$select=id, displayName, usertype, signInActivity"
[array]$Data = Invoke-MgGraphRequest -Uri $Uri -Headers $Headers
[array]$Users = $Data.Value

If (!($Users)) {
    Write-Host "Can't find any users... exiting!" ; break
}

# Paginate until we collect all user accounts
While ($Null -ne $Data.'@odata.nextLink') {
    Write-Host ("Fetching more user accounts - currently at {0}" -f $Users.count)
    $Uri = $Data.'@odata.nextLink'
    [array]$Data = Invoke-MgGraphRequest -Uri $Uri -Headers $Headers
    $Users = $Users + $Data.Value
}
Write-Host ("All available user accounts fetched ({0}) - now processing sign in report" -f $Users.count)

# Create report
$Report = [System.Collections.Generic.List[Object]]::new()
ForEach ($User in $Users) {
    $DaysSinceLastSignIn = $Null; $DaysSinceLastSuccessfulSignIn = $Null
    $DaysSinceLastSignIn = "N/A"; $DaysSinceLastSuccessfulSignIn = "N/A"
    $LastSuccessfulSignIn = $User.signInActivity.lastSuccessfulSignInDateTime
    $LastSignIn = $User.signInActivity.lastSignInDateTime
    If (!([string]::IsNullOrWhiteSpace($LastSuccessfulSignIn))) {
        $DaysSinceLastSuccessfulSignIn = (New-TimeSpan $LastSuccessfulSignIn).Days 
    }
    If (!([string]::IsNullOrWhiteSpace($LastSignIn))) {
        $DaysSinceLastSignIn = (New-TimeSpan $LastSignIn).Days
    }    
    $DataLine = [PSCustomObject][Ordered]@{
        User                            = $User.displayName
        UserId                          = $User.ID
        'Last successful sign in'       = $LastSuccessfulSignIn
        'Last sign in'                  = $LastSignIn
        'Days since successful sign in' = $DaysSinceLastSuccessfulSignIn
        'Days since sign in'            = $DaysSinceLastSignIn
    }
    $Report.Add($DataLine)
}
# Export report
$Report | Sort-Object 'Days since sign in' | Export-Csv ~/Desktop/last-login.csv -Force

