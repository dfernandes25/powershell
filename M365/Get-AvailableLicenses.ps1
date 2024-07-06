<#
    .SYNOPSIS
    Get list of available licenses using msgraph

    .DESCRIPTION
    List license types and available units for assignment

    .USAGE
    Interactive requirement to enter credentials

    .LINK
    https://github.com/12Knocksinna/Office365itpros/tree/master

    .NOTES
    Don Fernandes
    don@cbctech.net
    20240221 created
    20240706 modified

#>

# Connect to the Graph with permission to update the directory (with licenses)
Connect-MgGraph -Scopes Directory.ReadWrite.All -NoWelcome
$LicensesAvailable = $True
    
# Find the set of SKUs used in the tenant
[array]$Skus = (Get-MgSubscribedSku)
$SkuList = [System.Collections.Generic.List[Object]]::new()  
ForEach ($Sku in $Skus) 
{
  $SkuAvailable = ($Sku.PrepaidUnits.Enabled - $Sku.ConsumedUnits)
  $ReportLine = [PSCustomObject]@{
    SkuId         = $Sku.SkuId
    SkuPartNumber = $Sku.SkuPartNumber
    Consumed      = $Sku.ConsumedUnits
    Paid          = $Sku.PrepaidUnits.Enabled
    Available     = $SkuAvailable
  }
  $SkuList.Add($ReportLine)
}
      
# Remove SKUs with no available licenses
$SkuList = $SkuList | Where-Object -FilterScript {
  $_.Available -gt 0
}
If ($SkuList.count -eq 0) 
{
  $LicensesAvailable = $False
  Write-Host -Object 'No SKUs have avaiilable licenses'
}

If ($LicensesAvailable -eq $True) 
{
  [int]$i = 0    
  Write-Host -Object ' '
  Write-Host -Object 'Product SKUs with available licenses' -ForegroundColor White
  Write-Host -Object '------------------------------------' -ForegroundColor White
  Write-Host -Object ''
  ForEach ($Sku in $SkuList) 
  {
    $i++
    $Line = ('{0}: {1} {2} ({3} licenses available)' -f $i, $Sku.SkuId, $Sku.SkuPartNumber, $Sku.Available)
    Write-Host -Object $Line 
  }
}
