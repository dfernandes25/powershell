<#
    .SYNOPSIS
    Reset computer to factory settings
 
    .DESCRIPTION
    Unattended factory reset of windows 10 computer
    Requires SYSTEM privileges, (not Admin)
 
    .EXAMPLE
    
 
    .NOTES
    don fernandes
    cbc technologies llc
    oct 25, 2022
 
    .LINK
    https://techcommunity.microsoft.com/t5/windows-deployment/factory-reset-windows-10-without-user-intervention/m-p/1348679
 
    .INPUTS

    .OUTPUTS

#>



$namespaceName = 'root\cimv2\mdm\dmmap'
$className = 'MDM_RemoteWipe'

$methodName = 'doWipeMethod'
# this method can survive a user reboot
# $methodName = "doWipeProtectedMethod"

$session = New-CimSession

$params = New-Object -TypeName Microsoft.Management.Infrastructure.CimMethodParametersCollection
$param = [Microsoft.Management.Infrastructure.CimMethodParameter]::Create('param', '', 'String', 'In')
$params.Add($param)

$instance = Get-CimInstance -Namespace $namespaceName -ClassName $className -Filter "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'"
$session.InvokeMethod($namespaceName, $instance, $methodName, $params)
