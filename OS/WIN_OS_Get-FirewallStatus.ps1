<#
    .SYNOPSIS
    check and enable firewall state
    
    .DESCRIPTION
    
    .PARAMETER

    .EXAMPLE
     
    .LINK
    
    .NOTES
    Don Fernandes
    don@cbctech.net
    cbc technologies llc
    created:20201109
    update: 20240706

    .INPUTS

    .OUTPUTS
     
#>

#----------------------------------------------
# VARIABLES
#----------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'

function Get-FirewallState 
{
  $FirewallStatus = 0
  $SysFirewallReg1 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile' -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
  If ($SysFirewallReg1 -eq 1) 
  {
    $FirewallStatus = 1 
  }

  $SysFirewallReg2 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
  If ($SysFirewallReg2 -eq 1) 
  {
    $FirewallStatus = ($FirewallStatus + 1) 
  }

  $SysFirewallReg3 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
  If ($SysFirewallReg3 -eq 1) 
  {
    $FirewallStatus = ($FirewallStatus + 1) 
  }

  If ($FirewallStatus -eq 3) 
  {
    Write-Host -Object 'myFirewallState firewall active'
  }
  else 
  {
    Write-Host -Object 'myFirewallState firewall is disabled, enabling now' 
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
  }   
}
Get-FirewallState
