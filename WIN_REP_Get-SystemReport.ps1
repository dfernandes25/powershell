<#
    .INFO 
    Endpoint-Diagnostics.ps1
    Don Fernandes
    CBC Technologies
    Created:  20210903
    Modified: 2022102

    .SYNOPSIS
    Creates html report with various system parameters
    Uploads report to ftp server

    .LINKS
    https://gallery.technet.microsoft.com/scriptcenter/Disk-Usage-Analyser-e4b05c1d
    http://www.azurefieldnotes.com/2016/08/04/powershellhtmlreportingpart1/

    .PARAMETERS
    Run as a task in endpoint management tool

#>

#----------------------------------------------
# VARIABLES
#----------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'
$script:cname    = $env:COMPUTERNAME
$script:days     = (Get-Date).AddHours(-24)
$script:date     = (Get-Date).ToShortDateString().Replace('/', '-')
$script:scrdir   = "$env:homedrive\scripts"
$script:invdir   = "$scrdir\inventory"
$script:csvdir   = "$invdir\csv"
$script:rptdir   = "$scrdir\reports"
$script:rptName  = "$env:COMPUTERNAME" + '-HTML-Inventory.html'
$script:logdir   = "$env:HOMEDRIVE\scriptlogs"
$script:logname  = "$cname-myInventory.log"

# $ci = Get-ComputerInfo

#----------------------------------------------
# PACKAGES
#----------------------------------------------
$packageManager   = 'PackageManagement'
$modulePackageGet = 'PowerShellGet'
$packageProvider  = 'Nuget'
$modName          = 'ReportHTML'

function Get-HouseKeeping {
  if (!(Get-EventLog -LogName Application -Source cbctech))
  { New-EventLog -LogName Application -Source cbctech > $null }
  
  if (!(Test-Path $csvdir)) { mkdir $csvdir -Force > $null }
  else {
    $files = Get-ChildItem -Path $csvdir 
    foreach ($file in $files) { Remove-Item -Path "$csvdir\$file" -Force -Recurse }
  }
  
  if (!(Test-Path -Path $rptdir)) { mkdir $rptdir -Force }
  if (!(Test-Path -Path $logdir)) { mkdir $logdir -Force }
  
  Write-EventLog -LogName Application -Source 'cbctech' -Message 'myHtmlInventory initialized' -EventId 4444 -EntryType information
  Start-Sleep -Seconds 3
  
  if (!(Get-PackageProvider -Name "$packageProvider")) {
    Import-Module -Name "$packageManager" -Force
    Import-Module -Name "$modulePackageGet" -Force
    Install-PackageProvider -Name "$packageProvider" -Force
    Import-PackageProvider -Name "$packageProvider" -ForceBootStrap
  }
 
  
  if (!(Get-InstalledModule -Name "$modName" )) {
    Install-Module -Name "$modName" -Force
    Import-Module -Name "$modName" -Force
  }else {Update-Module -Force -Name "$modName"}
}

Write-EventLog -LogName Application -Source 'cbctech' -Message 'myHtmlInventory packages loaded' -EventId 4444 -EntryType information
Write-EventLog -LogName Application -Source 'cbctech' -Message 'myHtmlInventory gathering data' -EventId 4444 -EntryType information
Start-Sleep -Seconds 3

function Get-userInfo {
  $sysUsers = Get-WmiObject -Class Win32_UserAccount -ComputerName $cname |
  Select-Object -Property Name, AccountType, SID, Status, PasswordRequired, PasswordExpires, PasswordChangeable, Domain
  $sysUsers
}
 
function Get-CompInfo {
  $sysComp = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $cname
  $sysComp2 = Get-WmiObject -Class Win32_ComputerSystemProduct -ComputerName $cname
  $compInfo = [ordered] @{
    'Vendor'       = $sysComp.Manufacturer
    'Model Number' = $sysComp.Model
    'Model Name'   = $sysComp2.Version
    'Domain'       = $sysComp.Domain
  }

  New-Object -TypeName psobject -Property $compInfo
}

function Get-BiosInfo {
  $sysBIOS = Get-WmiObject -Class Win32_BIOS -ComputerName $cname
  $biosInfo = [ordered] @{
    'Version'    = $sysBIOS.BIOSVersion[0]
    'SMBIOS'     = $sysBIOS.SMBIOSBIOSVersion
    'Serial Num' = $sysBIOS.SerialNumber
    'Status'     = $sysBIOS.Status
  }

  New-Object -TypeName psobject -Property $biosInfo 
}

function Get-OsInfo {
  $sysOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $cname
  $OSInfo = [ordered] @{
    'OS'     = $sysOS.Caption
    'Build'  = $sysOS.BuildNumber
    'Serial' = $sysOS.SerialNumber
    'SP'     = $sysOS.servicepackmajorversion
  }

  New-Object -TypeName psobject -Property $OSInfo
}

function Get-CpuInfo {
  $sysCPU = Get-WmiObject -Class Win32_Processor -ComputerName $cname
  $cpuInfo = [ordered] @{
    'Processor'     = $sysCPU.Name
    'ID'            = $sysCPU.ProcessorId
    'Serial'        = $sysCPU.SerialNumber
    'Cores'         = $sysCPU.NumberOfCores
    'Virt Enabled'  = $sysCPU.VirtualizationFirmwareEnabled
    'Max Speed GHz' = $sysCPU.MaxClockSpeed / 1000
  }

  New-Object -TypeName psobject -Property $cpuInfo
}

function Get-ramInfo {
  $sysRAM = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $cname
  if ($sysRAM[0].TypeDetail = 128) {
    $typeDetail = 'Synchronous'
  }
  else {
    $typeDetail = 'Unknown'
  }
  
  if ($sysRAM[0].MemoryType = 24) {
    $memType = 'DDR3'
  }
  else {
    $typeDetail = 'Unknown'
  }
  
  $sysComp = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $cname
  $ramInfo = [ordered] @{
    'Total RAM'    = $sysComp.TotalPhysicalMemory
    'Banks Used'   = $sysRAM.Count
    'Manufacturer' = $sysRAM[0].Manufacturer
    'Clock Speed'  = $sysRAM[0].ConfiguredClockSpeed
    'Part Number'  = $sysRAM[0].PartNumber
    'Type Detail'  = $typeDetail
    'Memory Type'  = $memType
  }

  New-Object -TypeName psobject -Property $ramInfo
}

function Get-NicInfo {
  $NICS = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $cname -Filter "IPEnabled='True'"
  
  ForEach ($NIC in $NICS) {
    $nicInfo = [ordered] @{
      'NIC Description' = $NIC.Description
      'DHCP'            = $NIC.DHCPEnabled
      'DNS Domain'      = $NIC.DNSDomain
      'IP Address'      = $NIC.IPAddress[0]
      'IP Gateway'      = [string]$NIC.DefaultIPGateway
      'IP Subnet'       = $NIC.IPSubnet[0]
      'MAC'             = $NIC.MACAddress
      'Service'         = $NIC.ServiceName
    }
    New-Object -TypeName psobject -Property $nicInfo
  }
}

function Get-MonInfo {
  $sysMon = Get-WmiObject -Class Win32_DesktopMonitor -ComputerName $cname
  $monInfo = [ordered] @{
    'Manufacturer' = $sysMon.MonitorManufacturer
    'Monitor Type' = $sysMon.MonitorType
    'Monitor Name' = $sysMon.Name
  }
  New-Object -TypeName psobject -Property $monInfo
}

function Get-vidInfo {
  $sysVid = Get-WmiObject -Class Win32_VideoController -ComputerName $cname
  $vidInfo = [ordered] @{
    'Name'   = $sysVid.Name
    'Mode'   = $sysVid.VideoModeDescription
    'Driver' = $sysVid.DriverVersion  
  }
  New-Object -TypeName psobject -Property $vidInfo
}

function Get-printerInfo {
  $sysPrinters = Get-WmiObject -Class Win32_Printer -ComputerName $cname |
  Select-Object -Property Name, PrinterState, PrinterStatus
  $sysPrinters
}

function Get-FirewallInfo { 
  $fwMgr = New-Object -ComObject HNetCfg.FwMgr  
  $profile = $fwMgr.LocalPolicy.CurrentProfile 
  # if (!$profile.FirewallEnabled) {$profile.FirewallEnabled = $TRUE} #turn on firewall
  $fwprops = [ordered] @{
    'FirewallEnabled'              = $profile.FirewallEnabled
    'FirewallExceptionsAllowed'    = $profile.ExceptionsNotAllowed
    'FirewallProfileType'          = $profile.Type
    'FirewallNotificationSettings' = $profile.NotificationsDisabled
    'FirewallRemoteAdmin'          = $profile.RemoteAdminSettings.Enabled
  }
  New-Object -TypeName PSObject -Property $fwprops
}

function Get-AvInfo {
  $sysAV = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $cname
  switch ($sysAV.ProductState) {
    '262144' {
      $DefStatus = 'Up to date'  
      $RTStatus = 'Disabled'
    }
    '262160' {
      $DefStatus = 'Out of date' 
      $RTStatus = 'Disabled'
    }
    '266240' {
      $DefStatus = 'Up to date'  
      $RTStatus = 'Enabled'
    }
    '266256' {
      $DefStatus = 'Out of date' 
      $RTStatus = 'Enabled'
    }
    '393216' {
      $DefStatus = 'Up to date'  
      $RTStatus = 'Disabled'
    }
    '393232' {
      $DefStatus = 'Out of date' 
      $RTStatus = 'Disabled'
    }
    '393488' {
      $DefStatus = 'Out of date' 
      $RTStatus = 'Disabled'
    }
    '397312' {
      $DefStatus = 'Up to date'  
      $RTStatus = 'Enabled'
    }
    '397328' {
      $DefStatus = 'Out of date' 
      $RTStatus = 'Enabled'
    }
    '397584' {
      $DefStatus = 'Out of date' 
      $RTStatus = 'Enabled'
    }
    default {
      $DefStatus = 'Unknown' 
      $RTStatus = 'Unknown'
    }
  } 
     
  $avInfo = [ordered] @{
    'AV Name'    = $sysAV.displayName
    'Definition' = $DefStatus
    'Status'     = $RTStatus
  }
  New-Object -TypeName psobject -Property $avInfo 
}

function Get-diskInfo {
  $drives = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $cname -Filter 'DriveType=3'
  ForEach ($drive in $drives) {
    $hdInfo = [ordered] @{
      'Drive'    = $drive.DeviceID
      'Size GB'  = $drive.Size / 1GB -as [int]
      'Free GB'  = '{0:N2}' -f ($drive.freespace / 1GB) -as [int]
      'Free Pct' = ($drive.freespace / $drive.size) * 100 -as [int]
    }
    New-Object -TypeName psobject -Property $hdInfo
  }
}

function Get-SvcInfo {
  [CmdletBinding()]
  param
  (
    $svcs
  )
  $svcs = Get-WmiObject -Class Win32_Service -ComputerName $cname -Filter "StartMode='Auto' AND State<>'Running'"
  foreach ($svc in $svcs) {
    $svcInfo = @{
      'AutoStartService' = $svc.name
      'LogonAccount'     = $svc.startname
      'DisplayName'      = $svc.displayname
    }
    New-Object -TypeName PSObject -Property $svcInfo
  }
}  

function Get-ProcInfo {
  [CmdletBinding()]
  param
  (
    $procs
  )
  $procs = Get-Process |
  Where-Object -FilterScript {
    $_.company -notlike '*microsoft*'
  }  | 
  Sort-Object -Property RunTime -Descending |
  Select-Object -First 10 |
  Select-Object -Property Name, Description, Company, Handles, WS 
  $procs  
}

function Get-UserDirectories {
  $dirRoot = $env:USERPROFILE # Change this as desired
  $filter = '*' # Change this as desired, e.g. *.log or *.txt
  function Get-FolderSize {
    [CmdletBinding()]
    param
    (
      [Object]$path
    )
    $total = (Get-ChildItem -Path $path -ErrorAction SilentlyContinue -Filter $filter | Measure-Object -Property length -Sum -ErrorAction SilentlyContinue).Sum
    if (-not($total)) {
      $total = 0
    }
    $total
  }
  $results = @()
  $dirs = Get-ChildItem -Path $dirRoot -ErrorAction SilentlyContinue | Where-Object -FilterScript {
    $_.psIsContainer
  }

  foreach ($dir in $dirs) {
    $childFiles = @(Get-ChildItem -Path $dir.pspath -ErrorAction SilentlyContinue -Filter $filter | Where-Object -FilterScript {
        -not($_.psIsContainer)
      })
    if ($childFiles) {
      $filecount = ($childFiles.count)
    }
    else {
      $filecount = 0
    }

    $childDirs = @(Get-ChildItem -Path $dir.pspath -ErrorAction SilentlyContinue | Where-Object -FilterScript {
        $_.psIsContainer
      })
    if ($childDirs ) {
      $dircount = ($childDirs.count)
    }
    else {
      $dircount = 0
    }
    
    $result = New-Object -TypeName psobject -Property @{
      'Folder'         = (Split-Path -Path $dir.pspath -NoQualifier)
      'TotalSize (MB)' = ((Get-FolderSize -path ($dir.pspath)) / 1MB) -as [int]
      'FileCount'      = $filecount
      'SubDirs'        = $dircount
    }
    $results += $result
  }
  $results
}

function Get-InstalledSoftware {
  <#
	.SYNOPSIS
		Retrieves a list of all software installed on a Windows computer.
	.EXAMPLE
		PS> Get-InstalledSoftware
		
		This example retrieves all software installed on the local computer.
	.PARAMETER ComputerName
		If querying a remote computer, use the computer name here.
	
	.PARAMETER Name
		The software title you'd like to limit the query to.
	
	.PARAMETER Guid
		The software GUID you'e like to limit the query to
	#>
  [CmdletBinding()]
  param (
		
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName = $env:COMPUTERNAME,
		
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
		
    [Parameter()]
    [guid]$Guid
  )
  process {
    try {
      $scriptBlock = {
        $args[0].GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value }
				
        $UninstallKeys = @(
          "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
          "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
        $UninstallKeys += Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | foreach {
          "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        }
        if (-not $UninstallKeys) {
          Write-Warning -Message 'No software registry keys found'
        }
        else {
          foreach ($UninstallKey in $UninstallKeys) {
            $friendlyNames = @{
              'DisplayName'    = 'Name'
              'DisplayVersion' = 'Version'
            }
            Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
            if ($Name) {
              $WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" }
            }
            elseif ($GUID) {
              $WhereBlock = { $_.PsChildName -eq $Guid.Guid }
            }
            else {
              $WhereBlock = { $_.GetValue('DisplayName') }
            }
            $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
            if (-not $SwKeys) {
              Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
            }
            else {
              foreach ($SwKey in $SwKeys) {
                $output = @{ }
                foreach ($ValName in $SwKey.GetValueNames()) {
                  if ($ValName -ne 'Version') {
                    $output.InstallLocation = ''
                    if ($ValName -eq 'InstallLocation' -and 
                      ($SwKey.GetValue($ValName)) -and 
                      (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\'))) {
                      $output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
                    }
                    [string]$ValData = $SwKey.GetValue($ValName)
                    if ($friendlyNames[$ValName]) {
                      $output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
                    }
                    else {
                      $output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
                    }
                  }
                }
                $output.GUID = ''
                if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b') {
                  $output.GUID = $SwKey.PSChildName
                }
                New-Object -TypeName PSObject -Prop $output
              }
            }
          }
        }
      }
			
      if ($ComputerName -eq $env:COMPUTERNAME) {
        & $scriptBlock $PSBoundParameters
      }
      else {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $PSBoundParameters
      }
    }
    catch {
      Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
    }
  }
}

function Get-AppInfo {
  $win32_product = Get-InstalledSoftware
  foreach ($app in $win32_product) {
    $applications = [ordered] @{
      'Name'        = $app.Name
      'Version'     = $app.Version
      'Vendor'      = $app.Publisher
      'GUID'        = $app.GUID
      'InstallDate' = $app.InstallDate
      'Size'        = $app.EstimatedSize
    }
    New-Object -TypeName PSObject -Property $applications        
  }
}

<#
    function Get-Shares
    {
    $shares = Get-SMBShare -ErrorAction SilentlyContinue | Select-Object -Property Name, ScopeName, Path, Description	
    $shares
    }
#>

function Get-EventLogs {
  $events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Application', 'System'
    Level     = 2, 3
    StartTime = $days
  } -ErrorAction SilentlyContinue | Select-Object -Property TimeCreated, LogName, ProviderName, Id, LevelDisplayName, Message 	
  $events
}

function Get-InterestingEvents {
  $interestingEvents = Get-WinEvent -FilterHashtable @{
    Logname   = 'System'
    ID        = 7001, 7002
    StartTime = $days
  } | 
  Select-Object -Property ID, @{
    label      = 'Category'
    expression = {
      Switch ($_.ID) {
        '7001' {
          'Logon'
        }
        '7002' {
          'Logoff'
        }
      }
    }
  }, @{
    label      = 'Time Created'
    expression = {
      $_.TimeCreated.ToString('yyyy-M-d HH:mm:ss')
    }
  }, Message
  $interestingEvents
}


Write-EventLog -LogName Application -Source 'cbctech' -Message 'myHtmlInventory building report' -EventId 4444 -EntryType information

function Get-HtmlReport {  
  $rpt = @() 
  $rpt += Get-HTMLOpenPage -TitleText "$env:COMPUTERNAME Diagnostics Report" 
  
  # users #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Users" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-userInfo)
  $rpt += Get-HTMLContentClose  
  # endpoint #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Endpoint" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-CompInfo) -Fixed
  $rpt += Get-HTMLContentClose
  # bios #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME BIOS" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-BiosInfo) -Fixed
  $rpt += Get-HTMLContentClose
  # os #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME OS" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-OsInfo) -Fixed
  $rpt += Get-HTMLContentClose
  
  # ram #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME RAM" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-ramInfo) -Fixed
  $rpt += Get-HTMLContentClose
  # cpu #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME CPU" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-CpuInfo) -Fixed
  $rpt += Get-HTMLContentClose
  # nic #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME NIC" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-NicInfo)
  $rpt += Get-HTMLContentClose
  # mon #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Monitor" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-MonInfo) -Fixed
  $rpt += Get-HTMLContentClose
  
  # vid #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Video" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-vidInfo) -Fixed
  $rpt += Get-HTMLContentClose
  # printer #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Printers" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-printerInfo)
  $rpt += Get-HTMLContentClose   
  # firewall #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Firewall" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-FirewallInfo) -Fixed
  $rpt += Get-HTMLContentClose
  # av #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME AntiVirus" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-AvInfo) -Fixed
  $rpt += Get-HTMLContentClose
  
  # disk #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Disk Drive" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-diskInfo) -Fixed
  $rpt += Get-HTMLContentClose 
  # svcs #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Startup Services" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-SvcInfo)
  $rpt += Get-HTMLContentClose  
  # processes #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Top 10 Processes" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-ProcInfo)
  $rpt += Get-HTMLContentClose  
  # user directories #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME User Directory" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-UserDirectories)
  $rpt += Get-HTMLContentClose
                       
  # applications #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Applications" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-AppInfo)
  $rpt += Get-HTMLContentClose
  # environmentals #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Environmentals" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-ChildItem -Path env: | Select-Object -Property Name, Value)
  $rpt += Get-HTMLContentClose 
  # powershell #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Powershell Version" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects ($PSVersionTable.PSVersion)
  $rpt += Get-HTMLContentClose 
  
  <# smb #
      $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME SMB Shares" -IsHidden -BackgroundShade 1
      $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-Shares)
      $rpt += Get-HTMLContentClose 
  #>
  
  # 24 hour warning and error events #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME System and App Events" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-EventLogs)
  $rpt += Get-HTMLContentClose  
  # interesting events #
  $rpt += Get-HTMLContentOpen -HeaderText "$env:COMPUTERNAME Interesting Events" -IsHidden -BackgroundShade 1
  $rpt += Get-HTMLContentTable -ArrayOfObjects (Get-InterestingEvents)
  $rpt += Get-HTMLContentClose 
            
  Save-HTMLReport -ReportContent $rpt -ReportName $rptName -ReportPath $rptdir #-ShowReport
}

Get-HouseKeeping
Get-HtmlReport

Write-EventLog -LogName Application -Source 'cbctech' -Message 'myHtmlInventory uploading report' -EventId 4444 -EntryType information

function Send-FTP {
  [CmdletBinding()]
  [OutputType([string])]
  
  param
  (
    
    [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
    [string]$user = 'username',

    [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
    [string]$pass = 'password',

    [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
    [string]$filter = '*.html',

    [Parameter(Mandatory = $false, Position = 3, ValueFromPipeline = $true)]
    [string]$ftpDownload = "$rptdir",

    [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
    [string]$ftp = 'ftp://xxx.xx.xxx.xxx/uploads/BuildInventory/'
   
  )

  $webclient = New-Object -TypeName System.Net.WebClient  
  $webclient.Credentials = New-Object -TypeName System.Net.NetworkCredential -ArgumentList ($user, $pass)  
 
  foreach ($item in (Get-ChildItem -Path $ftpDownload -Filter $filter)) {
    $uri = New-Object -TypeName System.Uri -ArgumentList ($ftp + $item.Name) 
    $webclient.UploadFile($uri, $item.FullName) 
  }
} 
# Send-FTP

Write-EventLog -LogName Application -Source 'cbctech' -Message 'myHtmlInventory complete' -EventId 4444 -EntryType information


<# NEED TO ADD
    Windows update checks and installs
    Driver checks
    Additional event error codes
    ScriptBlock logging
#>
