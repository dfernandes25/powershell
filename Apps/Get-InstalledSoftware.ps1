#requires -Modules Microsoft.PowerShell.Management
#requires -version 3.0
<#
    Quickly list installed software on multiple machines without using WMI win32_Product class which can be slow
    Based on code from https://blogs.technet.microsoft.com/heyscriptingguy/2011/11/13/use-powershell-to-quickly-find-installed-software/
#>

<#
    .SYNOPSIS

    Retrieve information on installed programs

    .DESCRIPTION
    Does not use WMI/CIM since Win32_Product only retrieves MSI installed software. Instead it processes the "Uninstall" registry key(s) which is also usually much faster

    .PARAMETER computers
    Comma separated list of computer names to query. Use . to represent the local computer

    .PARAMETER exportcsv
    The name and optional path to a non-existent csv file which will have the results written to it

    .PARAMETER gridview
    The output will be presented in an on screen filterable/sortable grid view. Lines selected when OK is clicked will be placed in the clipboard

    .PARAMETER uninstall
    Run the uninstaller defined for each item selected in the gridview after OK is clicked. Will only run uninstallers for packages selected on the local computer

    .PARAMETER remove
    Comma separated list of one or more package names, or regular expressions that mach one or more package names, that will be uninstalled.

    .PARAMETER silent
    Try and run the uninstall silently. This only works where the uninstall program is msiexec.exe

    .PARAMETER importcsv
    A csv file containing a list of computers to process where the computer name is in the "ComputerName" column unless specified via the -computerColumnName parameter

    .PARAMETER computerColumnName
    The column name in the csv specified via -importcsv which contains the name of the computer to query

    .PARAMETER includeEmptyDisplayNames
    Includes registry keys which have no "DisplayName" value which may not be valid installed packages

    .EXAMPLE
    & '.\Get installed software.ps1' -gridview -computers .
    Retrieve installed software details on the local computer and show in a grid view

    .EXAMPLE
    & '.\Get installed software.ps1' -computers computer1,computer2,computer3 -exportcsv installed.software.csv
    Retrieve installed software details on the computers computer1, computer2 and computer3 and write to the CSV file "installed.software.csv" in the current directory

    .EXAMPLE
    & '.\Get installed software.ps1' -gridview -importcsv computers.csv -computerColumnName Machine
    Retrieve installed software details on computers in the CSV file computers.csv in the current directory where the column name "Machine" contains the name of the computer and write the results to standard output

    .EXAMPLE
    & '.\Get installed software.ps1' -gridview -computers . -uninstall
    Retrieve installed software details on the local computer and show in a grid view. Packages selected after OK is clicked in the grid view will be uninstalled.

    .EXAMPLE
    & '.\Get installed software.ps1' -computers . -remove '7\-zip','Notepad\+\+' -Confirm:$false
    Retrieve installed software details on the local computer and and remove 7-Zip and Notepad++ without asking for confirmation.

    .EXAMPLE

    & '.\Get installed software.ps1' -computers . -remove 'Acrobat Reader' -Confirm:$false -silent
    Retrieve installed software details on the local computer and and remove Adobe Acrobat Reader silently, so without any user prompts, and without asking for confirmation.

#>

function Get-InstalledSoftware 
{
  [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High', DefaultParameterSetName = 'ComputerList')]

  Param
  (
    [Parameter(Mandatory = $false, ParameterSetName = 'ComputerList')]
    [string[]]$computers ,
    [string]$exportcsv ,
    [switch]$gridview ,
    [Parameter(Mandatory = $false, ParameterSetName = 'ComputerCSV')]
    [string]$importcsv ,
    [Parameter(Mandatory = $false, ParameterSetName = 'ComputerCSV')]
    [string]$computerColumnName = 'ComputerName' ,
    [switch]$uninstall ,
    [string[]]$remove ,
    [switch]$silent ,
    [switch]$quiet ,
    [switch]$includeEmptyDisplayNames
  )

  Function Remove-Package() 
  {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param
    (
      $package ,
      [switch]$silent
    )

    [bool]$uninstallerRan = $false

    if ( $package.ComputerName -eq $env:COMPUTERNAME ) 
    {
      Write-Verbose -Message ('Removing `"{0}`" ...' -f $package.DisplayName)

      if ( ! [string]::IsNullOrEmpty( $package.Uninstall ) ) 
      {
        if ( $PSCmdlet.ShouldProcess( $package.DisplayName , 'Remove package' ) ) 
        {
          ## need to split uninstall line so we can pass to Start-Process since we need to wait for each to finish in turn
          [string]$executable = $null
          [string]$arguments = $null
          if ( $package.Uninstall -match '^"([^"]*)"\s?(.*)$' `
          -or $package.Uninstall -match '^(.*\.exe)\s?(.*)$' ) 
          {
            ## cope with spaces in path but no quotes
            $executable = $Matches[1]
            $arguments = $Matches[2].Trim()
          }
          else 
          {
            ## unquoted so see if there's a space delimiting exe and arguments
            [int]$space = $package.Uninstall.IndexOf( ' ' )
            if ( $space -lt 0 ) 
            {
              $executable = $package.Uninstall
            }
            else 
            {
              $executable = $package.Uninstall.SubString( 0 , $space )
              if ( $space -lt $package.Uninstall.Length ) 
              {
                $arguments = $package.Uninstall.SubString( $space ).Trim()
              }
            }
          }
          [hashtable]$processArguments = @{
            'FilePath' = $executable
            'PassThru' = $True
            'Wait'   = $True
          }
          if ( $silent ) 
          {
            if ( $executable -match '^msiexec\.exe$' -or $executable -match '^msiexec$' -or $executable -match '[^a-z0-9_]msiexec\.exe$' -or $executable -match '[^a-z0-9_]msiexec$' ) 
            {
              ## Some uninstallers pass /I as they are meant to be interactive so we'll change this to /X
              $arguments = ($arguments -replace '/I' , '/X') + ' /qn /norestart'
            }
            else 
            {
              Write-Warning -Message ("Don't know how to run silent uninstall for package `"{0}`", uninstaller `"{1}`"" -f $package.DisplayName, $executable)
            }
          }
          if ( ! [string]::IsNullOrEmpty( $arguments ) ) 
          {
            $processArguments.Add( 'ArgumentList' , $arguments )
          }
          Write-Verbose -Message ('Running {0} `"{1}`" for {2} ...' -f $executable, $arguments, $package.DisplayName)
          $uninstallProcess = Start-Process @processArguments
          if ( ( Get-Variable -Name 'uninstallProcess' -ErrorAction SilentlyContinue ) -and $uninstallProcess ) 
          {
            ## catch where user declined UAC elevation
            Write-Verbose -Message ('Uninstall exited with code {0}' -f $uninstallProcess.ExitCode)
            ## https://docs.microsoft.com/en-us/windows/desktop/Msi/error-codes
            if ( $uninstallProcess.ExitCode -eq 3010 ) 
            {
              ## maybe should check it's msiexec that ran
              Write-Warning -Message ('Uninstall of `"{0}`" requires a reboot' -f $package.DisplayName)
            }
            $uninstallerRan = $True
          }
        }
      }
      else 
      {
        Write-Warning -Message ('Unable to uninstall `"{0}`" as it has no uninstall string' -f $package.DisplayName)
      }
    }
    else 
    {
      Write-Warning -Message ('Unable to uninstall `"{0}`" as it is on {1} and may not be silent' -f $package.DisplayName, $package.ComputerName)
    }

    $uninstallerRan
  }

  Function Process-RegistryKey 
  {
    [CmdletBinding()]
    Param
    (
      [string]$hive ,
      $reg ,
      [string[]]$UninstallKeys ,
      [switch]$includeEmptyDisplayNames ,
      [AllowNull()]
      [string]$username
    )

    ForEach ( $UninstallKey in $UninstallKeys ) 
    {
      $regkey = $reg.OpenSubKey($UninstallKey) 
    
      if ( $regkey ) 
      {
        [string]$architecture = if ( $UninstallKey -match '\\wow6432node\\' ) 
        {
          '32 bit'
        }
        else 
        {
          'Native'
        } 

        $subkeys = $regkey.GetSubKeyNames() 
    
        foreach ($key in $subkeys) 
        {
          $thisKey = Join-Path -Path $UninstallKey -ChildPath $key 

          $thisSubKey = $reg.OpenSubKey($thisKey) 

          if ( $includeEmptyDisplayNames -or ! [string]::IsNullOrEmpty( $thisSubKey.GetValue('DisplayName') ) ) 
          {
            [string]$installDate = $thisSubKey.GetValue('InstallDate')
            $installedOn = New-Object -TypeName 'DateTime'
            if ( [string]::IsNullOrEmpty( $installDate ) -or ! [datetime]::TryParseExact( $installDate , 'yyyyMMdd' , [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$installedOn ) ) 
            {
              $installedOn = $null
            }
            $size = New-Object -TypeName 'Int'
            if ( ! [int]::TryParse( $thisSubKey.GetValue('EstimatedSize') , [ref]$size ) ) 
            {
              $size = $null
            }
            else 
            {
              $size = [math]::Round( $size / 1KB , 1 ) ## already in KB
            }

            [pscustomobject][ordered]@{
              'ComputerName'   = $computername
              'Hive'           = $hive
              'User'           = $username
              'Key'            = $key
              'Architecture'   = $architecture
              'DisplayName'    = $($thisSubKey.GetValue('DisplayName'))
              'DisplayVersion' = $($thisSubKey.GetValue('DisplayVersion'))
              'InstallLocation' = $($thisSubKey.GetValue('InstallLocation'))
              'InstallSource'  = $($thisSubKey.GetValue('InstallSource'))
              'Publisher'      = $($thisSubKey.GetValue('Publisher'))
              'InstallDate'    = $installedOn
              'Size (MB)'      = $size
              'System Component' = $($thisSubKey.GetValue('SystemComponent') -eq 1)
              'Comments'       = $($thisSubKey.GetValue('Comments'))
              'Contact'        = $($thisSubKey.GetValue('Contact'))
              'HelpLink'       = $($thisSubKey.GetValue('HelpLink'))
              'HelpTelephone'  = $($thisSubKey.GetValue('HelpTelephone'))
              'Uninstall'      = $($thisSubKey.GetValue('UninstallString'))
            }
          }
          else 
          {
            Write-Warning -Message ('Ignoring `"{0}\{1}`" on {2} as has no DisplayName entry' -f $hive, $thisKey, $computername)
          }

          $thisSubKey.Close()
        } 
        $regkey.Close()
      }
      elseif ( $hive -eq 'HKLM' ) 
      {
        Write-Warning -Message ('Failed to open `"{0}\{1}`" on {2}' -f $hive, $UninstallKey, $computername)
      }
    }
  }

  if ( $quiet ) 
  {
    $VerbosePreference = $WarningPreference = 'SilentlyContinue'
  }

  [string[]]$UninstallKeys = @( 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall' , 'SOFTWARE\\wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall' )

  if ( $uninstall -and ! $gridview ) 
  {
    Throw 'Can only use -uninstall when -gridview is used too'
  }

  if ( $remove -and $remove.Count ) 
  {
    if ( $gridview ) 
    {
      Throw 'Can only use -remove when -gridview is not used'
    }
    [string[]]$invalids = @()
    ForEach ( $removal in $remove ) 
    {
      try 
      {
        $null = $null -match $removal
      }
      catch 
      {
        $invalids += $_.Exception.Message
      }
    }

    if ( $invalids -and $invalids.Count ) 
    {
      Throw ("There were {0} -remove arguments which were invalid regular expressions:`n`tError {1}" -f $invalids.Count, ($invalids -join "`n`tError "))
    }
  }

  if ( ! [string]::IsNullOrEmpty( $importcsv ) ) 
  {
    Remove-Variable -Name computers -Force -ErrorAction Stop
    $computers = @( Import-Csv -Path $importcsv -ErrorAction Stop )
  }

  if ( ! $computers -or $computers.Count -eq 0 ) 
  {
    $computers = @( $env:COMPUTERNAME )
  }

  [array]$installed = @( foreach ($pc in $computers) 
    {
      if ( [string]::IsNullOrEmpty( $importcsv ) ) 
      {
        $computername = $pc
      }
      elseif ( $pc.PSObject.Properties[ $computerColumnName ] ) 
      {
        $computername = $pc.PSObject.Properties[ $computerColumnName ].Value
      }
      else 
      {
        Throw ('Column name `"{0}`" missing from `"{1}`"' -f $computerColumnName, $importcsv)
      }

      if ( $computername -eq '.' ) 
      {
        $computername = $env:COMPUTERNAME
      }

      $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey( 'LocalMachine' , $computername )
    
      if ( $? -and $reg ) 
      {
        Process-RegistryKey -Hive 'HKLM' -reg $reg -UninstallKeys $UninstallKeys -includeEmptyDisplayNames:$includeEmptyDisplayNames
        $reg.Close()
      }
      else 
      {
        Write-Warning -Message ('Failed to open HKLM on {0}' -f $computername)
      }

      $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey( 'Users' , $computername )
    
      if ( $? -and $reg ) 
      {
        ## get each user SID key and process that for per-user installed apps
        ForEach ( $subkey in $reg.GetSubKeyNames() ) 
        {
          try 
          {
            if ( $userReg = $reg.OpenSubKey( $subkey ) ) 
            {
              [string]$username = $null
              try 
              {
                $username = ([System.Security.Principal.SecurityIdentifier]($subkey)).Translate([System.Security.Principal.NTAccount]).Value
              }
              catch 
              {
                $username = $null
              }
              Process-RegistryKey -Hive (Join-Path -Path 'HKU' -ChildPath $subkey) -reg $userReg -UninstallKeys $UninstallKeys -includeEmptyDisplayNames:$includeEmptyDisplayNames -user $username
              $userReg.Close()
            }
          }
          catch 
          {

          }
        }
        $reg.Close()
      }
      else 
      {
        Write-Warning -Message ('Failed to open HKU on {0}' -f $computername)
      }
  } ) | Sort-Object -Property ComputerName, DisplayName

  [int]$uninstalled = 0

  if ( $installed -and $installed.Count ) 
  {
    Write-Verbose -Message ('Found {0} installed items on {1} computers' -f $installed.Count, $computers.Count)

    if ( ! [string]::IsNullOrEmpty( $exportcsv ) ) 
    {
      $installed | Export-Csv -NoClobber -NoTypeInformation -Path $exportcsv
    }
    if ( $gridview ) 
    {
      $packages = $installed | Out-GridView -Title ('{0} installed items on {1} computers' -f $installed.Count, $computers.Count) -PassThru
      if ( $packages ) 
      {
        if ( $uninstall ) 
        {
          ForEach ( $package in $packages ) 
          {                 
            if ( Remove-Package -Package $package -silent:$silent ) 
            {
              $uninstalled++
            }
          }
        }
        else 
        {
          $packages | Set-Clipboard
        }
      }
    }
    elseif ( $remove -and $remove.Count ) 
    {
      [int]$matched = 0
      ForEach ( $removal in $remove ) 
      {
        $removed = $installed |
        Where-Object {
          $_.DisplayName -match $removal
        } |
        ForEach-Object `
        {
          $matched++
          if ( Remove-Package -Package $_ -silent:$silent ) 
          {
            $uninstalled++
            $_
          }
        }
      }
      Write-Verbose -Message ('Ran uninstaller for {0} packages for {1} matches' -f $uninstalled, $matched)
      if ( ! $matched ) 
      {
        Write-Warning -Message 'No unistallers were run as no packages specified in -remove matched'
      }
    }
    else 
    {
      $installed
    }
  }
  else 
  {
    Write-Warning -Message ('Found no installed products in the registry on {0} computers' -f $computers.Count)
  }
}

$cname = $env:COMPUTERNAME
$rptdir = "$env:HOMEDRIVE\Scripts\reports"

if (!(Test-Path -Path $rptdir))
{
  mkdir -Path $rptdir -Force 
}

Get-InstalledSoftware -exportcsv ('{0}\{1}-installed-software.csv' -f $rptdir, $cname)

function Send-FTP 
{ 
  $ftp = 'ftp://xxx.xx.xxx.xxx/uploads/BuildInventory/'
  $user = 'username'
  $pass = 'password'
      
  $webclient = New-Object -TypeName System.Net.WebClient  
  $webclient.Credentials = New-Object -TypeName System.Net.NetworkCredential -ArgumentList ($user, $pass)  
   
  foreach ($item in (Get-ChildItem -Path ('{0}' -f $rptdir))) 
  {
    $uri = New-Object -TypeName System.Uri -ArgumentList ($ftp + $item.Name) 
    $webclient.UploadFile($uri, $item.FullName) 
  }
}
# Send-FTP
