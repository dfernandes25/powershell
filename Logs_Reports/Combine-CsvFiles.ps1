<#
    .INFO 
    Combine-CsvFiles.ps1
    Don Fernandes
    CBC Technologies
    Created:  20240706
    Modified: 

    .SYNOPSYS
    We collect many csv files from our endpoints for analysys
    Combine and manipulate multiple csv files from different locations
    Create a single xlsx workbook
    Also includes code for MacOS file system


    .LINKS
    

    .PARAMETERS
    Run as a task in endpoint management tool

#>


<# windows version #>
$sourceDir = "$env:HOMEDRIVE\Users\user\Downloads\lastReboot"
$outFile   = "$env:HOMEDRIVE\Users\user\Downloads\rebootCombined.csv"
if(Test-Path -Path $outFile)
{
  Remove-Item -Path $outFile -Force
}

$sourceDir |
Get-ChildItem -Filter *.csv | 
Select-Object -ExpandProperty Fullname | 
Import-Csv |
Export-Csv -Path ('{0}' -f $outFile) -NoTypeInformation -Append -Delimiter ','

<# mac version #>
# get windows update status
$nasDir = '/Volumes/homes/ftpuser/uploads/winUpdateLogs'
$output = '/Volumes/Macintosh HD/Users/cbc/Desktop/WUstatus.csv'
if(Test-Path -Path $output)
{
  Remove-Item -Path $outFile -Force
}

$nasDir |
Get-ChildItem -Filter *status* | 
Select-Object -ExpandProperty Fullname | 
Import-Csv |
Export-Csv -Path ('{0}' -f $output) -Force -NoTypeInformation -Append -Delimiter ','

# get installed windows updates
$nasDir = '/Volumes/homes/ftpuser/uploads/winUpdateLogs'
$output = '/Volumes/Macintosh HD/Users/cbc/Desktop/WUinstalled.csv'
if(Test-Path -Path $output)
{
  Remove-Item -Path $outFile -Force
}
        
$nasDir |
Get-ChildItem -Filter *install* | 
Select-Object -ExpandProperty Fullname | 
Import-Csv |
Export-Csv -Path ('{0}' -f $output) -Force -NoTypeInformation -Append -Delimiter ','


<# INVENTORY #>
# set directories #
$zipDir = '/Volumes/homes/ftpuser/uploads/inventory'
$outDir = '/Volumes/Macintosh HD/Users/cbc/Desktop/inventory'

# create destination directory based on zip file name and then expand the zip file #
Set-Location -Path $zipDir
$files = Get-ChildItem -Path .
foreach($fs in $files)
{
  $dirName = $fs.BaseName
  New-Item -ItemType Directory -Name $dirName -Path $outDir
  Expand-Archive -Path $fs -DestinationPath $outDir/$dirName
  # add column to csv files with their computer name #
  Get-ChildItem -Path $outDir/$dirName -Filter *.csv | ForEach-Object -Process {
    $CSV = Import-Csv -Path $_.FullName -Delimiter ','
    #$FileName = $_.Name
    $CSV |
    Select-Object -Property *, @{
      N = 'Computer'
      E = {
        $dirName
      }
    } |
    Export-Csv -Path $_.FullName -NoTypeInformation -Delimiter ';'
  }
}
 
# combine all csv files of the same type #
# Get all csv files in the directory and its subdirectories
$csvFiles = Get-ChildItem -Path $outDir -Recurse -Filter *.csv
# Loop through each csv file
foreach ($csvFile in $csvFiles) 
{
  # Get the name of the csv file without the extension
  $csvFileName = [System.IO.Path]::GetFileNameWithoutExtension($csvFile.FullName)
  # Get all csv files with the same name
  $sameNameCsvFiles = Get-ChildItem -Path $outDir -Recurse -Filter ('{0}.csv' -f $csvFileName)
  # Combine all csv files with the same name
  $combinedCsv = @()
  foreach ($sameNameCsvFile in $sameNameCsvFiles) 
  {
    $csvContent = Import-Csv -Path $sameNameCsvFile.FullName
    $combinedCsv += $csvContent
  }
  # Export the combined csv to a new file with the same name as the original csv file
  $combinedCsv | Export-Csv -Path ('{0}\combined-{1}.csv' -f $outDir, $csvFileName) -NoTypeInformation
}

# combine the csv files into an xlsx file #
function New-Workbook
{
  $files = Get-ChildItem -Path ('{0}\*.csv' -f $outDir)
  $outFile = ('{0}\_master-inventory.xlsx' -f $outDir)
  foreach($file in $files)
  {
    $sheetname = $file.basename
    Import-Csv -Path $file.fullname -Delimiter ';'  | Export-Excel -Path ('{0}' -f $outFile) -AutoSize -AutoFilter -FreezeTopRow -WorksheetName $sheetname
  }
}
New-Workbook
