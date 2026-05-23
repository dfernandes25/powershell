############################################################
# CONFIGURATION
############################################################

$SearchName     = "Archive-DeletedItems-Only"
$MaxParallel    = 5            # Number of parallel purge threads (5 = safe, 10 = aggressive)
$TotalIterations = 2000        # Total purge passes
$DelayBetweenJobs = 1          # Seconds between job launches

############################################################
# FUNCTION: Connect to Compliance PowerShell
############################################################
function Connect-ComplianceSession {
    Write-Host "Connecting to Purview Compliance..." -ForegroundColor Cyan
    
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    
    Connect-IPPSSession -EnableSearchOnlySession
    
    Write-Host "Connected successfully." -ForegroundColor Green
}

############################################################
# FUNCTION: Validate Search Exists and Completed
############################################################
function Validate-Search {
    param($Name)

    $search = Get-ComplianceSearch $Name -ErrorAction Stop

    if ($search.Status -ne "Completed") {
        Write-Host "Search is not completed. Starting it now..." -ForegroundColor Yellow
        Start-ComplianceSearch $Name

        do {
            Start-Sleep -Seconds 5
            $search = Get-ComplianceSearch $Name
            Write-Host "Waiting for search completion... Status: $($search.Status)"
        } while ($search.Status -ne "Completed")
    }

    if ($search.Items -eq 0) {
        throw "Search returned 0 items — aborting purge."
    }

    Write-Host "Search validated: $($search.Items) items found." -ForegroundColor Green
}

############################################################
# FUNCTION: Execute Single Purge Action
############################################################
function Invoke-Purge {
    param($SearchName, $Iteration)

    try {
        New-ComplianceSearchAction `
            -SearchName $SearchName `
            -Purge `
            -PurgeType HardDelete `
            -Confirm:$false `
            -ErrorAction Stop

        Write-Output "PASS $Iteration SUCCESS"
    }
    catch {
        Write-Output "PASS $Iteration FAILED: $($_.Exception.Message)"
        Start-Sleep -Seconds 5
    }
}

############################################################
# FUNCTION: Parallel Purge Engine
############################################################
function Start-ParallelPurge {
    param(
        $SearchName,
        $TotalIterations,
        $MaxParallel
    )

    Write-Host "Starting parallel purge..." -ForegroundColor Cyan

    $jobs = @()
    $counter = 1

    while ($counter -le $TotalIterations) {

        # Clean up finished jobs
        $jobs = $jobs | Where-Object { $_.State -eq 'Running' }

        # Launch new jobs if under limit
        while ($jobs.Count -lt $MaxParallel -and $counter -le $TotalIterations) {

            $job = Start-Job -ScriptBlock {
                param($sName, $i)

                Import-Module ExchangeOnlineManagement
                Connect-IPPSSession -EnableSearchOnlySession

                try {
                    New-ComplianceSearchAction `
                        -SearchName $sName `
                        -Purge `
                        -PurgeType HardDelete `
                        -Confirm:$false
                    
                    "PASS $i SUCCESS"
                }
                catch {
                    "PASS $i FAILED: $($_.Exception.Message)"
                }

            } -ArgumentList $SearchName, $counter

            $jobs += $job
            Write-Host "Started purge job $counter"

            $counter++

            Start-Sleep -Seconds $DelayBetweenJobs
        }

        Start-Sleep -Seconds 2
    }

    Write-Host "Waiting for all jobs to complete..." -ForegroundColor Yellow

    $jobs | Wait-Job | Receive-Job

    Write-Host "Parallel purge complete." -ForegroundColor Green
}

############################################################
# FUNCTION: Cleanup Sessions
############################################################
function Disconnect-All {
    Write-Host "Disconnecting sessions..." -ForegroundColor Cyan

    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Disconnect-MgGraph -ErrorAction SilentlyContinue

    Write-Host "Disconnected." -ForegroundColor Green
}

############################################################
# MAIN EXECUTION
############################################################

try {
    Connect-ComplianceSession

    Validate-Search -Name $SearchName

    Start-ParallelPurge `
        -SearchName $SearchName `
        -TotalIterations $TotalIterations `
        -MaxParallel $MaxParallel

}
catch {
    Write-Error $_
}
finally {
    Disconnect-All
}