<#
.SYNOPSIS
Merges one or more diagnostics output files into a single merged file named MergedDiagnosticsFile.json.  This merged file is used with the Diagnostics Analyzer Tool on the AD FS Help website (https://adfshelp.microsoft.com/DiagnosticsAnalyzer).

.DESCRIPTION
The Join-DiagnosticsFiles cmdlet is used to merge one or more diagnostics output files into a single file.  You can then upload this merged file to AD FS Help and view the farm health and configuration holistically.

.PARAMETER FilePath
The location of the output files that will be merged

.EXAMPLE
Join-DiagnosticsFiles c:\output
Merge the diagnostics files located in the c:\output folder

.EXAMPLE
Join-DiagnosticsFiles .
Merge the diagnostics files located in the current folder
#>
Function Join-DiagnosticsFiles
{
    [CmdletBinding()]
    Param
    (
        [string] $FilePath = $null
    )

    # Merged data file name
    $FileFilter = "ADFSDiagnosticsFile*.json"
    $OutputFileName = "\MergedDiagnosticsFile.json"

    # Dictionary of the objects used to create the merged test collection
    $mergedTestData = @{}
    $mergedTestData["AllTests"] = @()
    $mergedTestData["PassedTests"] = @()
    $mergedTestData["WarningTests"] = @()
    $mergedTestData["FailedTests"] = @()
    $mergedTestData["ErrorTests"] = @()
    $mergedTestData["NotRunTests"] = @()
    $mergedTestData["ReachableServers"] = @()
    $mergedTestData["UnreachableServers"] = @()

    # Objects to hold the version and ADFS Configuration information
    $version =""
    $adfsConfiguration = ""

    # Read each file in the folder
    Write-Host "Locating diagnostics files at: $FilePath" 

    $files = Get-ChildItem $FilePath -Filter $FileFilter

    # Make sure that at least one file exists
    if ($files.Length -eq 0) {
        Write-Error "There are no diagnostics files found at: '$FilePath'.  Make sure the path is correct and the files are in format '$FileFilter'."
        return
    }

    $files | 
        ForEach-Object {
            
            $fileName = $_ | Select-Object -ExpandProperty FullName

            Write-Host "  - Merging file: $fileName"  
            
            $allTests = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select AllTests
            $passedTests = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select PassedTests
            $warningTests = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select WarningTests
            $failedTests = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select FailedTests
            $errorTests = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select ErrorTests
            $notRunTests = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select NotRunTests
            $reachableServers = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select ReachableServers
            $unreachableServers = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select UnreachableServers

            $mergedTestData["AllTests"] += $allTests.AllTests
            $mergedTestData["PassedTests"] += $passedTests.PassedTests
            $mergedTestData["WarningTests"] += $warningTests.WarningTests
            $mergedTestData["FailedTests"] += $failedTests.FailedTests
            $mergedTestData["ErrorTests"] += $errorTests.ErrorTests
            $mergedTestData["NotRunTests"] += $notRunTests.NotRunTests
            $mergedTestData["ReachableServers"] += $reachableServers.ReachableServers
            $mergedTestData["UnreachableServers"] += $unreachableServers.UnreachableServers

            $configuration = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Adfs-Configuration

            # Only add the ADFS Configuration information if this is coming from the primary node
            if (($configuration | Select-Object -ExpandProperty Role).ToString() -eq "1") {
                $adfsConfiguration = $configuration
            }

            $version = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object Version | Select Version
        }
        
    $outputPath = $FilePath + $OutputFileName
    Write-Host
    Write-Host "Creating merged diagnostics file: $outputPath"

    $resultantData = @{}
    $resultantData["Test-AdfsServerHealth"] = @()
    $resultantData["Test-AdfsServerHealth"] = $mergedTestData
    $resultantData["Adfs-Configuration"] = $adfsConfiguration

    $mergedOutput = @{}
    $mergedOutput["ADFSToolbox"] = $resultantData
    $mergedOutput["Version"] = $version.Version

    $mergedOutput | ConvertTo-JSON -depth 100 -Compress | Out-File $OutputPath -Encoding default
}