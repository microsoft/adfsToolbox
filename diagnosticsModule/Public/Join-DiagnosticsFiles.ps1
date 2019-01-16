<#
.SYNOPSIS
Merges one or more diagnostics output files into a single merged file named MergedDiagnosticsFile.json.  This merged file is used with the Diagnostics Analyzer Tool on the AD FS Help website (https://adfshelp.microsoft.com/DiagnosticsAnalyzer).

.DESCRIPTION
The Join-DiagnosticsFiles cmdlet is used to merge one or more diagnostics output files into a single file.  You can then upload this merged file to AD FS Help and view the farm health and configuration holistically.

.PARAMETER FilePath
The location of the output files that will be merged.  The default value is the current folder.

.EXAMPLE
Join-DiagnosticsFiles
Merge the diagnostics files located in the current folder

.EXAMPLE
Join-DiagnosticsFiles c:\output
Merge the diagnostics files located in the c:\output folder
#>
Function Join-DiagnosticsFiles
{
    [CmdletBinding()]
    Param
    (
        [string] $FilePath = "."
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
            
            $adfsServerHealthData = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth

            $mergedTestData["AllTests"] += $adfsServerHealthData.AllTests
            $mergedTestData["PassedTests"] += $adfsServerHealthData.PassedTests
            $mergedTestData["WarningTests"] += $adfsServerHealthData.WarningTests
            $mergedTestData["FailedTests"] += $adfsServerHealthData.FailedTests
            $mergedTestData["ErrorTests"] += $adfsServerHealthData.ErrorTests
            $mergedTestData["NotRunTests"] += $adfsServerHealthData.NotRunTests
            $mergedTestData["ReachableServers"] += $adfsServerHealthData.ReachableServers
            $mergedTestData["UnreachableServers"] += $adfsServerHealthData.UnreachableServers

            $configuration = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Adfs-Configuration

            # Only add the ADFS Configuration information if this is coming from the primary node
            if (($configuration | Select-Object -ExpandProperty Role).ToString() -eq "1") {
                $adfsConfiguration = $configuration
            }

            $version = @(Get-Content $fileName -raw) | ConvertFrom-Json | Select-Object Version | Select Version
        }
        
    $outputPath = $FilePath + $OutputFileName
    Write-Host "Creating merged diagnostics file: $outputPath"

    $resultantData = @{}
    $resultantData["Test-AdfsServerHealth"] = $mergedTestData
    $resultantData["Adfs-Configuration"] = $adfsConfiguration

    $mergedOutput = @{}
    $mergedOutput["ADFSToolbox"] = $resultantData
    $mergedOutput["Version"] = $version.Version

    $mergedOutput | ConvertTo-JSON -depth $maxJsonDepth -Compress | Out-File $OutputPath -Encoding default
}