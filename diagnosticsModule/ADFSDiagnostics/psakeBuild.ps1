#Requires -Version 4
#Requires -RunAsAdministrator

[cmdletbinding()]
param(
    [switch]
    $CodeCoverage = $false
)

properties {
    $root = $PSScriptRoot
}

# Default task includes Analyzing and Testing of module
task default -depends Analyze, Test

# Analyze by running Invoke-ScriptAnalyzer. Check script against best known practices
task Analyze {
    $saResults = Invoke-ScriptAnalyzer -Path "$root\Public" -Severity @('Error', 'Warning') -Recurse -ExcludeRule "PSAvoidUsingWriteHost", "PSUseDeclaredVarsMoreThanAssignments" -Verbose:$false
    $saResults += Invoke-ScriptAnalyzer -Path "$root\Private" -Severity @('Error', 'Warning') -Recurse -Verbose:$false
    if ($saResults)
    {
        $saResults | Format-Table
        Write-Error -Message 'One or more Script Analyzer errors/warnings where found. Build cannot continue!'
    }
}

# Run our test to make sure everything is in line
task Test {
    $tests = @(Get-ChildItem -Path $PSScriptRoot\Test\**\*.Test.ps1 -Recurse)

    if ($CodeCoverage)
    {
        $codeCoveragePaths = @()
        foreach ($test in $tests)
        {
            $name = $test.Name -replace ".Test.ps1$", ".ps1"
            $directory = $test.Directory.Name
            $codeCoveragePath = $PSScriptRoot, $directory, $name -join "\"
            if (Test-Path $codeCoveragePath)
            {
                $codeCoveragePaths += $codeCoveragePath
            }
        }

        $testResults = Invoke-Pester -Path @($tests.FullName) -CodeCoverage @($codeCoveragePaths) -PassThru
    }
    else
    {
        $testResults = Invoke-Pester -Path @($tests.FullName) -PassThru
    }

    if ($testResults.FailedCount -gt 0)
    {
        $testResults.TestResult | Where-Object { $_.Result -ne "Passed" } | Format-List
        Write-Error -Message 'One or more Pester tests failed. Build cannot continue!'
    }
}