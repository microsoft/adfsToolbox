#Requires -Version 4
#Requires -RunAsAdministrator

Param(
    [switch]
    $CodeCoverage = $false
)

Write-Host "Running tests for ADFS Diagnostics Module"

if (!(Get-Command Install-Module))
{
    throw 'PackageManagement is not installed. You need V5 or https://www.microsoft.com/en-us/download/details.aspx?id=51451'
}

# Verify that our testing utilities are installed.
if (!(Get-Module -Name Pester -ListAvailable))
{
    Install-Module -Name Pester
}

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

    Invoke-Pester -Path @($tests.FullName) -CodeCoverage @($codeCoveragePaths)
}
else
{
    Invoke-Pester -Path @($tests.FullName)
}
