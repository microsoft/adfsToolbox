# Determine our script root
$parent = Split-Path $PSScriptRoot -Parent
$root = Split-Path $parent -Parent
# Load module via definition
Import-Module $root\ADFSDiagnosticsModule.psm1 -Force

InModuleScope ADFSDiagnosticsModule {
    # The output file
    $MergedFiledName = ".\Data\Diagnostics\MergedDiagnosticsFile.json"

    # Cleanup any existing data file
    if (Test-Path $MergedFiledName) {
        Write-Host "Cleaning up merged file from previous run"
        Remove-Item $MergedFiledName
    }

    Describe "TestJoinDiagnosticsFile" {
        It "should pass" {
            Join-DiagnosticsFiles .\Data\Diagnostics

            # Make sure the merged file exists
            $exists = Test-Path $MergedFiledName
            $exists | should beexactly True

            # Parse the data and make sure that it is indeed merged from both files

            # Version check
            $version = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object Version | Select Version
            $version.Version | should beexactly "1.0.9"

            # Test data check
            $allTests = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select AllTests
            $allTests.AllTests.Length | should beexactly 49

            $passedTests = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select PassedTests
            $passedTests.PassedTests.Length | should beexactly 31

            $warningTests = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select WarningTests
            $warningTests.WarningTests.Length | should beexactly 1

            $failedTests = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select FailedTests
            $failedTests.FailedTests.Length | should beexactly 5

            $errorTests = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select ErrorTests
            $errorTests.ErrorTests.Length | should beexactly 0

            $notRunTests = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select NotRunTests
            $notRunTests.NotRunTests.Length | should beexactly 12

            $reachableServers = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select ReachableServers
            $reachableServers.ReachableServers.Length | should beexactly 2

            $unreachableServers = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Test-AdfsServerHealth | Select UnreachableServers
            $unreachableServers.UnreachableServers.Length | should beexactly 1

            # ADFS Configuration check
            # We don't need to check everything here.  It's either all there or none of it is there.
            $configuration = @(Get-Content $MergedFiledName -raw) | ConvertFrom-Json | Select-Object -ExpandProperty ADFSToolbox | Select-Object -ExpandProperty Adfs-Configuration
            $configuration.AdfsGlobalAuthenticationPolicy.PrimaryIntranetAuthenticationProvider.Length | should beexactly 3
        }

        It "should fail" {
            # Arrange
            Mock -CommandName Write-Error -MockWith {}

            Join-DiagnosticsFiles .

            # Assert
            Assert-MockCalled Write-Error
        }

        # Cleanup
        if (Test-Path $MergedFiledName) {
            Write-Host "Cleaning up merged file from test run"
            Remove-Item $MergedFiledName
        }
    }
}
