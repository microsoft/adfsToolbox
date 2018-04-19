# Determine our script root
$root = Split-Path $PSScriptRoot -Parent

# Load module via definition
Import-Module $root\ADFSDiagnostics.psd1 -Force

InModuleScope ADFSDiagnostics {
    Describe 'Load ADFSDiagnostics' {
        AfterAll {
            Remove-Module ADFSDiagnostics
        }

        It 'should load ADFSDiagnostics module' {
            $ADFSDiagnosticsModule = Get-Module ADFSDiagnostics -all

            $ADFSDiagnosticsModule | should be $true
        }
    }
}
