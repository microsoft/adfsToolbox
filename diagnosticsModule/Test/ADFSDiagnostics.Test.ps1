# Determine our script root
$root = Split-Path $PSScriptRoot -Parent

# Load module via definition
Import-Module $root\ADFSDiagnosticsModule.psm1 -Force

InModuleScope ADFSDiagnosticsModule {
    Describe 'Load ADFSDiagnostics' {
        It 'should load ADFSDiagnostics module' {
            $ADFSDiagnosticsModule = Get-Module ADFSDiagnosticsModule -all

            $ADFSDiagnosticsModule | should be $true
        }
    }
}
