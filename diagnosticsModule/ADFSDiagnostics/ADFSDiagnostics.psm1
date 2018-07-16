#Requires -Version 4
#Requires -RunAsAdministrator

<#

.SYNOPSIS
    Contains data gathering, health checks, and additional utilities for AD FS server deployments.

.DESCRIPTION

    Version: 3.0.1

    ADFSDiagnostics.psm1 is a Windows PowerShell module for diagnosing issues with ADFS


.DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    Copyright (c) Microsoft Corporation. All rights reserved.
#>

$Script:ModuleVersion = "3.0.1"

$url = "https://api.github.com/repos/Microsoft/adfsManagementTools/releases/latest"
$oldProtocol = [Net.ServicePointManager]::SecurityProtocol
# We switch to using TLS 1.2 because GitHub closes the connection if it uses 1.0 or 1.1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try
{
    $response = Invoke-WebRequest -URI $url | ConvertFrom-Json
    if ($response.name -ne $ModuleVersion)
    {
       Write-Host "There is a newer version available. Run 'Update-Module -Name ADFSDiagnostics' to update to the newest version"
       Write-Host "Alternatively, you can download it manually from https://github.com/Microsoft/adfsManagementTools/releases/latest"
    }
    else
    {
       Write-Host "You have the latest version installed!"
    }
}
catch
{
    # Github limits the number of unauthenticated API requests. To avoid this throwing an error we supress it here.
}

[Net.ServicePointManager]::SecurityProtocol = $oldProtocol


#Get public and private function definition files.
Write-Debug "Importing public and private functions"

$Public = @(Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)
#Dot source the files
foreach ($import in @($Public + $Private))
{
    try
    {
        . $import.fullname
    }
    catch
    {
        Write-Error -Message "Failed to import script $($import.fullname): $_"
    }
}

Export-ModuleMember -Function $Public.Basename