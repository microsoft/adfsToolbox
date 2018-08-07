<#

.SYNOPSIS
    Contains data gathering, health checks, and additional tools for AD FS server deployments.

.DESCRIPTION

    ADFSToolbox is a Windows PowerShell module that contains various tools for managing ADFS


.DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    Copyright (c) Microsoft Corporation. All rights reserved.
#>

New-Variable -Name ModuleVersion -Value "1.0.2"

$url = "https://api.github.com/repos/Microsoft/adfsToolbox/releases/latest"
$oldProtocol = [Net.ServicePointManager]::SecurityProtocol
# We switch to using TLS 1.2 because GitHub closes the connection if it uses 1.0 or 1.1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try
{
    $response = Invoke-WebRequest -URI $url | ConvertFrom-Json
    if ($response.name -ne $ModuleVersion)
    {
       Write-Host "There is a newer version available. Run 'Update-Module -Name ADFSToolbox' to update to the latest version" -BackgroundColor DarkYellow -ForegroundColor Black
       Write-Host "Alternatively, you can download it manually from https://github.com/Microsoft/adfsToolbox/releases/latest" -BackgroundColor DarkYellow -ForegroundColor Black
    }
    else
    {
       Write-Host "You have the latest version installed!" -BackgroundColor DarkYellow -ForegroundColor Black
    }
}
catch
{
    # Github limits the number of unauthenticated API requests. To avoid this throwing an error we supress it here.
    Write-Host "Importing ADFSToolbox version $ModuleVersion" -BackgroundColor Yellow -ForegroundColor Black
    Write-Host "Unable to reach GitHub, please manually verify that you have the latest version by going to https://github.com/Microsoft/adfsToolbox/releases/latest" -BackgroundColor Yellow -ForegroundColor Black
}

[Net.ServicePointManager]::SecurityProtocol = $oldProtocol

Export-ModuleMember -Variable ModuleVersion -Function *