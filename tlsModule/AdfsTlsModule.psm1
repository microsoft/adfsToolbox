#Copyright (c) Microsoft Corporation. All rights reserved.
#Licensed under the MIT License.

<#
.SYNOPSIS
Configures ADFS servers for TLS 1.2 security.

.DESCRIPTION
The Get-ADFSTLSConfiguration cmdlet checks the local server's configuration for TLS and SSL and both writes the results to the console and places the results in a text file for review.

.PARAMETER
This cmdlet takes no parameters.

.EXAMPLE
Get-ADFSTLSConfiguration

.NOTES
Registry items detailed in https://support2.microsoft.com/kb/245030/en-us
Offical doc @ https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs
#>

$global:FormatEnumerationLimit = -1
Function Get-ADFSTLSConfiguration
{
    #function to review the current TLS config of the ADFS server and place results to an output file.
    #function should return a boolean response for whether only TLS 1.2 is allowed true, else false
    Write-host "This cmdlet provides a per server test result of what SSL and TLS settings are currently configured per the local servers registry. Each ADFS server in the farm will need the test ran individually." -ForegroundColor Yellow
    $OutputValues = new-object PSObject
    $OutputFile = ($pwd.path + '\') + (($env:COMPUTERNAME) + "_ADFS-TLSConfig.txt")
    $Time = Get-Date
    "ADFS SSL/TLS Configuration" | Out-file -FilePath $OutputFile -Encoding utf8
    (get-wmiobject -class win32_computersystem).Name | Out-file -FilePath $OutputFile -Encoding utf8 -Append
    $Time |  Out-file -FilePath $OutputFile -Encoding utf8 -Append
    "**********************************************************"  |  Out-file -FilePath $OutputFile -Encoding utf8 -Append
    #Read current registry config for SSL and TLS settings.
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client")
        {$PCT1ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server")
        {$PCT1ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client")
        {$SSL2ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server")
        {$SSL2ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client")
        {$SSL3ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
        {$SSL3ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
         {$TLS1ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")
        {$TLS1ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
        {$TLS11ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")
        {$TLS11ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")
        {$TLS12ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"}
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")
        {$TLS12ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"}
    if (($PCT1ClientReg.Enabled -eq 0) -or ($PCT1ClientReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "PCT1 Client Setting" -value "Disabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "PCT1 Client Setting" -value "Enabled (NOT default)"}
    if (($PCT1ServerReg.Enabled -eq 0) -or ($PCT1ServerReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "PCT1 Server Setting" -value "Disabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "PCT1 Server Setting" -value "Enabled (NOT default)"}
    if (($SSL2ClientReg.Enabled -eq 1) -or ($SSL2ClientReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "SSL2 Client Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "SSL2 Client Setting" -value "Disabled (NOT default)"}
    if (($SSL2ServerReg.Enabled -eq 1) -or ($SSL2ServerReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "SSL2 Server Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "SSL2 Server Setting" -value "Disabled (NOT default)"}
    if (($SSL3ClientReg.Enabled -eq 1) -or ($SSL3ClientReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "SSL3 Client Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "SSL3 Client Setting" -value "Disabled (NOT default) for POODLE"}
    if (($SSL3ServerReg.Enabled -eq 1) -or ($SSL3ServerReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "SSL3 Server Setting" -value "Enabled (default) - POODLE still possible"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "SSL3 Server Setting" -value "Disabled (NOT Default) for POODLE"}
    if (($TLS1ClientReg.Enabled -eq 1) -or ($TLS1ClientReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.0 Client Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.0 Client Setting" -value "Disabled (NOT default)"}
    if (($TLS1ServerReg.Enabled -eq 1) -or ($TLS1ServerReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.0 Server Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.0 Server Setting" -value "Disabled (NOT Default)"}
    if (($TLS11ClientReg.Enabled -eq 1) -or ($TLS11ClientReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.1 Client Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.1 Client Setting" -value "Disabled (NOT default)"}
    if (($TLS11ServerReg.Enabled -eq 1) -or ($TLS11ServerReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.1 Server Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.1 Server Setting" -value "Disabled (NOT Default)"}
    if (($TLS12ClientReg.Enabled -eq 1) -or ($TLS12ClientReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.2 Client Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.2 Client Setting" -value "Disabled (NOT default)"}
    if (($TLS12ServerReg.Enabled -eq 1) -or ($TLS12ServerReg.Enabled -eq $null))
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.2 Server Setting" -value "Enabled (default)"}
        else
        {add-member -inputobject $OutputValues -membertype noteproperty -name "TLS 1.2 Server Setting" -value "Disabled (NOT Default)"}

    if ($TLS12ServerReg.enabled -eq 1)
        {$TLS1dot2 = $true}
        else
        {$TLS1dot2 = $false}
    $OutputValues | Out-file -FilePath $OutputFile -Encoding utf8 -Append
    If ($TLS1dot2 -ne $true)
    {
    Write-host "The computer" ($env:COMPUTERNAME) "is not configured to use only Transport Layer Security 1.2. Run the Set-ADFSTLSConfiguration cmdlet on this server to use TLS 1.2 only." -BackgroundColor Yellow -ForegroundColor Red
    }
If ($TLS1dot2 -eq $true)
    {
    Write-host "This ADFS server is already enabled for TLS 1.2 only." -ForegroundColor Green
    }
}




<#
.SYNOPSIS
Configures ADFS servers for TLS 1.2 security.

.DESCRIPTION
The Set-ADFSTLSConfiguration cmdlet enables TLS 1.2 as client and server (if needed) and turns off TLS SSL, TLS 1.0 and TLS 1.1.

.PARAMETER
This cmdlet takes no parameters.

.EXAMPLE
Set-ADFSTLSConfiguration

.NOTES
Registry items detailed in http://support2.microsoft.com/kb/245030/en-us
Offical doc @ https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs
#>


Function Set-ADFSTLSConfiguration
{
    #enable strong crypto for .Net
    if (Test-path -path Registry::'HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727')
    {New-ItemProperty -Path Registry::'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null}
    if (Test-path -path Registry::"HKLM\SOFTWARE\Microsoft\.NetFramework\v4.0.30319")
    {New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null}
    Write-Host '.Net Schannel Use Strong Crypto is enabled.'  -ForegroundColor Green
     #enable TLS 1.2
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.2 is enabled.'  -ForegroundColor Green
    #SSL 2.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'SSL 2.0 has been disabled.' -ForegroundColor Green
    #disable SSL 3.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'SSL 3.0 has been disabled.' -ForegroundColor Green
    #disable TLS 1.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.0 has been disabled.' -ForegroundColor Green
    #disable TLS 1.1
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.1 has been disabled.' -ForegroundColor Green
    Write-host 'TLS 1.2 is now the sole SSL/TLS setting allowed on this server.'  -ForegroundColor Green
    Write-host 'WARNING: The server must be rebooted for the SSL and TLS settings to take effect.' -BackgroundColor Red
}

#Export the appropriate module functions

Export-ModuleMember -Function Get-ADFSTLSConfiguration
Export-ModuleMember -Function Set-ADFSTLSConfiguration