<#
.SYNOPSIS
Retrieves overall details of the AD FS farm.

.DESCRIPTION
The Get-ADFSServerConfiguration takes a snapshot of the AD FS farm configuration and relevant dependencies.

.PARAMETER IncludeTrusts
When set, the output of the commandlet will include infromation about the Relying Party trusts and Claims Provider Trusts.

.EXAMPLE
Get-AdfsServerConfiguration -IncludeTrusts | ConvertTo-Json | Out-File ".\ADFSFarmDetails.txt"
Gets the snapshot of the configuration of the AD FS farm, and save it in JSON format

.NOTES
When run against a secondary computer on a Windows Internal Database AD FS farm, the result of this commandlet is expected to be significantly reduced.
If an exception occurs when attempting to get a configuration value, the respective property of the returned object will contain the exception message.
#>
Function Get-AdfsServerConfiguration
{
    [CmdletBinding()]
    Param(
        [switch]$IncludeTrusts
    )

    $role = Get-ADFSRole
    $configurationOutput = New-Object PSObject;
    
    # Duplicate from Get-AdfsSystemInformation
    # No Try-catch needed for this property
    $configurationOutput | Add-Member NoteProperty -name "Role" -value $role -Force;

    # Duplicate from Get-AdfsSystemInformation
    $hostsPropertyName = "Hosts"
    try
    {
        $hostsEntry = @{};
        $hostsFile = Join-Path $env:SystemRoot "system32\drivers\etc\hosts"
        $regex = [regex] "\s+";
        foreach ($line in Get-Content $hostsFile)
        {
            $ip = new-object System.Net.IPAddress -ArgumentList 0
            $trimmed = $line.Trim();

            if (![string]::IsNullOrEmpty($trimmed) -and
                !($trimmed.StartsWith("#")) -and 
                ($items = $regex.Split($trimmed)).Count -ge 2 -and
                ![string]::IsNullOrEmpty($items[1]) -and
                !$hostsEntry.ContainsKey($items[1]) -and
                [system.net.ipaddress]::TryParse($items[0], [ref] $ip))
            {
                $hostsEntry.Add($items[1], $items[0]);
            }
        }
        $configurationOutput | Add-Member NoteProperty -name $hostsPropertyName -value $hostsEntry -Force;
    } 
    catch 
    { 
        $configurationOutput | Add-Member NoteProperty -name $hostsPropertyName -value "SCRIPTERROR: $_.Exception.Message" -Force;
    }

    # Duplicate from Get-AdfsSystemInformation
    $sslBindingsPropertyName = "SslBindings"
    try
    { 
        $bindings = @(@{});
        $bindingCount = -1;
        $bindingsStr = netsh http show sslcert 
        
        #remove all title/extra lines 
        $bindingsStr = $bindingsStr | Foreach{$tok = $_.Split(":"); IF ($tok.Length -gt 1 -and $tok[1].TrimEnd() -ne "" -and $tok[0].StartsWith(" ")){$_}}
        
        foreach ($bindingLine in $bindingsStr)
        {
            if ($bindingLine.Trim().ToLower().StartsWith("ip:port"))
            {
                $bindings += @{};
                $bindingCount = $bindingCount + 1;
                $bindings[$bindingCount].Add("IPPort", $bindingLine.Trim().Split(':')[2].Trim() + ":" + $bindingLine.Trim().Split(':')[3].Trim());
                Continue;
            }
            if ($bindingLine.Trim().ToLower().StartsWith("hostname:port"))
            {
                $bindings += @{};
                $bindingCount = $bindingCount + 1;
                $bindings[$bindingCount].Add("HostnamePort", $bindingLine.Trim().Split(':')[2].Trim() + ":" + $bindingLine.Trim().Split(':')[3].Trim());
                Continue;
            }
            if ($bindingCount -ge 0)
            {
                $bindings[$bindingCount].Add($bindingLine.Trim().Split(':')[0].Trim(), $bindingLine.Trim().Split(':')[1].Trim());
            }
        }
        $configurationOutput | Add-Member NoteProperty -name $sslBindingsPropertyName -value $bindings -Force;
    } 
    catch 
    {
        $configurationOutput | Add-Member NoteProperty -name $sslBindingsPropertyName -value "SCRIPTERROR: $_.Exception.Message" -Force;
    }

    if ($role -ne "STS")
    {
        return $configurationOutput
    }
    
    # Get OS Version to determine ADFS Version
    $OSVersion = [System.Environment]::OSVersion.Version
    $ADFSVersion = Get-AdfsVersion($OSVersion);

    Import-ADFSAdminModule

    $adfsSyncProperties = $null

    try
    {
        $adfsSyncProperties = Get-AdfsSyncProperties -ErrorVariable adfsSyncProperties;
        $configurationOutput | Add-Member NoteProperty -name "ADFSSyncProperties" -value $adfsSyncProperties -Force;
    }
    catch [Exception] {
        $configurationOutput | Add-Member NoteProperty -name "ADFSSyncProperties" -value "SCRIPTERROR: $_.Exception.Message" -Force;
    }

    if ( $null -eq $adfsSyncProperties ) 
    {
       return $configurationOutput
    }

    if ($adfsSyncProperties.Role -eq "PrimaryComputer")
    {
        # Common to All Versions of ADFS
        if (IsExecutedByConnectHealth)
        {
            $adfsRelyingPartyTrustCount = -1;
        }

        if ($IncludeTrusts)
        {
            try
            {
                $adfsClaimsProviderTrust = Get-AdfsClaimsProviderTrust -ErrorVariable adfsClaimsProviderTrust;
                $configurationOutput | Add-Member NoteProperty -name "ADFSClaimsProviderTrust" -value $AdfsClaimsProviderTrust -Force;
            }
            catch [Exception] {
                $configurationOutput | Add-Member NoteProperty -name "ADFSClaimsProviderTrust" -value "SCRIPTERROR: $_.Exception.Message" -Force;
            }
            try
            {
                $adfsRelyingPartyTrust = Get-AdfsRelyingPartyTrust -ErrorVariable adfsRelyingPartyTrust;
				
                # Only collect Trust Count when $IncludeTrusts is included
                $adfsRelyingPartyTrustCount = $adfsRelyingPartyTrust.Count;
                $configurationOutput | Add-Member NoteProperty -name "ADFSRelyingPartyTrust" -value $adfsRelyingPartyTrust -Force;
            }
            catch [Exception] {
                $configurationOutput | Add-Member NoteProperty -name "ADFSRelyingPartyTrust" -value "SCRIPTERROR: $_.Exception.Message" -Force;
            }
        }       
        try
        {
            $adfsAttributeStore = Get-AdfsAttributeStore -ErrorVariable adfsAttributeStore;
            $configurationOutput | Add-Member NoteProperty -name "ADFSAttributeStore" -value $adfsAttributeStore -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "ADFSAttributeStore" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }

        try
        {
            $adfsCertificateCollection = Get-AdfsCertificateList -RemovePrivateKey
            $configurationOutput | Add-Member NoteProperty -name "ADFSCertificate" -value $adfsCertificateCollection -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "ADFSCertificate" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }

        try
        {
            $adfsClaimDescription = Get-AdfsClaimDescription -ErrorVariable adfsClaimDescription;
            $configurationOutput | Add-Member NoteProperty -name "ADFSClaimDescription" -value $adfsClaimDescription -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "ADFSClaimDescription" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }
        try
        {
            $adfsEndpoint = Get-AdfsEndpoint -ErrorVariable adfsEndpoint;
            $configurationOutput | Add-Member NoteProperty -name "ADFSEndpoint" -value $adfsEndpoint -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "ADFSEndpoint" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }
        try
        {
            $adfsProperties = Retrieve-AdfsProperties
            $configurationOutput | Add-Member NoteProperty -name "ADFSProperties" -value $adfsProperties -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "ADFSProperties" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }
        
        try
        {            
            # To prevent heavy usage of SQL for customers with large RP sets for every run (1hr interval) check for CH            
            if (-not (IsExecutedByConnectHealth)) 
            { 
                $adfsRelyingPartyTrustCount = (Get-AdfsRelyingPartyTrust).Count;
            }
            
            $configurationOutput | Add-Member NoteProperty -name "ADFSRelyingPartyTrustCount" -value $adfsRelyingPartyTrustCount -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "ADFSRelyingPartyTrustCount" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }
        try
        {
            $adfsClaimsProviderTrustCount = 0
            $adfsClaimsProviderTrustCount = (Get-AdfsClaimsProviderTrust).Count;
            
            $configurationOutput | Add-Member NoteProperty -name "ADFSClaimsProviderTrustCount" -value $adfsClaimsProviderTrustCount -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "ADFSClaimsProviderTrustCount" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }
        
        try
        {
            $adfSConfigurationDatabaseConnectionString = (Get-WmiObject -namespace root/ADFS -class SecurityTokenService).Properties["ConfigurationDatabaseConnectionString"].Value
            $configurationOutput | Add-Member NoteProperty -name "ADFSConfigurationDatabaseConnectionString" -value $adfSConfigurationDatabaseConnectionString -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "ADFSConfigurationDatabaseConnectionStringy" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }
        
        $adfsServiceAccount = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).StartName;
        $configurationOutput | Add-Member NoteProperty -name "AdfssrvServiceAccount" -value $adfsServiceAccount -Force;

        $ADFSVersion = Get-AdfsVersion($OSVersion);
        $configurationOutput | Add-Member NoteProperty -name "AdfsVersion" -value $ADFSVersion -Force;
        
        try
        {
            $aadRpId = "urn:federation:MicrosoftOnline";
            $aadRp =  Get-ADFSRelyingPartyTrust -Identifier $aadRpId;
            $aadRpStatus = ""        

            if ($aadRp -eq $null)
            {
                $aadRpStatus = "Not Configured";
            }
            else
            {
                if (-not $aadRp.Enabled)
                {
                    $aadRpStatus = "Configured but disabled";
                }
                else
                {
                    $aadRpStatus = "Configured";
                }
            }
            $configurationOutput | Add-Member NoteProperty -name "AadTrustStatus" -value $aadRpStatus -Force;
        }
        catch [Exception] {
            $configurationOutput | Add-Member NoteProperty -name "AadTrustStatus" -value "SCRIPTERROR: $_.Exception.Message" -Force;
        }
    
        Switch ($ADFSVersion)
        {
            {($_ -eq $adfs3) -or ($_ -eq $adfs4)}
            {
                try
                {
                    $adfsAdditionalAuthenticationRule = Get-AdfsAdditionalAuthenticationRule -ErrorVariable adfsAdditionalAuthenticationRule;
                    $configurationOutput | Add-Member NoteProperty -name "ADFSAdditionalAuthenticationRule" -value $adfsAdditionalAuthenticationRule -Force;
                }
                catch [Exception] {
                    $configurationOutput | Add-Member NoteProperty -name "ADFSAdditionalAuthenticationRule" -value "SCRIPTERROR: $_.Exception.Message" -Force;
                }
                try
                {
                    $adfsClient = Get-AdfsClient -ErrorVariable adfsClient;
                    $configurationOutput | Add-Member NoteProperty -name "ADFSClient" -value $adfsClient -Force;
                }
                catch [Exception] {
                    $configurationOutput | Add-Member NoteProperty -name "ADFSClient" -value "SCRIPTERROR: $_.Exception.Message" -Force;
                }


                try
                {
                    $adfsGlobalAuthenticationPolicy = Get-AdfsGlobalAuthenticationPolicy -ErrorVariable adfsGlobalAuthenticationPolicy;
                    $configurationOutput | Add-Member NoteProperty -name "ADFSGlobalAuthenticationPolicy" -value $adfsGlobalAuthenticationPolicy -Force;
                }
                catch [Exception] {
                    $configurationOutput | Add-Member NoteProperty -name "ADFSGlobalAuthenticationPolicy" -value "SCRIPTERROR: $_.Exception.Message" -Force;
                }

                try
                {
                    $adfsDeviceRegistration = Get-AdfsDeviceRegistration -ErrorVariable adfsDeviceRegistration;
                    $configurationOutput | Add-Member NoteProperty -name "ADFSDeviceRegistration" -value $adfsDeviceRegistration -Force;
                }
                catch [Exception] {
                    $configurationOutput | Add-Member NoteProperty -name "ADFSDeviceRegistration" -value "SCRIPTERROR: $_.Exception.Message" -Force;
                }
            }
            $adfs2x
            {
                try
                {
                    Import-Module WebAdministration
                    $adfsGlobalAuthenticationPolicy = @{};
                    $iisSites = Get-ChildItem IIS:\Sites
                    $webConfigPath = $null
                    foreach($site in $iisSites)
                    {
                        $name = $site.Name
                        $adfsDefaultSite = dir IIS:\Sites\$name | where {$_.Name -eq 'adfs\ls'}
                        if ($adfsDefaultSite -ne $null)
                        {
                            $webConfigPath = $adfsDefaultSite.PhysicalPath
                            break
                        }
                    }
                    if ($webConfigPath -ne $null)
                    {
                        $adfsLsWebConfig = [xml](get-content -Path "$webConfigPath\web.config")
                        if ($adfsLsWebConfig -ne $null)
                        {
                            $authMethods = $adfsLsWebConfig.SelectNodes("//localAuthenticationTypes/add")
                            if ($authMethods -ne $null)
                            {
                                Foreach($authenticationMethod in $authMethods)
                                {
                                    if (!($adfsGlobalAuthenticationPolicy.ContainsKey($authenticationMethod.name)))
                                    {
                                        $adfsGlobalAuthenticationPolicy.Add($authenticationMethod.name, $authenticationMethod.page);
                                    }
                                }
                            }
                        }
                    }
                    $configurationOutput | Add-Member NoteProperty -name "ADFSGlobalAuthenticationPolicy" -value $adfsGlobalAuthenticationPolicy -Force;
                }
                catch [Exception] {
                    $configurationOutput | Add-Member NoteProperty -name "ADFSGlobalAuthenticationPolicy" -value "SCRIPTERROR: $_.Exception.Message" -Force;
                }
            }
        }
    }

    $configurationOutput;
}
