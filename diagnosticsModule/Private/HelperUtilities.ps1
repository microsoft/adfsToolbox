Function Out-Verbose
{
    Param($out)
    Write-Verbose "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name): $out"
}

Function Out-Warning
{
    Param($out)
    Write-Warning "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name): $out"
}

Function IsAdfsSyncPrimaryRole([switch] $force)
{
    if ((IsAdfsServiceRunning) -and (-not $script:adfsSyncRole -or $force))
    {
        try
        {
            $stsrole = Get-ADFSSyncProperties | Select-Object -ExpandProperty Role
            $script:isAdfsSyncPrimaryRole = $stsrole -eq "PrimaryComputer"
        }
        catch
        {
            #Write-Verbose "Could not tell if running on a primary WID sync node. Returning false..."
            return $false
        }
    }
    return $script:isAdfsSyncPrimaryRole
}

Function Retrieve-AdfsProperties([switch] $force)
{
    if ((IsAdfsServiceRunning) -and (-not $script:adfsProperties -or $force))
    {
        $isPrimary = IsAdfsSyncPrimaryRole -force $force
        if ($isPrimary)
        {
            $script:adfsProperties = Get-AdfsProperties
        }
    }
    return $script:adfsProperties
}

Function Test-RunningOnAdfsSecondaryServer
{
    return -not (IsAdfsSyncPrimaryRole)
}

Function Test-RunningRemotely
{
    return (Get-Host).Name -eq "ServerRemoteHost";
}

Function Get-AdfsVersion
{
    $OSVersion = [System.Environment]::OSVersion.Version

    If ($OSVersion.Major -eq 6)
    {
        # Windows 2012 R2
        If ($OSVersion.Minor -ge 3)
        {
            return $adfs3;
        }
        Else
        {
            #Windows 2012, 2008 R2, 2008
            If ($OSVersion.Minor -lt 3)
            {
                return $adfs2x;
            }
        }
    }

    If ($OSVersion.Major -eq 10)
    {
        # Windows Server 10
        If ($OSVersion.Minor -eq 0)
        {
            return $adfs3;
        }
    }
    return $null
}
Function EnvOSVersionWrapper
{
    return [System.Environment]::OSVersion.Version;
}

Function Get-OsVersion
{
    $OSVersion = EnvOSVersionWrapper

    if (($OSVersion.Major -eq 10) -and ($OSVersion.Minor -eq 0))
    {
        # Windows Server 2016
        return [OSVersion]::WS2016;
    }
    elseif ($OSVersion.Major -eq 6)
    {
        # Windows 2012 R2
        if ($OSVersion.Minor -ge 3)
        {
            return [OSVersion]::WS2012R2;
        }
        elseif ($OSVersion.Minor -lt 3)
        {
            #Windows 2012
            return [OSVersion]::WS2012;
        }
    }
    return [OSVersion]::Unknown;
}

Function Import-ADFSAdminModule()
{
    #Used to avoid extra calls to Add-PsSnapin so DFTs function appropriately on WS 2008 R2
    if ($testMode)
    {
        return
    }
    $OSVersion = [System.Environment]::OSVersion.Version

    If ($OSVersion.Major -eq 6)
    {
        # Windows 2012 R2 and 2012
        If ($OSVersion.Minor -ge 2)
        {
            Import-Module ADFS
        }
        Else
        {
            #Windows 2008 R2, 2008
            If ($OSVersion.Minor -lt 2)
            {
                if ( (Get-PSSnapin -Name Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue) -eq $null )
                {
                    Add-PsSnapin Microsoft.Adfs.Powershell
                }
            }
        }
    }
}

Function Get-AdfsRole()
{
    #ADFS 2012 R2 STS: hklm:\software\microsoft\adfs FSConfigurationStatus = 2
    $adfs3StsRegValue = Get-ItemProperty "hklm:\software\microsoft\adfs" -Name FSConfigurationStatus -ErrorAction SilentlyContinue
    if ($adfs3StsRegValue.FSConfigurationStatus -eq 2)
    {
        return $adfsRoleSTS
    }

    #ADFS 2012 R2 Proxy: hklm:\software\microsoft\adfs ProxyConfigurationStatus = 2
    $adfs3ProxyRegValue = Get-ItemProperty "hklm:\software\microsoft\adfs" -Name ProxyConfigurationStatus -ErrorAction SilentlyContinue
    if ($adfs3ProxyRegValue.ProxyConfigurationStatus -eq 2)
    {
        return $adfsRoleProxy
    }

    #ADFS 2.x STS: HKLM:\Software\Microsoft\ADFS2.0\Components SecurityTokenServer = 1
    $adfs2STSRegValue = Get-ItemProperty "hklm:\software\microsoft\ADFS2.0\Components" -Name SecurityTokenServer -ErrorAction SilentlyContinue
    if ($adfs2STSRegValue.SecurityTokenServer -eq 1)
    {
        return $adfsRoleSTS
    }

    #ADFS 2.x Proxy: HKLM:\Software\Microsoft\ADFS2.0\Components ProxyServer = 1
    $adfs2STSRegValue = Get-ItemProperty "hklm:\software\microsoft\ADFS2.0\Components" -Name ProxyServer -ErrorAction SilentlyContinue
    if ($adfs2STSRegValue.ProxyServer -eq 1)
    {
        return $adfsRoleProxy
    }

    return "none"
}

Function Get-ServiceState($serviceName)
{
    return (Get-Service $serviceName -ErrorAction SilentlyContinue).Status
}

Function IsAdfsServiceRunning()
{
    $adfsSrv = Get-ServiceState($adfsServiceName)
    return $adfsSrv -ne $null -and ($adfsSrv -eq "Running")
}

Function IsAdfsProxyServiceRunning()
{
    $adfsSrv = Get-ServiceState($adfsProxyServiceName)
    return $adfsSrv -ne $null -and ($adfsSrv -eq "Running")
}

Function GetHttpsPort
{
    $stsrole = Get-ADFSSyncProperties | Select-Object -ExpandProperty Role

    if (IsAdfsSyncPrimaryRole)
    {
        return (Retrieve-AdfsProperties).HttpsPort
    }
    else
    {
        #TODO: How to find the Https Port in secondaries generically?
        return 443;
    }
}

Function GetSslBinding()
{
    #Get ssl bindings from registry. Due to limitations on the IIS powershell, we cannot use the iis:\sslbindings
    #provider
    $httpsPort = GetHttpsPort
    $adfsVersion = Get-AdfsVersion

    if ( $adfsVersion -eq $adfs2x)
    {
        $portRegExp = "^.*" + ":" + $httpsPort.ToString() + "$";

        $bindingRegKeys = dir hklm:\system\currentcontrolset\services\http\parameters\SslBindingInfo -ErrorAction SilentlyContinue | where {$_.Name -match $portRegExp}

        if ($bindingRegKeys -eq $null)
        {
            #no bindings found in the given port. Returning null
            return $null
        }
        else
        {
            $bindingFound = ($bindingRegKeys)[0];
            $bindingProps = $bindingFound  | Get-ItemProperty

            $name = $bindingFound.PSChildName
            $bindingHost = $name.Split(':')[0]

            #if the binding is the fallback 0.0.0.0 address, then point to localhost
            if ($bindingHost -eq "0.0.0.0")
            {
                $bindingHost = "localhost"
            }

            $hostNamePort = $bindingHost.ToString() + ":" + $httpsPort.ToString()

            $thumbprintBytes = $bindingProps.SslCertHash;
            $thumbprint = ""
            $thumbprintBytes | % { $thumbprint = $thumbprint + $_.ToString("X2"); }

            $sslCert = dir Cert:\LocalMachine\My\$thumbprint -ErrorAction SilentlyContinue

            $result = New-Object PSObject
            $result | Add-Member NoteProperty -name "Name" -value $name
            $result | Add-Member NoteProperty -name "Host" -value $bindingHost
            $result | Add-Member NoteProperty -name "Port" -value $httpsPort
            $result | Add-Member NoteProperty -name "HostNamePort" -value $hostNamePort
            $result | Add-Member NoteProperty -name "Thumbprint" -value $thumbprint
            $result | Add-Member NoteProperty -name "Certificate" -value $sslCert

            return $result
        }

    }
    else
    {
        if ($adfsVersion -eq $adfs3 -or $adfsVersion -eq $adfs4)
        {
            #select the first binding for the https port found in configuration
            $sslBinding = Get-AdfsSslCertificate | Where-Object {$_.PortNumber -eq $httpsPort} | Select-Object -First 1
            $thumbprint = $sslBinding.CertificateHash
            $sslCert = dir Cert:\LocalMachine\My\$thumbprint -ErrorAction SilentlyContinue

            $result = New-Object PSObject
            $result | Add-Member NoteProperty -name "Name" -value $sslBinding.HostName
            $result | Add-Member NoteProperty -name "Host" -value "localhost"
            $result | Add-Member NoteProperty -name "Port" -value $httpsPort
            $result | Add-Member NoteProperty -name "HostNamePort" -value ("localhost:" + $httpsPort.ToString());
            $result | Add-Member NoteProperty -name "Thumbprint" -value $thumbprint
            $result | Add-Member NoteProperty -name "Certificate" -value $sslCert

            return $result
        }
    }
}

Function GetAdfsCertificatesToCheck($primaryFilter)
{
    #Skip service communication cert if there are no message security endpoints
    $endpoints = Get-AdfsEndpoint | where {$_.SecurityMode -eq 'Message' -and $_.Enabled -eq $true -and $_.AddressPath -ne '/adfs/services/trusttcp/windows'}
    $skipCommCert = ($endpoints -eq $null)

    #get all certs
    $adfsCertificates = Get-AdfsCertificate | where {$_.IsPrimary -eq $primaryFilter}

    if ($skipCommCert)
    {
        $adfsCertificates = $adfsCertificates | where {$_.CertificateType -ne "Service-Communications"}
    }

    return $adfsCertificates
}

function GetAdHealthAgentRegistryKeyValue($valueName, $defaultValue)
{
    $agentRegistryValue = Get-ItemProperty -path $AdHealthAgentRegistryKeyPath -Name $valueName -ErrorAction SilentlyContinue
    if ($agentRegistryValue -eq $null)
    {
        return $defaultValue;
    }
    else
    {
        return $agentRegistryValue.$valueName;
    }
}

Function IsLocalUser
{
    $isLocal = ($env:COMPUTERNAME -eq $env:USERDOMAIN)
    return $isLocal
}

Function ObjectDispose([System.IDisposable] $disposeMe)
{
    if ($null -ne $disposeMe)
    {
        if ($null -ne $disposeMe.psbase)
        {
            $disposeMe.psbase.Dispose()
        }
        else
        {
            $disposeMe.Dispose()
        }
    }
}

Function GetObjectsFromAD ($domain, $filter, [switch] $GlobalCatalog)
{
    try
    {
        $directoryContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext "Domain",$domain
        $searchDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($directoryContext)
        $searchDomainDirectoryEntry = $searchDomain.GetDirectoryEntry()
        $domainDistinguishedName = $searchDomainDirectoryEntry.distinguishedName
        $domainDirectoryEntry = $null

        if ($GlobalCatalog)
        {
            $domainDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry "GC://$domainDistinguishedName"
        }
        else
        {
            $domainDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$domainDistinguishedName"
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot =  $domainDirectoryEntry 
        $searcher.SearchScope = "SubTree"
        $props = $searcher.PropertiestoLoad.Add("distinguishedName")
        $props = $searcher.PropertiestoLoad.Add("objectGuid")
        $searcher.Filter = $filter
        $searchResults = $searcher.FindAll()
        
        $finalResults = @()
        if (($searchResults -ne $null) -and ($searchResults.Count -ne 0))
        {
            $searchResults | % { $finalResults += $_}
        }
        return $finalResults
    }
    finally
    {
        ObjectDispose $searchDomain
        ObjectDispose $searchDomainDirectoryEntry
        ObjectDispose $domainDirectoryEntry
        ObjectDispose $searcher
        ObjectDispose $searchResults
    }
}

Function Get-FirstEnabledWIAEndpointUri()
{
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12
    $cli = New-Object net.WebClient;
    $sslBinding = GetSslBinding
    $mexString = $cli.DownloadString("https://" + $sslBinding.HostNamePort + "/adfs/services/trust/mex")
    $xmlMex = [xml]$mexString
    $wiaendpoint = $xmlMex.definitions.service.port | where {$_.EndpointReference.Address -match "trust/\d+/(windows|kerberos)"} | select -First 1
    if ($wiaendpoint -eq $null)
    {
        return $null
    }
    else
    {
        return $wiaendpoint.EndpointReference.Address
    }
}

Function Get-ADFSIdentifier
{
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $cli = New-Object net.WebClient;
    #Set the encoding to handle the cases of servers returning metadata with Unicode characters in it. E.g., Korean.
    $cli.Encoding = [System.Text.Encoding]::UTF8
    $sslBinding = GetSslBinding
    $fedmetadataString = $cli.DownloadString("https://" + $sslBinding.HostNamePort + "/federationmetadata/2007-06/federationmetadata.xml")
    $fedmetadata = [xml]$fedmetadataString
    return $fedmetadata.EntityDescriptor.entityID
}

Function NetshHttpShowSslcert
{
    return (netsh http show sslcert)
}

Function GetSslBindings
{
    $output = NetshHttpShowSslcert | ForEach-Object {$tok = $_.Split(":"); IF ($tok.Length -gt 1 -and $tok[1].TrimEnd() -ne "" -and $tok[0].StartsWith(" ")) {$_}}
    $bindings = @{};
    $bindingName = "";
    foreach ($bindingLine in $output)
    {
        $splitLine = $bindingLine.Split(":");
        switch -WildCard ($bindingLine.Trim().ToLower())
        {
            "ip:port*"
            {
                $bindingName = $splitLine[2].Trim() + ":" + $splitLine[3].Trim();
                $bindings[$bindingName] = @{};
            }
            "hostname:port*"
            {
                $bindingName = $splitLine[2].Trim() + ":" + $splitLine[3].Trim();
                $bindings[$bindingName] = @{};
            }
            "certificate hash*"
            {
                $bindings[$bindingName].Add("Thumbprint", $splitLine[1].Trim());
            }
            "application id*"
            {
                $bindings[$bindingName].Add("Application ID", $splitLine[1].Trim());
            }
            "ctl store name*"
            {
                $bindings[$bindingName].Add("Ctl Store Name", $splitLine[1].Trim());
            }
        }
    }

    $bindings;
}

Function IsSslBindingValid
{
    Param
    (
        # The SSL bindings dictionary
        [Parameter(Mandatory = $true)]
        [Object]
        $Bindings,
        # The IP port or hostname port
        # Format: "127.0.0.0:443" or "localhost:443"
        [Parameter(Mandatory = $true)]
        [string]
        $BindingIpPortOrHostnamePort,
        # The thumbprint of the AD FS SSL certificate
        [Parameter(Mandatory = $true)]
        [string]
        $CertificateThumbprint,
        # Bool to check for Ctl Store
        [Parameter(Mandatory = $false)]
        [boolean]
        $VerifyCtlStoreName = $true
    )

    $returnVal = @{}

    Out-Verbose "Validating SSL binding for $BindingIpPortOrHostnamePort.";
    if (!$Bindings[$BindingIpPortOrHostnamePort])
    {
        Out-Verbose "Fail: No binding could be found with $BindingIpPortOrHostnamePort";
        $returnVal["Detail"] = "The following SSL certificate binding could not be found $BindingIpPortOrHostnamePort.";
        $returnVal["IsValid"] = $false;
        return $returnVal;
    }

    $binding = $Bindings[$BindingIpPortOrHostnamePort];

    if ($binding["Thumbprint"] -ne $CertificateThumbprint)
    {
        Out-Verbose "Fail: Not matching thumbprint";
        $returnVal["Detail"] = "The following SSL certificate binding $BindingIpPortOrHostnamePort did not match the AD FS SSL thumbprint: $CertificateThumbprint.";
        $returnVal["IsValid"] = $false;
        return $returnVal;
    }

    if ($VerifyCtlStoreName -and $binding["Ctl Store Name"] -ne $ctlStoreName)
    {
        Out-Verbose "Fail: Not matching Ctl store name";
        $returnVal["Detail"] = "The following SSL certificate binding $BindingIpPortOrHostnamePort did not have the correct Ctl Store Name: AdfsTrustedDevices.";
        $returnVal["IsValid"] = $false;
        return $returnVal;
    }

    Out-Verbose "Successfully validated SSL binding for $BindingIpPortOrHostnamePort.";
    $returnVal["IsValid"] = $true;
    return $returnVal;
}

Function IsUserPrincipalNameFormat
{
    Param
    (
        [string]
        $toValidate
    )

    if ([string]::IsNullOrEmpty($toValidate))
    {
        return $false;
    }

    return $toValidate -Match $EmailAddressRegex;
}

Function CheckRegistryKeyExist($key)
{
    return (Get-Item -LiteralPath $key -ErrorAction SilentlyContinue) -ne $null;
}

Function IsTlsVersionEnabled($version)
{
    $TlsVersionPath = $TlsPath -f "$version";
    Out-Verbose "Checking if TLS $version is enabled";
    if (CheckRegistryKeyExist($TlsVersionPath))
    {
        Out-Verbose "The registry key exists for this TLS version";
        $clientPath = $TlsClientPath -f $TlsVersionPath;
        $serverPath = $TlsServerPath -f $TlsVersionPath;
        if (CheckRegistryKeyExist($clientPath) -and CheckRegistryKeyExist($serverPath))
        {
            Out-Verbose "Both Client and Server keys exist.";
            $clientEnabled = IsTlsVersionEnabledInternal $clientPath;
            $serverEnabled = IsTlsVersionEnabledInternal $serverPath

            return $clientEnabled -and $serverEnabled;
        }
    }
    else
    {
        Out-Verbose "The registry key for this TLS version does not exist at $TlsVersionPath";
    }

    return $true;
}

Function GetValueFromRegistryKey($key, $name)
{
    return $key.GetValue($name);
}

Function IsTlsVersionEnabledInternal($path)
{
    Out-Verbose "Checking if version is enabled for $path";
    $key = Get-Item -LiteralPath $path;
    $enabled = GetValueFromRegistryKey $key "Enabled"
    $disabledByDefault = GetValueFromRegistryKey $key "DisabledByDefault"
    Out-Verbose "Enabled = $enabled";
    Out-Verbose "DisabledByDefault = $disabledByDefault";
    if (($enabled -ne $null -and $enabled -eq 0) -and ($disabledByDefault -ne $null -and $disabledByDefault -eq 1))
    {
        Out-Verbose "It is properly disabled";
        return $false;
    }

    Out-Verbose "It is enabled";
    return $true;
}

Function IsServerTimeInSyncWithReliableTimeServer
{
    Out-Verbose "Comparing server time with reliable time server";
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback;
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null;

    $originalSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol;
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls";

    $request = Invoke-WebRequest -Uri 'http://nist.time.gov/actualtime.cgi?lzbc=siqm9b' -UseBasicParsing;

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback;
    [Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol;

    $currentRtsTimeUtc = (New-Object -TypeName DateTime -ArgumentList (1970, 1, 1)).AddMilliseconds(([Xml]$request.Content).timestamp.time / 1000);
    Out-Verbose "Current reliable time server time UTC $currentRtsTimeUtc";

    $currentTimeFromServerUtc = (Get-Date).ToUniversalTime();
    Out-Verbose "Current server time UTC $currentTimeFromServerUtc";

    $timeDifferenceInSeconds = [int]($currentRtsTimeUtc - $currentTimeFromServerUtc).TotalSeconds;
    Out-Verbose "Time difference in seconds $timeDifferenceInSeconds";

    if ($timeDifferenceInSeconds -eq $null -or $timeDifferenceInSeconds -lt ($timeDifferenceMaximum * -1) -or $timeDifferenceInSeconds -gt $timeDifferenceMaximum)
    {
        Out-Verbose "Detected that the time difference between reliable time server and the current server time is greater $timeDifferenceMaximum or less than -$timeDifferenceMaximum";
        return $false;
    }

    return $true;
}

Function GetCertificatesFromAdfsTrustedDevices
{
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($ctlStoreName, $localMachine);
    $store.open("ReadOnly");
    return $store.Certificates;
}

Function VerifyCertificatesArePresent($certificatesInPrimaryStore)
{
    $certificatesInStore = @(GetCertificatesFromAdfsTrustedDevices);
    $missingCerts = @();
    foreach ($certificate in $certificatesInPrimaryStore)
    {
        if (!$certificatesInStore.Contains($certificate))
        {
            $missingCerts += $certificate;
        }
    }

    return $missingCerts;
}

function GenerateDiagnosticData()
{
    Param
    (
        [switch]    $includeTrusts,
        [string]    $sslThumbprint,
        [string[]]  $adfsServers,
        [switch]    $local
    )

    # configs
    # cmdlets to be run and have results output into the diagnostic file
    # structured as follows:
    # modules = @{module1 = @{cmdlet1.1 = arrayList of arguments,
    #                         cmdlet1.2 = arrayList of arguments, ...}
    #             module2 = @{cmdlet2.1 = arrayList of arguments, ...}
    #             ...
    #            }
    # (the arguments will be joined and run with the cmdlet.)
    $modules =
        @{ADFSToolbox =
            @{
                'Test-AdfsServerHealth' = New-Object System.Collections.ArrayList;
            };
        };

    # version number of the output (updated when the function is changed)
    $outputVersion = $ModuleVersion
    # end configs

    Out-Verbose "Binding each argument to relevant cmdlets"
    if ($includeTrusts)
    {
        $modules['ADFSToolbox']['Test-AdfsServerHealth'].Add('-verifyTrustCerts') > $null
    }

    if ($sslThumbprint)
    {
        $modules['ADFSToolbox']['Test-AdfsServerHealth'].Add('-sslThumbprint $sslThumbprint') > $null
    }

    if ($adfsServers)
    {
        $modules['ADFSToolbox']['Test-AdfsServerHealth'].Add('-AdfsServers $adfsServers') > $null
    }

    if ($local)
    {
        $modules['ADFSToolbox']['Test-AdfsServerHealth'].Add('-local') > $null
    }

    # create aggregate object to store diagnostic output from each cmdlet run
    $diagnosticData = New-Object -TypeName PSObject
    $testAdfsServerHealth = New-Object -TypeName PSObject

    # Add ADFS configuration information to the diagnostics json
    $adfsConfiguration = New-Object -TypeName PSObject
    $adfsConfiguration =  AdfsConfiguration
    $metadata = New-Object -TypeName PSObject
    $metadata | Add-Member -MemberType NoteProperty -Name 'Run Id' -Value (New-Guid).Guid
    $metadata | Add-Member -MemberType NoteProperty -Name 'Timestamp' -Value (Get-Date).ToUniversalTime()
    $metadata | Add-Member -MemberType NoteProperty -Name 'Version' -Value $outputVersion

    foreach($module in $modules.keys)
    {
        $moduleData = New-Object -TypeName PSObject
        foreach($cmdlet in (($modules[$module]).keys))
        {
            # join the arguments together
            $args = $modules[$module][$cmdlet]-join -' '

            # join the command with the arguments
            $cmd = -join($module,'\', $cmdlet, ' ', $args)

            # upon success, add the cmdlet results;
            # otherwise add the error message
            Out-Verbose "Attempting to run cmdlet $cmdlet"
            try
            {
                $res = (Invoke-Expression -Command $cmd)
                Add-Member -InputObject $moduleData -MemberType NoteProperty -Name $cmdlet -Value $res
                Add-Member -InputObject $diagnosticData -MemberType NoteProperty -Name $module -Value $moduleData
                Out-Verbose "Successfully ran cmdlet $cmdlet"
            }
            catch
            {
                Write-Error -Message (-join("Error running cmdlet ", $cmd, ": ", $_.Exception.Message))
                return $null
            }
        }
    }

    # add the AD FS Configuration information to the output
    Add-Member -InputObject $moduleData -MemberType NoteProperty -Name "Adfs-Configuration" -Value $adfsConfiguration

    # add metadata
    Add-Member -InputObject $moduleData -MemberType NoteProperty -Name "Metadata" -Value $metadata

    return $diagnosticData
}

function GenerateJSONDiagnosticData()
{
    Param
    (
        [switch]    $includeTrusts,
        [string]    $sslThumbprint,
        [string[]]  $adfsServers,
        [switch]    $local
    )

    Out-Verbose "Generating diagnostic data"
    $diagnosticData = GenerateDiagnosticData -includeTrusts:$includeTrusts -sslThumbprint $sslThumbprint -adfsServers $adfsServers -local:$local;
    Out-Verbose "Successfully generated diagnostic data"

    return ConvertTo-JSON -InputObject $diagnosticData -Depth $maxJsonDepth -Compress
}

function IsExecutedByConnectHealth {
    # Attempt to load the synthetic transactions library to test if Connect Health is the executer of the script. 
    # If the dll exists Connect Health executed the test, skip gathering the RP count.
    ipmo .\Microsoft.Identity.Health.Adfs.SyntheticTransactions.dll -ErrorAction SilentlyContinue -ErrorVariable synthTxErrVar 
    if ($synthTxErrVar -ne $null) 
    { 
        return $false;
    }

    return $true    
}
