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

Function Get-OsVersion
{
    $OSVersion = [System.Environment]::OSVersion.Version;

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
        if ($adfsVersion -eq $adfs3)
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

Function GetObjectsFromAD ($domain, $filter)
{
    Out-Verbose "Domain = $domain, filter = $filter";
    $rootDomain = New-Object System.DirectoryServices.DirectoryEntry
    $searcher = New-Object System.DirectoryServices.DirectorySearcher $domain
    $searcher.SearchRoot = $rootDomain
    $searcher.SearchScope = "SubTree"
    $props = $searcher.PropertiestoLoad.Add("distinguishedName")
    $props = $searcher.PropertiestoLoad.Add("objectGuid")
    $searcher.Filter = $filter
    return $searcher.FindAll()
}

Function Get-FirstEnabledWIAEndpointUri()
{
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
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
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $cli = New-Object net.WebClient;
    $sslBinding = GetSslBinding
    $fedmetadataString = $cli.DownloadString("https://" + $sslBinding.HostNamePort + "/federationmetadata/2007-06/federationmetadata.xml")
    $fedmetadata = [xml]$fedmetadataString
    return $fedmetadata.EntityDescriptor.entityID
}

Function GetSslBindings
{
    $output = netsh http show sslcert | ForEach-Object {$tok = $_.Split(":"); IF ($tok.Length -gt 1 -and $tok[1].TrimEnd() -ne "" -and $tok[0].StartsWith(" ")) {$_}}
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
        # The test result
        [Parameter(Mandatory = $true)]
        [ref]
        $TestResult,
        # Bool to check for Ctl Store
        [Parameter(Mandatory = $false)]
        [boolean]
        $VerifyCtlStoreName = $true
    )

    Out-Verbose "Validating SSL binding for $BindingIpPortOrHostnamePort.";
    if (!$Bindings[$BindingIpPortOrHostnamePort])
    {
        Out-Verbose "Fail: No binding could be found with $BindingIpPortOrHostnamePort";
        $testResult.Value.Detail = "The following SSL certificate binding could not be found $BindingIpPortOrHostnamePort.";
        $testResult.Value.Result = [ResultType]::Fail;
        return $false;
    }

    $binding = $Bindings[$BindingIpPortOrHostnamePort];

    if ($binding["Thumbprint"] -ne $CertificateThumbprint)
    {
        Out-Verbose "Fail: Not matching thumbprint";
        $testResult.Value.Detail = "The following SSL certificate binding $BindingIpPortOrHostnamePort did not match the AD FS SSL thumbprint: $CertificateThumbprint.";
        $testResult.Value.Result = [ResultType]::Fail;
        return $false;
    }

    if ($VerifyCtlStoreName)
    {
        if ($binding["Ctl Store Name"] -ne "AdfsTrustedDevices")
        {
            Out-Verbose "Fail: Not matching Ctl store name";
            $testResult.Value.Detail = "The following SSL certificate binding $BindingIpPortOrHostnamePort did not have the correct Ctl Store Name: AdfsTrustedDevices.";
            $testResult.Value.Result = [ResultType]::Fail;
            return $false;
        }
    }

    Out-Verbose "Successfully validated SSL binding for $BindingIpPortOrHostnamePort.";
    return $true;
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

Function IsTlsVersionEnabledInternal($path)
{
    Out-Verbose "Checking if version is enabled for $path";
    $key = Get-Item -LiteralPath $clientPath;
    $enabled = $key.GetValue("Enabled");
    $disabledByDefault = $key.GetValue("DisabledByDefault");
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