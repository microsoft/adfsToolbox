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

Function Get-AdfsVersion($osVersion)
{
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
        return "STS"
    }

    #ADFS 2012 R2 Proxy: hklm:\software\microsoft\adfs ProxyConfigurationStatus = 2
    $adfs3ProxyRegValue = Get-ItemProperty "hklm:\software\microsoft\adfs" -Name ProxyConfigurationStatus -ErrorAction SilentlyContinue
    if ($adfs3ProxyRegValue.ProxyConfigurationStatus -eq 2)
    {
        return "Proxy"
    }

    #ADFS 2.x STS: HKLM:\Software\Microsoft\ADFS2.0\Components SecurityTokenServer = 1
    $adfs2STSRegValue = Get-ItemProperty "hklm:\software\microsoft\ADFS2.0\Components" -Name SecurityTokenServer -ErrorAction SilentlyContinue
    if ($adfs2STSRegValue.SecurityTokenServer -eq 1)
    {
        return "STS"
    }

    #ADFS 2.x Proxy: HKLM:\Software\Microsoft\ADFS2.0\Components ProxyServer = 1
    $adfs2STSRegValue = Get-ItemProperty "hklm:\software\microsoft\ADFS2.0\Components" -Name ProxyServer -ErrorAction SilentlyContinue
    if ($adfs2STSRegValue.ProxyServer -eq 1)
    {
        return "Proxy"
    }

    return "none"
}



Function IsAdfsServiceRunning()
{
    $adfsSrv = get-service adfssrv

    if ($adfsSrv -eq $null)
    {
        return $false
    }
    else
    {
        return ($adfsSrv.Status -eq "Running")
    }
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
    $osVersion = [System.Environment]::OSVersion.Version
    $adfsVersion = Get-AdfsVersion -osVersion $osVersion

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