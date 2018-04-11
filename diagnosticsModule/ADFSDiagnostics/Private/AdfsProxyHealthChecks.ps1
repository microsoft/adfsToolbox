Function TestIsAdfsProxyRunning
{
    $testName = "TestIsAdfsProxyRunning";
    $serviceStateOutputKey = "ADFSProxyServiceState";
    $testResult = New-Object TestResult -ArgumentList($testName);

    try
    {
        $adfsProxyServiceState = Get-ServiceState($adfsProxyServiceName);
        if ($adfsProxyServiceState -ne "Running")
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail = "Current state of $adfsProxyServiceName is: $adfsProxyServiceState";
        }
        $testResult.Output = @{$serviceStateOutputKey = $adfsProxyServiceState};

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestSTSReachableFromProxy()
{
    $testName = "STSReachableFromProxy"
    $exceptionKey = "STSReachableFromProxyException"
    try
    {
        $mexUrlTestResult = New-Object TestResult -ArgumentList($testName);
        $mexUrlTestResult.Output = @{$exceptionKey = "NONE"}

        $proxyInfo = gwmi -Class ProxyService -Namespace root\ADFS

        $stsHost = $proxyInfo.HostName + ":" + $proxyInfo.HostHttpsPort

        $mexUrl = "https://" + $stsHost + "/adfs/services/trust/mex";
        $webClient = New-Object net.WebClient;
        try
        {
            $data = $webClient.DownloadData($mexUrl);
            #If the mex is successfully downloaded from proxy, then the test is deemed succesful
        }
        catch [Net.WebException]
        {
            $exceptionEncoded = [System.Web.HttpUtility]::HtmlEncode($_.Exception.ToString());
            $mexUrlTestResult.Result = [ResultType]::Fail;
            $mexUrlTestResult.Detail = $exceptionEncoded;
            $mexUrlTestResult.Output.Set_Item($exceptionKey, $exceptionEncoded)
        }

        return $mexUrlTestResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestNoNonSelfSignedCertificatesInRootStore
{
    $testName = "TestNoNonSelfSignedCertificateInRootStore";
    $testResult = New-Object TestResult -ArgumentList($testName)
    $certificateOutputKey = "NonSelfSignedCertificates";

    try
    {
        $nonSelfSignedCertificates = Get-ChildItem Cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject} | Select-Object FriendlyName, Thumbprint, Subject;

        if ($nonSelfSignedCertificates.Count -ne 0)
        {
            $testResult.Detail = "There were non-self-signed certificates found in the root store. Move them to the intermediate store.";
            $testResult.Result = [ResultType]::Fail;
            $testResult.Output = @{$certificateOutputKey = $nonSelfSignedCertificates};
        }

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestProxySslBindings
{
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $AdfsSslThumbprint
    )
    $testName = "TestProxySslBindings";
    $testResult = New-Object TestResult -ArgumentList($testName);
    Out-Verbose "Parameter AdfsSslThumbprint = $AdfsSslThumbprint";

    try
    {
        $bindings = GetSslBindings;
        Out-Verbose "Attempting to get federation service name.";
        $proxyInfo = Get-WmiObject -Class ProxyService -Namespace root\ADFS

        $federationServiceName = $proxyInfo.HostName;
        Out-Verbose "Retrieved federation service name: $federationServiceName.";

        $adfsPort = $proxyInfo.HostHttpsPort;
        $tlsPort = $proxyInfo.TlsClientPort;
        Out-Verbose "Retrieved ADFS Port: $adfsPort TLS Port: $tlsPort";

        # Expected SSL bindings
        Out-Verbose "Attempting to validate expected SSL bindings."
        $isValid = IsSslBindingValid -Bindings $bindings -BindingIpPortOrHostnamePort $($federationServiceName + ":" + $adfsPort) -CertificateThumbprint $AdfsSslThumbprint -TestResult ([ref]$testResult)
        if (!$isValid)
        {
            return $testResult;
        }

        $bindings.Remove($($federationServiceName + ":" + $adfsPort));

        $isValid = IsSslBindingValid -Bindings $bindings -BindingIpPortOrHostnamePort $($federationServiceName + ":" + $tlsPort) -CertificateThumbprint $AdfsSslThumbprint -TestResult ([ref]$testResult) -VerifyCtlStoreName $false;
        if (!$isValid)
        {
            return $testResult;
        }

        $bindings.Remove($($federationServiceName + ":" + $tlsPort));

        # Check custom bindings that match the AD FS Application Id
        foreach ($key in $bindings.Keys)
        {
            if ($bindings[$key]["Application ID"] -eq $adfsApplicationId)
            {
                Out-Verbose "Checking custom SSL certificate binding $key.";

                # We can only validate the Thumbprint here since we do not know which ip/hostname port this binding is for.
                $isValid = IsSslBindingValid -Bindings $bindings -BindingIpPortOrHostnamePort $key -CertificateThumbprint $AdfsSslThumbprint -TestResult ([ref]$testResult) -VerifyCtlStoreName $false;
                if (!$isValid)
                {
                    return $testResult;
                }
            }
        }

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}
