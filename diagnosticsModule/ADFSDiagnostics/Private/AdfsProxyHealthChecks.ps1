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
        $testResult = New-Object TestResult -ArgumentList ($testName)
        $testResult.Result = [ResultType]::NotRun;
        $testResult.Detail = $_.Exception.Message;
        $testResult.ExceptionMessage = $_.Exception.Message
        return $testResult;
    }
}