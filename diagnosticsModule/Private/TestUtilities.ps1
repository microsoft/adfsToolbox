Function CreateTestResultFromPSObject($obj)
{
    $testResult = New-Object TestResult -ArgumentList($obj.Name);
    $testResult.Result = $obj.Result;
    $testResult.Detail = $obj.Detail;
    $testResult.Output = $obj.Output;
    $testResult.ExceptionMessage = $obj.ExceptionMessage;
    $testResult.Exception = $obj.Exception;

    return $testResult;
}

Function Create-NotRunOnSecondaryTestResult
{
    param(
        [string] $testName
    )
    $testResult = New-Object TestResult -ArgumentList($testName)
    $testResult.Result = [ResultType]::NotRun;
    $testResult.Detail = "This check runs only on Primary Nodes."
    return $testResult
}

Function Create-ErrorExceptionTestResult
{
    param(
        [string]
        $testName,
        [Exception]
        $exception
    )

    $testResult = New-Object TestResult -ArgumentList($testName);
    $testResult.Result = [ResultType]::Error;
    $testResult.ExceptionMessage = $exception.Message;
    $testResult.Exception = $exception.ToString();
    return $testResult;
}

Function Invoke-TestFunctions
{
    param(
        [string]
        $role,
        [array]
        $functionsToRun,
        $functionArguments
    )

    $results = @()
    $totalFunctions = $functionsToRun.Count
    $functionCount = 0
    foreach ($function in $functionsToRun)
    {
        $functionCount++
        $percent = 100 * $functionCount / $totalFunctions
        Write-Progress -Activity "Executing Tests for $role" -Status $function -PercentComplete $percent
        $result = Invoke-Expression $function
        $results = $results + $result
    }

    return $results
}

Function TestAdfsSTSHealth()
{
    Param
    (
        $verifyO365 = $true,
        [string[]]
        $adfsServers = $null
    )

    $functionArguments = @{"adfsServers" = $adfsServers};

    $role = Get-ADFSRole

    if ($role -ne $adfsRoleSTS)
    {
        return
    }

    # Determine ADFS Version
    $ADFSVersion = Get-AdfsVersion

    Import-ADFSAdminModule

    #force refresh of ADFS Properties

    try
    {
        $props = Retrieve-AdfsProperties -force
    }
    catch
    {
        #do nothing, other than prevent the error record to go to the pipeline
    }

    $functionsToRun = @( `
            "TestIsAdfsRunning", `
            "TestIsWidRunning", `
            "TestPingFederationMetadata", `
            "TestSslBindings", `
            "Test-AdfsCertificates", `
            "TestADFSDNSHostAlias", `
            "TestADFSDuplicateSPN", `
            "TestServiceAccountProperties", `
            "TestAppPoolIDMatchesServiceID", `
            "TestComputerNameEqFarmName", `
            "TestSSLUsingADFSPort", `
            "TestSSLCertSubjectContainsADFSFarmName", `
            "TestAdfsAuditPolicyEnabled", `
            "TestAdfsRequestToken", `
            "TestTrustedDevicesCertificateStore", `
            "TestAdfsPatches", `
            "TestServicePrincipalName", `
            "TestTLSMismatch");

    if (($adfsServers -eq $null) -or ($adfsServers.Count -eq 0))
    {
        $functionsToRun += "TestProxyTrustPropagation";
        $functionsToRun += "TestTimeSync";
    }
    else
    {
        $functionsToRun += "TestProxyTrustPropagation -adfsServers `$functionArguments.adfsServers";
        $functionsToRun += "TestTimeSync -adfsServers `$functionArguments.adfsServers";
    }

    if ($verifyO365 -eq $true)
    {
        $functionsToRun = $functionsToRun + @( `
                "TestOffice365Endpoints", `
                "TestADFSO365RelyingParty", `
                "TestNtlmOnlySupportedClientAtProxyEnabled");
    }

    return Invoke-TestFunctions -role $adfsRoleSTS -functionsToRun $functionsToRun -functionArguments $functionArguments;
}

Function TryTestAdfsSTSHealthOnFarmNodes()
{
    Param(
        $verifyO365 = $true,
        [string[]]
        $adfsServers = $null,
        [switch]
        $local = $false
    )

    Out-Verbose "Attempting to run AD FS STS health checks farm wide.";
    if (($adfsServers -eq $null -or $adfsServers.Count -eq 0) -and (-not ($local)))
    {
        Out-Verbose "Detected that no farm information was provided.";
        $osVersion = Get-OsVersion;
        $isPrimary = IsAdfsSyncPrimaryRole;
        if ($osVersion -eq [OSVersion]::WS2016 -and $isPrimary)
        {
            $adfsServers = @();
            Write-Host "Detected OS as Windows Server 2016, attempting to run health checks across all of your AD FS servers in your farm.";

            $nodes = (Get-AdfsFarmInformation).FarmNodes;
            foreach ($server in $nodes)
            {
                # We skip adding the node that corresponds to this server.
                if ($server.FQDN -like ([System.Net.Dns]::GetHostByName(($env:computerName))).HostName)
                {
                    continue;
                }

                $adfsServers += $server
            }
            Out-Verbose "Detected the following servers in the farm: $adfsServers";
        }
    }
    else
    {
        # We filter out this computer's name and FQDN
        $adfsServers = $adfsServers | Where-Object { ($_ -notlike [System.Net.Dns]::GetHostByName(($env:computerName)).HostName) -and ($_ -notlike $env:COMPUTERNAME) };
    }

    $results = @();
    Write-Host "Running the health checks on the local machine.";
    $result = TestAdfsSTSHealth -verifyO365 $verifyO365 -verifyTrustCerts $verifyTrustCerts -adfsServers $adfsServers;
    foreach($test in $result)
    {
        $test.ComputerName = "Localhost";
    }

    $results += $result;

    if (($adfsServers -ne $null -and $adfsServers.Count -ne 0) -and (-not ($local)))
    {
        Write-Host "Running health checks on other servers in farm."

        $Private = @(Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue);
        $Public = @(Get-ChildItem -Path $PSScriptRoot\..\Public\*.ps1 -ErrorAction SilentlyContinue);
        $AllFunctionFiles = $Private + $Public;

        $commonFunctions = (Get-Command $AllFunctionFiles).ScriptContents;
        $commonFunctions = $commonFunctions -join [Environment]::NewLine;

        foreach ($server in $adfsServers)
        {
            Write-Host "Running health checks on $server.";
            $session = New-PSSession -ComputerName $server -ErrorAction SilentlyContinue;
            if ($session -eq $null)
            {
                Out-Warning "There was a problem connecting to $server, skipping this server."
                continue;
            }

            $deserializedResult = Invoke-Command -Session $session -ArgumentList $commonFunctions -ScriptBlock {
                param($commonFunctions)
                Invoke-Expression $commonFunctions;
                return TestAdfsSTSHealth;
            }

            $serializedResult = @();

            foreach($obj in $deserializedResult)
            {
                $newObj = CreateTestResultFromPSObject $obj;
                $newObj.ComputerName = $server;
                $serializedResult += $newObj;
            }

            $results += $serializedResult;

            if ($session)
            {
                Remove-PSSession $Session
            }
        }
    }

    Write-Host "Successfully completed all health checks.";
    return New-Object TestResultsContainer -ArgumentList(, $results);
}

Function TestAdfsProxyHealth()
{
    Param(
        [string]
        $sslThumbprint
    )

    $functionArguments = @{"AdfsSslThumbprint" = $sslThumbprint};

    $functionsToRun = @( `
            "TestIsAdfsRunning", `
            "TestIsAdfsProxyRunning", `
            "TestSTSReachableFromProxy", `
            "TestNoNonSelfSignedCertificatesInRootStore", `
            "TestTLSMismatch", `
            "TestTimeSync");

    if ([string]::IsNullOrWhiteSpace($sslThumbprint))
    {
        $functionsToRun += "TestProxySslBindings";
    }
    else
    {
        $functionsToRun += "TestProxySslBindings -AdfsSslThumbprint `$functionArguments.AdfsSslThumbprint";
    }

    $results = Invoke-TestFunctions -role "Proxy" -functionsToRun $functionsToRun -functionArguments $functionArguments;
    foreach($test in $result)
    {
        $test.ComputerName = "Localhost";
    }

    Write-Host "Successfully completed all health checks.";

    return New-Object TestResultsContainer -ArgumentList(, $results);
}