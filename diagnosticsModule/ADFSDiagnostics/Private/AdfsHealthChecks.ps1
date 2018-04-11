# Windows Internal Database Service State if it is used by ADFS
Function TestIsWidRunning()
{
    $testName = "IsWidRunning"
    $serviceStateKey = "WIDServiceState"
    $serviceStartModeKey = "WIDServiceStartMode"
    try
    {
        $adfsConfigurationDbTestResult = New-Object TestResult -ArgumentList($testName);
        $adfsConfigurationDb = (Get-WmiObject -namespace root/ADFS -class SecurityTokenService).Properties["ConfigurationDatabaseConnectionString"].Value;
        If ($adfsConfigurationDb.Contains("microsoft##wid") -or $adfsConfigurationDb.Contains("microsoft##ssee"))
        {
            $widService = (Get-WmiObject win32_service | Where-Object {$_.DisplayName.StartsWith("Windows Internal Database")})
            $widServiceState = $widService.State
            if ($widServiceState.Count -ne $null -and $widServiceState.Count -gt 1)
            {
                $widServiceState = $widServiceState[0];
            }
            If ($widServiceState -ne "Running")
            {
                $adfsConfigurationDbTestResult.Result = [ResultType]::Fail;
                $adfsConfigurationDbTestResult.Detail = "Current State of WID Service is: $widServiceState";
            }
            $adfsConfigurationDbTestResult.Output = @{$serviceStateKey = $widServiceState; $serviceStartModeKey = $widService.StartMode}
            return $adfsConfigurationDbTestResult;
        }
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

# Ping Federation metadata page on localhost
Function TestPingFederationMetadata()
{
    $testName = "PingFederationMetadata"
    $exceptionKey = "PingFedmetadataException"
    try
    {
        $fedmetadataUrlTestResult = New-Object TestResult -ArgumentList($testName);
        $fedmetadataUrlTestResult.Output = @{$exceptionKey = "NONE"}

        $sslBinding = GetSslBinding
        $fedmetadataUrl = "https://" + $sslBinding.HostNamePort + "/federationmetadata/2007-06/federationmetadata.xml";
        $webClient = New-Object net.WebClient;
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        try
        {
            $data = $webClient.DownloadData($fedmetadataUrl);
        }
        catch [Net.WebException]
        {
            $exceptionEncoded = [System.Web.HttpUtility]::HtmlEncode($_.Exception.ToString());
            $fedmetadataUrlTestResult.Result = [ResultType]::Fail;
            $fedmetadataUrlTestResult.Detail = $exceptionEncoded;
            $fedmetadataUrlTestResult.Output.Set_Item($exceptionKey, $exceptionEncoded)
        }
        return $fedmetadataUrlTestResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestSslBindings()
{
    $adfsVersion = Get-AdfsVersion

    $testName = "CheckAdfsSslBindings"
    $sslBindingsKey = "SSLBindings"
    $sslOutputs = @{$sslBindingsKey = $none}

    $sslBindingsTestResult = New-Object TestResult -ArgumentList $testName
    $isAdfsServiceRunning = IsAdfsServiceRunning;

    if (Test-RunningOnAdfsSecondaryServer)
    {
        return Create-NotRunOnSecondaryTestResult $testName
    }

    if ($isAdfsServiceRunning -eq $false)
    {
        $sslBindingsTestResult.Result = [ResultType]::NotRun;
        $sslBindingsTestResult.Detail = "AD FS service is not running";
        return $sslBindingsTestResult;
    }

    try
    {
        if ($adfsVersion -eq $adfs3)
        {
            $adfsSslBindings = Get-AdfsSslCertificate;

            $tlsClientPort = $adfsProperties.TlsClientPort
            if (($adfsSslBindings | where {$_.PortNumber -eq $tlsClientPort}).Count -eq 0)
            {
                $sslBindingsTestDetail += "SSL Binding missing for port $tlsClientPort, Certificate Authentication will fail.`n";
            }
            $httpsPort = $adfsProperties.HttpsPort
            if (($adfsSslBindings | where {$_.PortNumber -eq $httpsPort}).Count -eq 0)
            {
                $sslBindingsTestDetail += "SSL Binding missing for port $httpsPort, AD FS requests will fail.";
            }
            $sslOutputs.Set_Item($sslBindingsKey, $adfsSslBindings)
        }
        else
        {
            if ($adfsVersion -eq $adfs2x)
            {
                Import-Module WebAdministration;

                #for ADFS 2.0, we need to find the SSL bindings.
                $httpsPort = GetHttpsPort
                $sslBinding = GetSslBinding

                if ($sslBinding -eq $null)
                {
                    $sslBindingsTestDetail += "SSL Binding missing for port " + $httpsPort.ToString() + ", AD FS requests will fail.";
                }
                else
                {
                    $sslOutputs.Set_Item($sslBindingsKey, $sslBinding)
                }
            }
        }

        $sslBindingsTestResult.Output = $sslOutputs
        if ($sslBindingsTestDetail)
        {
            $sslBindingsTestResult.Result = [ResultType]::Fail;
            $sslBindingsTestResult.Detail = $sslBindingsTestDetail;
        }

        return $sslBindingsTestResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

function Test-AdfsCertificates ()
{
    $primaryCertificateTypes = @("Service-Communications", "Token-Decrypting", "Token-Signing", "SSL")
    $secondaryCerticateTypes = $primaryCertificateTypes | ? {$_ -ne "Service-Communications" -and $_ -ne "SSL"}

    $primaryValues = @{$true = $primaryCertificateTypes; $false = $secondaryCerticateTypes}

    $results = @()

    $notRunTests = $false
    $notRunReason = ""

    if (-not (IsAdfsServiceRunning))
    {
        $notRunTests = $true
        $notRunReason = "AD FS Service is not running"
    }

    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            $notRunTests = $true
            $notRunReason = "This check does not run on AD FS Secondary Server"
        }
    }
    catch
    {
        $notRunTests = $true
        $notRunReason = "Cannot verify sync status of AD FS Server " + $_.Exception.ToString()
    }

    if ($notRunTests)
    {
        foreach ($isPrimary in $primaryValues.Keys)
        {
            foreach ($certType in $primaryValues.Item($isPrimary))
            {
                $results += Generate-NotRunResults -certificateType $certType -notRunReason $notRunReason -isPrimary $isPrimary
            }
        }
        return $results
    }

    $certsToCheck = Get-AdfsCertificatesToTest
    foreach ($isPrimary in $primaryValues.Keys)
    {
        foreach ($certType in $primaryValues.Item($isPrimary))
        {
            $adfsCerts = @($certsToCheck | where {$_.CertificateType -eq $certType -and $_.IsPrimary -eq $isPrimary})

            foreach ($adfsCert in $adfsCerts)
            {
                if ($null -eq $adfsCert)
                {
                    $results += Generate-NotRunResults -certificateType $certType -notRunReason "Not Testing Certificate of type $certType`nIsPrimary: $isPrimary" -isPrimary $isPrimary
                    continue
                }

                #Order Here is Relevant: If NotRunReason gets set, then other tests will inherit that reason, (and won't run)
                $notRunReason = ""
                $availableResult = Test-CertificateAvailable -adfsCertificate $adfsCert -certificateType $certType -isPrimary $isPrimary
                $results += $availableResult

                $thumbprint = $adfsCert.Thumbprint
                $cert = $adfsCert.Certificate
                $storeName = $adfsCert.StoreName
                $storeLocation = $adfsCert.StoreLocation

                if ([String]::IsNullOrEmpty($notRunReason) -and (($availableResult.Result -eq [ResultType]::Fail) -or ($cert -eq $null)))
                {
                    $notRunReason = "$certType certificate with thumbprint $thumbprint cannot be found."
                }

                $results += Test-CertificateSelfSigned -cert $cert -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason
                $results += Test-CertificateHasPrivateKey -cert $cert -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason -storeName $storeName -storeLocation $storeLocation
                $results += Test-CertificateExpired -cert $cert -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason
                $results += Test-CertificateCRL -cert $cert -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason
                if ([String]::IsNullOrEmpty($notRunReason) -and (Verify-IsCertExpired -cert $cert))
                {
                    $notRunReason = "Certificate is already expired."
                }

                $results += Test-CertificateAboutToExpire -cert $cert -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason
            }
        }
    }

    return $results
}

Function TestADFSDNSHostAlias
{
    $testName = "CheckFarmDNSHostResolution"
    $farmNameKey = "FarmName"
    $resolvedHostKey = "ResolvedHost"
    $serviceAccountKey = "AdfsServiceAccount"
    $errorKey = "ErrorMessage"

    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }

        #Set this as a warning because WIA can succeed if the service account
        #has the SPNs for the host the DNS resolves to

        $testResult = New-Object TestResult -ArgumentList ($testName)

        $isAdfsServiceRunning = IsAdfsServiceRunning

        if ($isAdfsServiceRunning -eq $false)
        {
            $testResult.Result = [ResultType]::NotRun;
            $testResult.Detail = "AD FS service is not running";
            return $testResult;
        }
        $farmName = (Retrieve-AdfsProperties).HostName
        $serviceAccountName = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).StartName

        $resolutionResult = [System.Net.Dns]::GetHostEntry($farmName)
        $resolvedHostName = $resolutionResult.HostName


        if ($resolvedHostName -ne $farmName)
        {
            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = "Farm Name '" + $farmName + "' is resolved as host '" + $resolvedHostName + "'. This might break windows integrated authentication scenarios.`n"
            $testResult.Detail += "Adfs Service Account: " + $serviceAccountName
        }
        else
        {
            $testResult.Result = [ResultType]::Pass
        }
        $testResult.Output = @{$farmNameKey = $farmName; $resolvedHostKey = $resolvedHostName; $serviceAccountKey = $serviceAccountName}

        return $testResult
    }
    catch [System.Net.Sockets.SocketException]
    {
        $testResult = New-Object TestResult -ArgumentList($testName);
        $testResult.Result = [ResultType]::Fail;
        $testResult.Detail = "Could not resolve the farm name {0} with exception '{1}'" -f $farmName, $_.Exception.Message;
        $testResult.Output = @{$farmNameKey = $farmName; $serviceAccountKey = $serviceAccountName; $errorKey = $_.Exception.ToString()}
        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestADFSDuplicateSPN
{
    $testName = "CheckDuplicateSPN"
    $farmSPNKey = "ADFSFarmSPN"
    $serviceAccountKey = "ServiceAccount"
    $spnObjKey = "SpnObjects"
    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }

        #Verify there are no duplicate Service Principal Names (SPN) for the farm

        $testResult = New-Object TestResult -ArgumentList ($testName)

        if (IsLocalUser -eq $true)
        {
            $testResult.Result = [ResultType]::NotRun
            $testResult.Detail = "Current user " + $env:USERNAME + " is not a domain account. Cannot execute this test"
            return $testResult
        }

        $isAdfsServiceRunning = IsAdfsServiceRunning

        if ($isAdfsServiceRunning -eq $false)
        {
            $testResult.Result = [ResultType]::NotRun;
            $testResult.Detail = "AD FS service is not running";
            return $testResult;
        }

        #Search both the service account and the holder of the SPN in the directory
        $adfsServiceAccount = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).StartName
        if ([String]::IsNullOrWhiteSpace($adfsServiceAccount))
        {
            throw "ADFS Service account is null or empty. The WMI configuration is in an inconsistent state"
        }

        $serviceAccountParts = $adfsServiceAccount.Split('\\')
        if ($serviceAccountParts.Length -ne 2)
        {
            throw "Unexpected value of the service account $adfsServiceAccount. Expected in DOMAIN\\User format"
        }

        $serviceAccountDomain = $serviceAccountParts[0]
        $serviceSamAccountName = $serviceAccountParts[1]

        $farmName = (Retrieve-AdfsProperties).HostName
        $farmSPN = "host/" + $farmName

        $spnResults = GetObjectsFromAD -domain $serviceAccountDomain -filter "(servicePrincipalName=$farmSPN)"
        $svcAcctSearcherResults = GetObjectsFromAD -domain $serviceAccountDomain -filter "(samAccountName=$serviceSamAccountName)"

        #root cause: no SPN at all
        if (($spnResults -eq $null) -or ($spnResults.Count -eq 0))
        {
            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = "No objects in the directory with SPN $farmSPN are found." + [System.Environment]::NewLine + "AD FS Service Account: " + $adfsServiceAccount
            $testResult.Output = @{$farmSPNKey = $farmSPN; $serviceAccountKey = $adfsServiceAccount; $spnObjKey = "NONE"}

            return $testResult
        }

        #root cause: Could not find the service account. This should be very rare
        if (($svcAcctSearcherResults -eq $null) -or ($svcAcctSearcherResults.Count -eq 0))
        {
            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = "Did not find the service account $adfsServiceAccount in the directory"
            $testResult.Output = @{$farmSPNKey = $farmSPN; $serviceAccountKey = $adfsServiceAccount; $spnObjKey = $spnResults[0].Properties.distinguishedname}
            return $testResult
        }

        if ($svcAcctSearcherResults.Count -ne 1)
        {
            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = = [String]::Format("Did not find 1 result for the service account in the directory. Found={0}", $svcAcctSearcherResults.Count)
            $testResult.Output = @{$farmSPNKey = $farmSPN; $serviceAccountKey = $adfsServiceAccount; $spnObjKey = $spnResults[0].Properties.distinguishedname}
            return $testResult
        }

        #root cause: multiple SPN
        if ($spnResults.Count -gt 1)
        {

            $testDetail = "Multiple objects are found in the directory with SPN:" + $farmSPN + [System.Environment]::NewLine + "Objects with SPN: " + [System.Environment]::NewLine
            $spnObjects = @()

            for ($i = 0; $i -lt $spnResults.Count; $i++)
            {
                $testDetail += $spnResults[$i].Properties.distinguishedname + [System.Environment]::NewLine
                $spnObjects += $spnResults[$i].Properties.distinguishedname
            }

            $testDetail += "AD FS Service Account: " + $adfsServiceAccount

            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = $testDetail
            $testResult.Output = @{$farmSPNKey = $farmSPN; $serviceAccountKey = $adfsServiceAccount; $spnObjKey = $spnObjects}

            return $testResult
        }

        #root cause: SPN is in the wrong account
        if ($spnResults.Count -eq 1)
        {
            $spnDistinguishedName = $spnResults[0].Properties.distinguishedname
            $svcAccountDistinguishedName = $svcAcctSearcherResults[0].Properties.distinguishedname

            $spnObjectGuid = [Guid]$spnResults[0].Properties.objectguid.Item(0)
            $svcAccountObjectGuid = [Guid]$svcAcctSearcherResults[0].Properties.objectguid.Item(0)

            if ($spnObjectGuid -eq $svcAccountObjectGuid)
            {
                $testResult.Result = [ResultType]::Pass
                $testResult.Detail = "Found SPN in object: " + $spnDistinguishedName
                $testResult.Output = @{$farmSPNKey = $farmSPN; $serviceAccountKey = $adfsServiceAccount; $spnObjKey = $spnResults[0].Properties.distinguishedname}
                return $testResult
            }
            else
            {
                $testResult.Result = [ResultType]::Fail
                $testResult.Detail = "Found SPN in object: " + $spnDistinguishedName + " but it does not correspond to service account " + $svcAccountDistinguishedName
                $testResult.Output = @{$farmSPNKey = $farmSPN; $serviceAccountKey = $adfsServiceAccount; $spnObjKey = $spnResults[0].Properties.distinguishedname}
                return $testResult
            }
        }
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestServiceAccountProperties
{
    $testName = "TestServiceAccountProperties"
    $testResult = New-Object TestResult -ArgumentList ($testName)

    $serviceAcctKey = "AdfsServiceAccount"
    $userAcctCtrlKey = "AdfsServiceAccountUserAccountControl"
    $acctDisabledKey = "AdfsServiceAccountDisabled"
    $acctPwdExpKey = "AdfsServiceAccountPwdExpired"
    $acctLockedKey = "AdfsServiceAccountLockedOut"

    $testResult.Output = @{`
            $serviceAcctKey  = $none; `
            $userAcctCtrlKey = $none; `
            $acctDisabledKey = $none; `
            $acctPwdExpKey   = $none; `
            $acctLockedKey   = $none
    }

    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }

        $Adfssrv = get-wmiobject win32_service | where {$_.Name -eq "adfssrv"}
        $UserName = ((($Adfssrv.StartName).Split("\"))[1]).ToUpper()
        $testResult.Output.Set_Item($serviceAcctKey, $Adfssrv.StartName)
        if (($UserName -ne "NETWORKSERVICE") -or ($UserName -ne "NETWORK SERVICE"))
        {
            $searcher = new-object DirectoryServices.DirectorySearcher([ADSI]"")
            $searcher.filter = "(&(objectClass=user)(sAMAccountName=$UserName))"
            $founduser = $searcher.findOne()
            if (-not $founduser)
            {
                $testResult.Result = [ResultType]::Fail
                $testResult.Detail = "Adfs Service Account: " + $Adfssrv.StartName + "`nNot found in Active Directory"
                return $testResult
            }
            if (-not $founduser.psbase.properties.useraccountcontrol)
            {
                $testResult.Result = [ResultType]::Fail
                $testResult.Detail = "Adfs Service Account: " + $Adfssrv.StartName + "`nHas no useraccountcontrol property"
                return $testResult
            }
            $testResult.Output.Set_Item($userAcctCtrlKey, $founduser.psbase.properties.useraccountcontrol[0])

            $accountDisabled = $founduser.psbase.properties.useraccountcontrol[0] -band 0x02
            $testResult.Output.Set_Item($acctDisabledKey, $accountDisabled)

            $pwExpired = $founduser.psbase.properties.useraccountcontrol[0] -band 0x800000
            $testResult.Output.Set_Item($acctPwdExpKey, $pwExpired)

            $accountLockedOut = $founduser.psbase.properties.useraccountcontrol[0] -band 0x0010
            $testResult.Output.Set_Item($acctLockedKey, $accountLockedOut)

            if ($accountDisabled -or $pwExpired -or $accountLockedOut)
            {
                $accountEnabled = -not $accountDisabled
                $testResult.Result = [ResultType]::Fail
                $testResult.Detail = "Adfs Service Account: " + $Adfssrv.StartName + "`nPassword Expired:$pwExpired`nAccount Enabled: $accountEnabled`nAccount Locked Out: $accountLockedOut"
                return $testResult
            }
            $testResult.Result = [ResultType]::Pass
            return $testResult
        }
        else
        {
            $testResult.Result = [ResultType]::NotRun
            $testResult.Detail = "ADFS Service Account: " + $Adfssrv.StartName
            return $testResult
        }
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestAppPoolIDMatchesServiceID()
{
    $adfsVersion = Get-AdfsVersion
    $testName = "TestAppPoolIDMatchesServiceID"
    $testResult = New-Object TestResult -ArgumentList ($testName)
    $pipelineModeKey = "AdfsAppPoolPipelineMode"

    if ($adfsVersion -ne $adfs2x)
    {
        $testResult.Result = [ResultType]::NotRun
        $testResult.Detail = "Test only to be run on ADFS 2.0"
        return $testResult
    }

    try
    {
        Push-Location $env:windir\system32\inetsrv -ErrorAction SilentlyContinue
        $PipelineMode = .\appcmd list apppool adfsapppool /text:pipelinemode
        $testResult.Output = @{$pipelineModeKey = $PipelineMode}
        If ($PipelineMode.ToUpper() -eq "INTEGRATED")
        {
            $testResult.Result = [ResultType]::Pass
            return $testResult
        }
        $testResult.Result = [ResultType]::Fail
        $testResult.Detail = "Adfs Pipelinemode: " + $PipelineMode
        return $testResult
    }
    catch [System.Management.Automation.CommandNotFoundException]
    {
        $testResult.Result = [ResultType]::NotRun
        $errStr = "Could not execute appcmd.exe because it could not be found."
        $testResult.Detail = $errStr
        $testResult.ExceptionMessage = $errStr
        return $testResult
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
    finally
    {
        Pop-Location
    }
}

Function TestComputerNameEqFarmName
{
    $testName = "TestComputerNameEqFarmName"
    $testResult = New-Object TestResult -ArgumentList ($testName)
    $farmNameKey = "AdfsFarmName"
    $compNameKey = "ComputerName"

    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }

        $computerName = ($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN).ToUpper()
        $farmName = ((Retrieve-AdfsProperties).HostName).ToUpper()

        $testResult.Output = @{$farmNameKey = $farmName; $compNameKey = $computerName}

        if ($computerName -eq $farmName)
        {
            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = "Computer Name: $computerName`nADFS Farm Name: $farmName"
            return $testResult
        }
        $testResult.Result = [ResultType]::Pass
        return $testResult
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestSSLUsingADFSPort()
{
    $adfsVersion = Get-AdfsVersion
    $testName = "TestSSLUsingADFSPort"
    $testResult = New-Object TestResult -ArgumentList ($testName)

    $sslTpKey = "AdfsSSLCertThumbprint"
    $httpsPortKey = "AdfsHttpsPort"
    $sslBindingsKey = "AdfsSSLBindings"

    $testResult.Output = @{$sslTpKey = $none; $httpsPortKey = $none; $sslBindingsKey = $none}

    try
    {
        if ($adfsVersion -ne $adfs2x)
        {
            $testResult.Result = [ResultType]::NotRun
            $testResult.Detail = "Test only to be run on ADFS 2.0 Machine"
            return $testResult
        }

        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }


        $httpsPort = (Retrieve-AdfsProperties).HttpsPort

        $sslBinding = GetSslBinding
        $AdfsCertThumbprint = $sslBinding.Thumbprint

        $SSLPortMatch = get-webbinding | where-object {$_.certificateHash -eq $AdfsCertThumbprint} | where-object {$_.bindingInformation.Contains($httpsPort)}
        $SSLPortMatchStrs = @()
        $SSLPortMatch | foreach { $strs += $_.ToString() }

        $testResult.Output.Set_Item($sslTpKey, $AdfsCertThumbprint)
        $testResult.Output.Set_Item($httpsPortKey, $httpsPort)

        if (($SSLPortMatch | measure).Count -gt 0)
        {
            $testResult.Output.Set_Item($sslBindingsKey, $SSLPortMatchStrs)
            $sslMatches = "SSL Port Matches:`n"
            foreach ($sslMatch in $sslPortMatch)
            {
                if ($sslMatch.ItemXPath.Contains("Default Web Site"))
                {
                    $testResult.Result = [ResultType]::Pass
                    return $testResult
                }
                $sslPortMatch += $sslMatch.ItemXPath.Split("'")[1] + "`n"
            }
            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = "SSL Binding with certificate with Thumbprint: $AdfsCertThumbprint and Port: $httpsPort`n" + $sslMatches
            return $testResult
        }
        else
        {
            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = "No SSL Binding for Certificate with Thumbprint: $AdfsCertThumbprint and Port: $httpsPort"
            return $testResult
        }
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestSSLCertSubjectContainsADFSFarmName()
{
    $adfsVersion = Get-AdfsVersion
    $testName = "TestSSLCertSubjectContainsADFSFarmName"
    $testResult = New-Object TestResult -ArgumentList ($testName)
    $farmNameKey = "ADFSFarmName"
    $sslTpKey = "SslCertThumbprints"

    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }

        $sslCertHashes = @()
        switch ($adfsVersion)
        {
            $adfs3
            {
                foreach ($sslCert in (Get-AdfsSslCertificate))
                {
                    if (-not $sslCertHashes.Contains($sslCert.CertificateHash))
                    {
                        $sslCertHashes += $sslCert.CertificateHash
                    }
                }
            }
            $adfs2x
            {
                get-website -name "Default Web Site" | get-webbinding | where {-not [String]::IsNullOrEmpty($_.certificateHash)} | foreach { $sslCertHashes += $_.certificateHash}
            }
            default
            {
                $testResult.Result = [ResultType]::NotRun
                $testResult.Detail = "Invalid ADFS Version"
                return $testResult
            }
        }

        $farmName = (Retrieve-AdfsProperties).HostName

        $failureOutput = "ADFS Farm Name: $farmName`n"
        $testResult.Output = @{$farmNameKey = $farmName; $sslTpKey = $sslCertHashes}

        foreach ($thumbprint in $sslCertHashes)
        {
            $certToCheck = (dir Cert:\LocalMachine\My\$thumbprint)
            #check if cert SAN references ADFS Farmname
            # if it has an SAN that does not include the ADFS Farmname
            # fail the check
            $failureOutput += "Thumbprint: $thumbprint`n"
            $failureOutput += "Subject: " + $certToCheck.Subject + "`n"
            $sanExt = $certToCheck.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}
            If (($sanExt | measure-object).Count -gt 0)
            {
                $failureOutput += "SANs:`n"
                $sanObjs = new-object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
                $altNamesStr = [System.Convert]::ToBase64String($sanExt.RawData)
                $sanObjs.InitializeDecode(1, $altNamesStr)
                Foreach ($SAN in $sanObjs.AlternativeNames)
                {
                    $strValue = $SAN.strValue
                    $searchFilter = $strValue -replace "\*", "[\w-]+"
                    $searchFilter = "^" + $searchFilter + "$"
                    if ($farmName -match $searchFilter)
                    {
                        $testResult.Result = [ResultType]::Pass
                        return $testResult
                    }
                    $failureOutput += "  $strValue`n"
                }
            }
            else
            {

                if ($certToCheck.Subject)
                {
                    $searchFilter = $certToCheck.Subject.Split(",=")[1]
                    $searchFilter = $searchFilter -replace "\*", "[\w-]+"
                    $searchFilter = "^" + $searchFilter + "$"
                    if ($farmName -match $searchFilter)
                    {
                        $testResult.Result = [ResultType]::Pass
                        return $testResult
                    }
                }
            }
        }
        $testResult.Result = [ResultType]::Fail
        $testResult.Detail = $failureOutput
        return $testResult
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestAdfsAuditPolicyEnabled
{
    $testName = "TestAdfsAuditPolicyEnabled"
    $testResult = New-Object TestResult -ArgumentList ($testName)

    $auditSettingKey = "MachineAuditPolicy"
    $stsAuditSetting = "StsAuditConfig"

    $testResult.Output = @{`
            $auditSettingKey = $none;
        $stsAuditSetting     = $none;
    }

    try
    {
        $auditPolicy = auditpol /get /subcategory:"{0cce9222-69ae-11d9-bed3-505054503030}" /r | ConvertFrom-Csv
        $auditSetting = $auditPolicy."Inclusion Setting"

        $testResult.Output.Set_Item($auditSettingKey, $auditSetting);

        if ($auditSetting -ne "Success and Failure")
        {
            $testResult.Result = [ResultType]::Fail
            $testResult.Detail = "Audits are not configured for Usage data collection : Expected 'Success and Failure', Actual='$auditSetting'"
        }
        else
        {
            #So far, passing if we have the right policy
            $testResult.Result = [ResultType]::Pass
        }

        #and verify the STS audit setting
        $role = Get-AdfsRole
        if ($role -eq $adfsRoleSTS)
        {
            $adfsSyncSetting = (Get-ADFSSyncProperties).Role
            if (IsAdfsSyncPrimaryRole)
            {
                $audits = (Retrieve-AdfsProperties).LogLevel | where {$_ -like "*Audits"} | Sort-Object

                $auditsStr = ""
                foreach ($audit in $audits)
                {
                    $auditsStr = $auditsStr + $audit + ";"
                }
                $testResult.Output.Set_Item($stsAuditSetting, $auditsStr);

                if ($audits.Count -ne 2)
                {
                    $testResult.Result = [ResultType]::Fail
                    $testResult.Detail = $testResult.Detail + " ADFS Audits are not configured : Expected 'FailureAudits;SuccessAudits', Actual='$auditsStr'"
                }
            }
            else
            {
                #Did not run on a secondary. Cannot make any assertions on whether this part of the test failed or not
                $testResult.Output.Set_Item($stsAuditSetting, "(Cannot get this data from secondary node)");
            }
        }
        else
        {
            #Not run on an STS
            $testResult.Result = [ResultType]::Pass
            $testResult.Output.Set_Item($stsAuditSetting, "N/A");
        }

        return $testResult
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestAdfsRequestToken($retryThreshold = 5, $sleepSeconds = 3)
{
    $testName = "TestAdfsRequestToken"
    $testResult = New-Object TestResult -ArgumentList ($testName)
    $errorKey = "ErrorMessage"
    $testResult.Output = @{$errorKey = "NONE"}

    $targetEndpointUri = ""
    $targetRpId = ""
    try
    {
        $targetRpId = Get-ADFSIdentifier

        if ($targetRpId -eq $null)
        {
            $testResult.Result = [ResultType]::NotRun;
            $testResult.Detail = "Could not find the STS identifier"
            return $testResult
        }

        $targetEndpointUri = Get-FirstEnabledWIAEndpointUri

        if ($targetEndpointUri -eq $null)
        {
            $testResult.Result = [ResultType]::NotRun;
            $testResult.Detail = "No Windows Integrated Endpoints were enabled. No token requested"
            return $testResult
        }
    }
    catch [Exception]
    {
        $testResult.Result = [ResultType]::Fail;
        $testResult.Detail = "Unable to initialize token request. Caught Exception: " + $_.Exception.Message;
        $testResult.Output.Set_Item($errorKey, $_.Exception.Message)
        return $testResult;
    }
    $exceptionDetail = ""
    for ($i = 1; $i -le $retryThreshold; $i++)
    {
        try
        {
            $tokenString = ""
            #attempt to load first the synthetic transactions library, and fallback to the simpler version
            ipmo .\Microsoft.Identity.Health.SyntheticTransactions.dll -ErrorAction SilentlyContinue -ErrorVariable synthTxErrVar
            if ($synthTxErrVar -ne $null)
            {
                [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $sslBinding = GetSslBinding
                $tokenString = Test-AdfsServerToken -FederationServer $sslBinding.HostNamePort -AppliesTo $targetRpId
                $testResult.Result = [ResultType]::Pass;
            }
            else
            {
                $token = Test-AdfsRequestTokenFromSelf -AppliesToRpIdentifier $targetRpId -EndpointUri $targetEndpointUri
                $testResult.Result = [ResultType]::Pass;

                if ($token -is [System.IdentityModel.Tokens.GenericXmlSecurityToken])
                {
                    $xmlToken = $token -as [System.IdentityModel.Tokens.GenericXmlSecurityToken]
                    $tokenString = $xmlToken.TokenXml.OuterXml
                }
                else
                {
                    $tokenString = $token.ToString()
                }
            }
            $testResult.Detail = "Token Received: " + $tokenString + "`nTotal Attempts: $i"
            return $testResult;
        }
        catch [Exception]
        {
            $exceptionDetail = "Attempt: $i`nLatest Exception caught while requesting token: " + $_.Exception.Message + "`n"
            Start-Sleep $sleepSeconds
        }
    }
    $testResult.Result = [ResultType]::Fail;
    $testResult.Detail = $exceptionDetail
    $testResult.Output.Set_Item($errorKey, $exceptionDetail)
    return $testResult;
}

Function TestTrustedDevicesCertificateStore
{
    $testName = "TestTrustedDevicesCertificateStore";
    Out-Verbose "Checking the AdfsTrustedDevices certificate store.";
    $testResult = New-Object TestResult -ArgumentList($testName);

    try
    {
        if ([bool](Get-Item Cert:\LocalMachine).StoreNames["AdfsTrustedDevices"] -ne $true)
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail = "The AdfsTrustedDevices certificate store does not exist.";
        }

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestAdfsPatches
{
    Out-Verbose "Testing for required Windows Server patches for AD FS.";

    $testName = "TestAdfsPatches";
    $patchesOutputKey = "MissingAdfsPatches";
    $testResult = New-Object TestResult -ArgumentList($testName);

    try
    {
        $osVersion = Get-OsVersion;
        Out-Verbose "Detected OS version as $osVersion.";

        if ($osVersion -ne [OSVersion]::WS2012R2)
        {
            Out-Verbose "AD FS patches are only required for Windows Server 2012 R2";
            $testResult.Result = [ResultType]::NotRun;
            return $testResult;
        }

        $patches = @(
            @{"PatchId" = "KB2919355"; "PatchLink" = "https://support.microsoft.com/en-us/help/2919355/"},
            @{"PatchId" = "KB3000850"; "PatchLink" = "https://support.microsoft.com/en-us/help/3000850/"},
            @{"PatchId" = "KB3013769"; "PatchLink" = "https://support.microsoft.com/en-us/help/3013769/"},
            @{"PatchId" = "KB3020773"; "PatchLink" = "https://support.microsoft.com/en-us/help/3020773/"}
        );

        $notinstalled = @();

        foreach ($patch in $patches)
        {
            Out-Verbose "Checking patch $($patch.PatchId)";
            $hotfix = Get-HotFix -Id $patch.PatchId -ErrorAction SilentlyContinue;

            if (!$hotfix)
            {
                Out-Verbose "Could not find the following patch: $($patch.PatchId)";
                $notinstalled += $patch;
            }
        }

        if ($notinstalled.Count -ne 0)
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail = "There were missing patches that are not installed.";
            $testResult.Output = @{$patchesOutputKey = $notinstalled};
        }

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestServicePrincipalName
{
    $testName = "TestServicePrincipalName";
    Out-Verbose "Checking service principal name."

    if (Test-RunningOnAdfsSecondaryServer)
    {
        return Create-NotRunOnSecondaryTestResult $testName
    }

    $testResult = New-Object TestResult -ArgumentList($testName);

    try
    {
        if (IsLocalUser -eq $true)
        {
            $testResult.Result = [ResultType]::NotRun
            $testResult.Detail = "Current user " + $env:USERNAME + " is not a domain account. Cannot execute this test"
            return $testResult
        }

        if (!(IsAdfsServiceRunning))
        {
            $testResult.Result = [ResultType]::NotRun;
            $testResult.Detail = "AD FS service is not running";
            return $testResult;
        }

        $adfsServiceAccount = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).StartName;
        if ([String]::IsNullOrWhiteSpace($adfsServiceAccount))
        {
            throw "ADFS Service account is null or empty. The WMI configuration is in an inconsistent state";
        }

        Out-Verbose "Checking format of ADFS service account. $adfsServiceAccount";
        if (IsUserPrincipalNameFormat($adfsServiceAccount))
        {
            Out-Verbose "Detected UPN format.";
            $serviceSamAccountParts = $adfsServiceAccount.Split('@');
            $serviceSamAccountName = $serviceSamAccountParts[0];
            $serviceAccountDomain = $serviceSamAccountParts[1];
        }
        else
        {
            $serviceAccountParts = $adfsServiceAccount.Split('\\');
            if ($serviceAccountParts.Length -ne 2)
            {
                throw "Unexpected value of the service account $adfsServiceAccount. Expected in DOMAIN\\User format";
            }

            $serviceAccountDomain = $serviceAccountParts[0];
            $serviceSamAccountName = $serviceAccountParts[1];
        }
        Out-Verbose "ADFS service account = $serviceSamAccountName";

        Out-Verbose "Retrieving LDAP path of service account.";
        $svcAccountSearchResults = GetObjectsFromAD -domain $serviceAccountDomain -filter "(samAccountName=$serviceSamAccountName)";
        $ldapPath = $svcAccountSearchResults.Path -Replace "^LDAP://", "";
        Out-Verbose "Service account LDAP path = $ldapPath";

        $farmName = (Retrieve-AdfsProperties).HostName;

        Out-Verbose "Checking existence of HOST SPN";
        $ret = Invoke-Expression "setspn -f -q HOST/$farmName";
        Out-Verbose "SPN query result = $ret";

        if ($ret.Contains("No such SPN found."))
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail = "No such SPN was found for $farmName";

            return $testResult;
        }
        elseif ($ret.Contains("Existing SPN found!") -and !$ret.Contains($ldapPath))
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail = "An existing SPN was found for HOST/$farmName but it did not resolve to the ADFS service account.";

            return $testResult;
        }

        Out-Verbose "Successfully checked HOST SPN.";

        Out-Verbose "Checking existence of HTTP SPN";
        $ret = Invoke-Expression "setspn -f -q HTTP/$farmName";
        Out-Verbose "SPN query result = $ret";

        if ($ret.Contains("No such SPN found."))
        {
            # HTTP does not need to resolve.
            Out-Verbose "Unable to find HTTP SPN, this does not have to resolve.";
            return $testResult;
        }
        elseif ($ret.Contains("Existing SPN found!") -and !$ret.Contains($ldapPath))
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail = "An existing SPN was found for HTTP/$farmName but it did not resolve to the ADFS service account.";

            return $testResult;
        }
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestProxyTrustPropagation
{
    Param(
        [string[]]
        $adfsServers = $null
    )

    $testName = "TestProxyTrustPropagation";
    try
    {
        $testResult = New-Object TestResult -ArgumentList $testName;

        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName;
        }

        if ($adfsServers -eq $null -or $adfsServers.Count -eq 0)
        {
            $testResult.Result = [ResultType]::NotRun;
            $message = "No AD FS farm information was provided. Specify the list of servers in your farm using the -adfsServers flag.";
            Out-Warning $message;
            $testResult.Detail = $message;

            return $testResult;
        }

        Out-Verbose "Verifying that the proxy trust is propogating between the AD FS servers in the farm.";
        Out-Verbose "Farm information: $adfsServers";
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("ADFSTrustedDevices", "LocalMachine");
        $store.open("ReadOnly");

        $certificatesInPrimaryStore = $store.Certificates;

        $ErroneousCertificates = @{};
        foreach ($server in $adfsServers)
        {
            $session = New-PSSession -ComputerName $server -ErrorAction SilentlyContinue;
            if ($session -eq $null)
            {
                Out-Warning "There was a problem connecting to $server, skipping this server."
                continue;
            }
            Out-Verbose "Checking $server";

            $missingCerts = Invoke-Command -Session $session -ArgumentList @(, $certificatesInPrimaryStore) -ScriptBlock {
                param(
                    $certificatesInPrimaryStore
                )

                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("ADFSTrustedDevices", "LocalMachine");
                $store.open("ReadOnly");
                $certificatesInStore = $store.Certificates;
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

            if ($missingCerts.Count -ne 0)
            {
                $ErroneousCertificates.Add($server, $missingCerts);
            }

            if ($session)
            {
                Remove-PSSession $Session
            }
        }

        if ($ErroneousCertificates.Count -ne 0)
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail = "There were missing certificates on some of the secondary servers. There may be an issue with proxy trust propogation."
            $testResult.Output = @{"ErroneousCertificates" = $ErroneousCertificates};
        }

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception;
    }
}

# Check office 365 endpoints
Function TestOffice365Endpoints()
{
    $testName = "CheckOffice365Endpoints"

    #Keys for strongly typed Result data
    $wstrustUsernameKey = "WSTrust2005UsernameMixedEnabled"
    $wsTrustUsernameProxyKey = "WSTrust2005UsernameMixedProxyEnabled"
    $wsTrustWindowsKey = "WSTrust2005WindowsTransportEnabled"
    $wsTrustWindowsProxyKey = "WSTrust2005WindowsTransportProxyEnabled"
    $passiveKey = "PassiveEnabled"
    $passiveProxyKey = "PassiveProxyEnabled"

    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }

        $lyncEndpointsTestResult = New-Object TestResult -ArgumentList($testName);

        $isAdfsServiceRunning = IsAdfsServiceRunning

        if ($isAdfsServiceRunning -eq $false)
        {
            $lyncEndpointsTestResult.Result = [ResultType]::NotRun;
            $lyncEndpointsTestResult.Detail = "AD FS service is not running";
            return $lyncEndpointsTestResult;
        }

        $adfsProperties = Retrieve-AdfsProperties
        if ( $null -eq $adfsProperties )
        {
            $lyncEndpointsTestResult.Result = [ResultType]::Fail;
            $lyncEndpointsTestResult.Detail = "Unable to read adfs properties";
            return $lyncEndpointsTestResult;
        }

        $wstrust2005windowstransport = Get-AdfsEndpoint -AddressPath /adfs/services/trust/2005/windowstransport;
        $wstrust2005usernamemixed = Get-AdfsEndpoint -AddressPath /adfs/services/trust/2005/usernamemixed;
        $passive = Get-AdfsEndpoint -AddressPath /adfs/ls/;


        if ($wstrust2005windowstransport.Enabled -eq $false -or $wstrust2005windowstransport.Proxy -eq $false)
        {
            $lyncEndpointsTestResult.Result = [ResultType]::Fail;
            $lyncEndpointsTestResult.Detail = "Lync related endpoint is not configured properly; extranet users can experience authentication failure.`n";
        }

        if ($wstrust2005usernamemixed.Enabled -eq $false -or $wstrust2005usernamemixed.Proxy -eq $false)
        {
            $lyncEndpointsTestResult.Result = [ResultType]::Fail;
            $lyncEndpointsTestResult.Detail += "Exchange Online related endpoint is not enabled. This will prevent rich clients such as Outlook to connect.`n";
        }

        if ($passive.Enabled -eq $false)
        {
            $lyncEndpointsTestResult.Result = [ResultType]::Fail;
            $lyncEndpointsTestResult.Detail += "Passive endpoint is not enabled. This will prevent browser-based services such as Sharepoint Online or OWA to fail.`n";
        }

        if ($lyncEndpointsTestResult.Result -eq [ResultType]::Fail)
        {
            $lyncEndpointsTestResult.Detail += "Endpoint Status:`n" `
                + $wstrust2005usernamemixed.AddressPath + "`n  Enabled: " + $wstrust2005usernamemixed.Enabled + "`n  Proxy Enabled: " + $wstrust2005usernamemixed.Proxy + "`n" `
                + $wstrust2005windowstransport.AddressPath + "`n  Enabled: " + $wstrust2005windowstransport.Enabled + "`n  Proxy Enabled: " + $wstrust2005windowstransport.Proxy + "`n" `
                + $passive.AddressPath + "`n  Enabled: " + $passive.Enabled + "`n  Proxy Enabled: " + $passive.Proxy + "`n";
        }
        $lyncEndpointsTestResult.Output = @{`
                $wstrustUsernameKey      = $wstrust2005usernamemixed.Enabled; `
                $wsTrustUsernameProxyKey = $wstrust2005usernamemixed.Proxy; `
                $wsTrustWindowsKey       = $wstrust2005windowstransport.Enabled; `
                $wsTrustWindowsProxyKey  = $wstrust2005windowstransport.Proxy; `
                $passiveKey              = $passive.Enabled; `
                $passiveProxyKey         = $passive.Proxy
        }

        return $lyncEndpointsTestResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }

}

Function TestADFSO365RelyingParty
{
    $testName = "TestADFSO365RelyingParty"
    $aadRpId = "urn:federation:MicrosoftOnline"

    $rpIdKey = "MicrosoftOnlineRPID"
    $rpNameKey = "MicrosoftOnlineRPDisplayName"
    $rpEnabledKey = "MicrosoftOnlineRPEnabled"
    $rpSignAlgKey = "MicrosoftOnlineRPSignatureAlgorithm"

    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }

        $testResult = New-Object TestResult -ArgumentList ($testName)
        $testResult.Output = @{`
                $rpIdKey      = $aadRpId ; `
                $rpNameKey    = $none ; `
                $rpEnabledKey = $none ; `
                $rpSignAlgKey = $none
        }

        $isAdfsServiceRunning = IsAdfsServiceRunning

        if ($isAdfsServiceRunning -eq $false)
        {
            $testResult.Result = [ResultType]::NotRun;
            $testResult.Detail = "AD FS service is not running";
            return $testResult;
        }
        $aadRpName = "Microsoft Office 365 Identity Platform"

        $aadRp = Get-ADFSRelyingPartyTrust -Identifier $aadRpId

        if ($aadRp -eq $null)
        {
            $testResult.Result = [ResultType]::NotRun;
            $testResult.Detail = $aadRpName + "Relying Party trust is missing`n";
            $testResult.Detail += "Expected Relying Party Identifier: " + $aadRpId;
            return $testResult;
        }

        $aadRpDetail = $false
        $testPassed = $true
        $testResult.Detail = ""
        if (-not $aadRp.Enabled)
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail += $aadRpName + " Relying Party trust is disabled`n"
            $testResult.Detail += "Relying Party Trust Display Name: " + $aadRp.Name + "`n";
            $testResult.Detail += "Relying Party Trust Identifier: " + $aadRp.Identifier + "`n";
            $aadRpDetail = $true
            $testPassed = $false
        }

        if ($aadRp.SignatureAlgorithm -ne "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        {
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail += $aadRpName + " Relying Party token signature algorithm is not SHA-256`n";
            if (-not $aadRpDetail)
            {
                $testResult.Detail += "Relying Party Trust Display Name: " + $aadRp.Name + "`n";
                $testResult.Detail += "Relying Party Trust Identifier: " + $aadRp.Identifier + "`n";
            }
            $testResult.Detail += "Relying Party Trust Signature Algorithm: " + $aadRp.SignatureAlgorithm;
            $testPassed = $false
        }

        if ($testPassed)
        {
            $testResult.Result = [ResultType]::Pass
        }
        $testResult.Output.Set_Item($rpNameKey, $aadRp.Name)
        $testResult.Output.Set_Item($rpEnabledKey, $aadRp.Enabled)
        $testResult.Output.Set_Item($rpSignAlgKey, $aadRp.SignatureAlgorithm)

        return $testResult
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestNtlmOnlySupportedClientAtProxyEnabled
{
    $testName = "TestNtlmOnlySupportedClientAtProxyEnabled"
    $outputKey = "NtlmOnlySupportedClientAtProxy"
    try
    {
        if (Test-RunningOnAdfsSecondaryServer)
        {
            return Create-NotRunOnSecondaryTestResult $testName
        }

        $ntlmClientTestResult = New-Object TestResult -ArgumentList($testName);
        $isAdfsServiceRunning = IsAdfsServiceRunning

        if ($isAdfsServiceRunning -eq $false)
        {
            $ntlmClientTestResult.Result = [ResultType]::NotRun;
            $ntlmClientTestResult.Detail = "AD FS service is not running";
            return $ntlmClientTestResult;
        }

        $adfsProperties = Retrieve-AdfsProperties
        if ( $null -eq $adfsProperties )
        {
            $ntlmClientTestResult.Result = [ResultType]::Fail;
            $ntlmClientTestResult.Detail = "Unable to read adfs properties";
            $ntlmClientTestResult.Output = @{$outputKey = "NONE"}
            return $ntlmClientTestResult;
        }

        if ($adfsProperties.NtlmOnlySupportedClientAtProxy -eq $false)
        {
            $ntlmClientTestResult.Result = [ResultType]::Fail;
            $ntlmClientTestResult.Detail = "NtlmOnlySupportedClientAtProxy is disabled; extranet users can experience authentication failure.`n";
        }
        $ntlmClientTestResult.Output = @{$outputKey = $adfsProperties.NtlmOnlySupportedClientAtProxy}
        return $ntlmClientTestResult
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}
