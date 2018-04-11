# ADFS Service State
Function TestIsAdfsRunning()
{
    $testName = "IsAdfsRunning"
    $serviceStateOutputKey = "ADFSServiceState"
    try
    {
        $adfsServiceStateTestResult = New-Object TestResult -ArgumentList($testName);
        $adfsServiceState = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).State
        If ($adfsServiceState -ne "Running")
        {
            $adfsServiceStateTestResult.Result = [ResultType]::Fail;
            $adfsServiceStateTestResult.Detail = "Current State of adfssrv is: $adfsServiceState";
        }
        $adfsServiceStateTestResult.Output = @{$serviceStateOutputKey = $adfsServiceState}

        return $adfsServiceStateTestResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception
    }
}

Function TestTLSMismatch
{
    $testName = "TestTLSMismatch";

    try
    {
        $testResult = New-Object TestResult -ArgumentList ($testName)

        $tls10Enabled = IsTlsVersionEnabled("1.0");
        $tls11Enabled = IsTlsVersionEnabled("1.1");
        $tls12Enabled = IsTlsVersionEnabled("1.2");

        # If all TLS versions are enabled then there shouldn't be a mismatch between ADFS and WAP.
        if ($tls10Enabled -and $tls11Enabled -and $tls12Enabled)
        {
            return $testResult;
        }

        $str = "{0}{1}{2}" -f [int]$tls10Enabled, [int]$tls11Enabled, [int]$tls12Enabled;
        switch ($str)
        {
            "000"
            {
                Out-Verbose "All TLS versions are disabled"
                $testResult.Result = [ResultType]::Fail;
                $testResult.Detail = "Detected that all TLS versions are disabled. This will cause problems between your STS and Proxy servers. Fix this by enabling the correct TLS version.";
            }
            "001"
            {
                $message = "Detected that only TLS 1.2 is enabled. Ensure that this is also enabled on your other STS and Proxy servers.";
                Out-Warning $message;
                $testResult.Detail = $message;
                $testResult.Result = [ResultType]::Warning;
            }
            "010"
            {
                $message = "Detected that only TLS 1.1 is enabled. Ensure that this is also enabled on your other STS and Proxy servers.";
                Out-Warning $message;
                $testResult.Detail = $message;
                $testResult.Result = [ResultType]::Warning;
            }
            "100"
            {
                $message = "Detected that only TLS 1.0 is enabled. Ensure that this is also enabled on your other STS and Proxy servers.";
                Out-Warning $message;
                $testResult.Detail = $message;
                $testResult.Result = [ResultType]::Warning;
            }
        }

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception;
    }
}

Function TestAdfsEventLogs
{
    $testName = "TestAdfsEventLogs";
    Out-Verbose "Running test to check event logs for event ids known to be associated with WAP issues."
    try
    {
        $testResult = New-Object TestResult -ArgumentList ($testName);

        $adfsVersion = Get-AdfsVersion;
        if($adfsVersion -eq $null)
        {
            throw "Unable to determine AD FS version."
        }

        $pastPeriod = (Get-Date).AddDays(-7);

        if ($adfsVersion -eq $adfs2x)
        {
            $logName = "AD FS 2.0/Admin";
        }
        else
        {
            $logName = "AD FS/Admin";
        }

        Out-Verbose "Event log name = $logName";
        $role = Get-AdfsRole;
        switch ($role)
        {
            $adfsRoleSTS
            {
                # These are the event IDs for events on AD FS that are known to be related to WAP problems.
                $id = @(276);
            }
            $adfsRoleProxy
            {
                # These are the event IDs for events on WAP that are known to be related to WAP problems.
                $id = @(224, 393, 394);
            }
            default
            {
                throw "Unable to determine server role."
            }
        }

        Out-Verbose "Checking event IDs = $id";

        $events = Get-WinEvent -FilterHashTable @{LogName = $logName; StartTime = $pastPeriod; ID = $id} -ErrorAction SilentlyContinue;

        if ($events -ne $null -and $events.Count -ne 0)
        {
            Out-Verbose "Found events that indicate a problem with WAP and AD FS."
            $testResult.Result = [ResultType]::Fail;
            $testResult.Detail = "There were events found in the AD FS event logs that may be causing issues with the AD FS and WAP trust. Check the output for more details."
            $testResult.Output = @{"Events" = $events};
        }

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception;
    }
}

Function TestTimeSync
{
    Param(
        [string[]]
        $adfsServers = $null
    )

    Out-Verbose "Checking time synchronization."
    $testName = "TestTimeSync";

    try
    {
        $testResult = New-Object TestResult -ArgumentList ($testName);

        if (Test-RunningRemotely)
        {
            $testResult.Detail = "This test does not need to run remotely.";
            $testResult.Result = [ResultType]::NotRun;
            return $testResult;
        }

        $role = Get-AdfsRole;
        switch ($role)
        {
            $adfsRoleSTS
            {
                Out-Verbose "Detected that the current server is an ADFS server.";

                if ($adfsServers -eq $null -or $adfsServers.Count -eq 0)
                {
                    Out-Verbose "No farm information was provided. Only checking time synchronization with the local server and reliable time server."

                    if (!(IsServerTimeInSyncWithReliableTimeServer))
                    {
                        $testResult.Result = [ResultType]::Fail;
                        $testResult.Detail = "This server's time is out of sync with reliable time server. Check and correct any time synchronization issues."
                    }
                }
                else
                {
                    Out-Verbose "Detected that farm information was available, checking time synchronization across multiple servers.";
                    $serversNotInSync = @();

                    Out-Verbose "Checking localhost";
                    if (!(IsServerTimeInSyncWithReliableTimeServer))
                    {
                        $serversNotInSync += "Localhost";
                    }

                    foreach ($server in $adfsServers)
                    {
                        $session = New-PSSession -ComputerName $server -ErrorAction SilentlyContinue;
                        if ($session -eq $null)
                        {
                            Out-Warning "There was a problem connecting to $server, skipping this server."
                            continue;
                        }

                        Out-Verbose "Checking $server";

                        $Private = @(Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue);

                        $commonFunctions = (Get-Command $Private).ScriptContents;
                        $commonFunctions = $commonFunctions -join [Environment]::NewLine;

                        $isInSync = Invoke-Command -Session $session -ArgumentList $commonFunctions -ScriptBlock {
                            Param(
                                $commonFunctions
                            )
                            Invoke-Expression $commonFunctions;

                            return IsServerTimeInSyncWithReliableTimeServer;
                        }

                        if (!$isInSync)
                        {
                            $serversNotInSync += $server;
                        }
                    }

                    if ($serversNotInSync.Count -ne 0)
                    {
                        $testResult.Result = [ResultType]::Fail;
                        $testResult.Detail = "Some of the servers in your AD FS farm were out of sync with reliable time server. Check the output for a list of servers."
                        $testResult.Output = @{ "ServersOutOfSync" = $serversNotInSync; }
                    }
                }
            }
            $adfsRoleProxy
            {
                Out-Verbose "Detected that the current server is a WAP server.";

                if (!(IsServerTimeInSyncWithReliableTimeServer))
                {
                    $testResult.Result = [ResultType]::Fail;
                    $testResult.Detail = "This server's time is out of sync with reliable time server. Check and correct any time synchronization issues."
                }
            }
            default
            {
                throw "Unable to determine server role."
            }
        }

        return $testResult;
    }
    catch [Exception]
    {
        return Create-ErrorExceptionTestResult $testName $_.Exception;
    }
}