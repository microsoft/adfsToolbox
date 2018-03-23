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