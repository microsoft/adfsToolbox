<#
.SYNOPSIS
Gathers and exports diagnostic data into a file. This cmdlet is used with the Diagnostics Analyzer Tool on
the AD FS Help website (https://adfshelp.microsoft.com/DiagnosticsAnalyzer).

.DESCRIPTION
The Export-AdfsDiagnosticsFile cmdlet gathers diagnostic data from the current AD FS server and exports the diagnostic file
required for the AD FS Help Diagnostic Analyzer. This cmdlet works on AD FS 2.0 and later.

.PARAMETER FilePath
String parameter that specifies the location of the exported file. By default, a file will be created in the current folder.

.PARAMETER VerifyTrustCerts
Boolean parameter that will enable additional checks for relying party trust and claims provider trust certificates. It is false by default.

.PARAMETER SslThumbprint
String parameter that corresponds to the thumbprint of the AD FS SSL certificate. This is required for running test cases on proxy servers.

.PARAMETER AdfsServers
Array of fully qualified domain names (FQDN) of all of the AD FS STS servers that you want to run health checks on. For Windows Server 2016 this is automatically populated using Get-AdfsFarmInformation.
By default the tests are already run on the local machine, so it is not necessary include the FQDN of the current machine in this parameter.

.PARAMETER Local
Switch that indicates that you only want to run the health checks on the local machine. This takes precedence over -AdfsServers parameter.

.EXAMPLE
Export-AdfsDiagnosticsFile -verifyTrustCerts:$true
Export a diagnostic file of an AD FS Farm and examine the relying party trust and claims provider trust certificates.

.EXAMPLE
Export-AdfsDiagnosticsFile -adfsServers  @("sts1.contoso.com", "sts2.contoso.com", "sts3.contoso.com")
Export a diagnostic file of an AD FS farm by running checks on the following servers: sts1.contoso.com, sts2.contoso.com, sts3.contoso.com. This automatically runs the test on the local machine as well.

.EXAMPLE
Export-AdfsDiagnosticsFile -sslThumbprint ‎c1994504c91dfef663b5ce8dd22d1a44748a6e16
Export a diagnostic file of a WAP server and utilize the provided thumbprint to check SSL bindings.
#>


# the final output format is as follows (in JSON):
# diagnosticData:
#   { module1: { cmdlet1.1: results, cmdlet1.2: results, ...},
#       module2: { cmdlet2.1: results, ...}
#       ...
#   }
# where results will be the desired output or an exception message.
Function Export-AdfsDiagnosticsFile()
{
    # aggregate parameters for all cmdlets
    [CmdletBinding()]
    Param
    (
        [string]    $filePath = $null,
        [switch]    $includeTrusts = $false,
        [string]    $sslThumbprint = $null,
        [string[]]  $adfsServers = $null,
        [switch]    $local = $null
    )

    # generate filePath at current folder if filePath is not provided by user
    if (!$filePath)
    {
        $filePath= -join("ADFSDiagnosticsFile-", (Get-Date -UFormat %Y%m%d%H%M%S), ".json")
    }

    # create file if the file doesn't exist
    if (!(Test-Path -Path $filePath))
    {
        Out-Verbose "Creating file $filePath"
        New-Item $filePath -ItemType "file" > $null
    }

    $filePath = (Resolve-Path -Path $filePath).Path

    # run the private JSON generator for diagnostic data
    $JSONDiagnosticData = GenerateJSONDiagnosticData -includeTrusts:$includeTrusts -sslThumbprint $sslThumbprint -adfsServers $adfsServers -local:$local;

    Out-Verbose "Outputting diagnostic data at $filePath"
    Out-File -FilePath $filePath -InputObject $JSONDiagnosticData -Encoding ascii

    # print message for the user to find the file
    Write-Host "Please upload the diagnostic file located at $filePath to https://adfshelp.microsoft.com/DiagnosticsAnalyzer/Analyze."
}
