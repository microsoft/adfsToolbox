#Requires –Version 4
#Requires -RunAsAdministrator 

<# 
 
.SYNOPSIS
	Contains data gathering, health checks, and additional utilities for AD FS server deployments.

.DESCRIPTION

	Version: 1.0.0

	ADFSDiagnostics.psm1 is a Windows PowerShell module for diagnosing issues with ADFS


.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>

####################################
# TestResult Data type
####################################
Add-Type -AssemblyName System.Web;
Add-Type -AssemblyName System.Collections;

Add-Type -Language CSharp @"
public class TestResult
{
	public string Name;
	public ResultType Result;
	public string Detail;
    public System.Collections.Hashtable Output;
	public string ExceptionMessage;
	
	public TestResult(string name)
	{
		Name = name;
		Result = ResultType.Pass;
	}
	
}

public enum ResultType
{
	Pass = 0,
	Fail = 1,
	NotRun = 2
}

"@;

####################################
# AdHealthAgentInformation Data type
####################################

Add-Type -Language CSharp @"
public class AdHealthAgentInformation
{
	public string Version;
	public string UpdateState;
	public string LastUpdateAttemptVersion;
	public System.DateTime LastUpdateAttemptTime;
	public int NumberOfFailedAttempts;
	public string InstallerExitCode;
} 

"@;

####################################
# Constants
####################################
$adfs3 = "3.0"
$adfs2x = "2.0"
$tpKey = "Thumbprint"
$sslCertType = "SSL"

$none = "NONE"
$script:adfsProperties = $null 

$AdHealthAgentRegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\AdHealthAgent"
#reference: Microsoft.Agent.Health.AgentUpdater
Add-Type -Language CSharp @"
public static class RegistryValueName
{
	public const string TemporaryUpdaterLogPath = "TemporaryUpdaterLogPath";
	public const string NumberOfFailedAttempts = "NumFailedAttempts";
	public const string LastUpdateAttempt = "LastUpdateAttempt";
	public const string LastUpdateAttemptReadable = "LastUpdateAttemptReadable";
	public const string VersionOfUpdate = "UpdateVersion";
	public const string UpdateState = "UpdateState";
	public const string InstallerExitCode = "InstallerExitCode";
	public const string CurrentVersion = "Version";
}
"@;


####################################
# Utility Functions
####################################

$script:isAdfsSyncPrimaryRole = $null

Function IsAdfsSyncPrimaryRole([switch] $force)
{
    if ((IsAdfsServiceRunning) -and (-not $script:adfsSyncRole -or $force))
	{
        try
        {
            $stsrole =  Get-ADFSSyncProperties | Select-Object -ExpandProperty Role
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

# To prevent tests from attempting to execute on Secondary servers
# usage pattern:
# if (Test-RunningOnAdfsSecondaryServer)
# {
	# return Create-NotRunOnSecondaryTestResult $testName
# }

Function Test-RunningOnAdfsSecondaryServer
{
	return -not (IsAdfsSyncPrimaryRole)
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

Function Create-NotRunExceptionTestResult
{
	param(
		[string]
		$testName,
		[string]
		$exceptionMessage
	)
	$testResult= New-Object TestResult -ArgumentList($testName);
	$testResult.Result = [ResultType]::NotRun;
	$testResult.Detail = $exceptionMessage;
	$testResult.ExceptionMessage = $exceptionMessage
	return $testResult;
}

# TODO : Handle Non-English cultures

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

#for testability
$testMode = $false
Function Set-ADFSDiagTestMode
{
	$testMode = $true
}
####################
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

####################################
# Test Checks
####################################
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
		$testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
	}
}

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
			$adfsConfigurationDbTestResult.Output = @{$serviceStateKey = $widServiceState; $serviceStartModeKey=$widService.StartMode}
			return $adfsConfigurationDbTestResult;
		}
   }
   catch [Exception] 
   {
		$testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
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
		$fedmetadataUrl = "https://"+ $sslBinding.HostNamePort + "/federationmetadata/2007-06/federationmetadata.xml";
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
		$testResult= New-Object TestResult -ArgumentList ($testName)
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
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
		
		$mexUrl = "https://"+ $stsHost + "/adfs/services/trust/mex";
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
		$testResult= New-Object TestResult -ArgumentList ($testName)
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
   }

	
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
			$wstrustUsernameKey = $wstrust2005usernamemixed.Enabled;`
			$wsTrustUsernameProxyKey = $wstrust2005usernamemixed.Proxy;`
			$wsTrustWindowsKey = $wstrust2005windowstransport.Enabled;`
			$wsTrustWindowsProxyKey = $wstrust2005windowstransport.Proxy;`
			$passiveKey = $passive.Enabled;`
			$passiveProxyKey = $passive.Proxy}
		
		return $lyncEndpointsTestResult;
   }
   catch [Exception] 
   {
		$testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
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
		
		if($adfsProperties.NtlmOnlySupportedClientAtProxy -eq $false)
		{
			$ntlmClientTestResult.Result = [ResultType]::Fail;
			$ntlmClientTestResult.Detail = "NtlmOnlySupportedClientAtProxy is disabled; extranet users can experience authentication failure.`n";
		}
		$ntlmClientTestResult.Output = @{$outputKey = $adfsProperties.NtlmOnlySupportedClientAtProxy}
		return $ntlmClientTestResult
   }
   catch [Exception] 
   {
		$testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
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
        $portRegExp = "^.*" + ":" + $httpsPort.ToString()+ "$";

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
            $thumbprint =""
            $thumbprintBytes | %{ $thumbprint = $thumbprint + $_.ToString("X2"); }

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

##################################
# Certificate Checks Section
##################################

####################
# Certificate Utility Function Section
####################

Function Create-CertCheckName
{
	param(
		[string]
		$certType,
		[string]
		$checkName,
		[bool]
		$isPrimary = $true
	)
	
	$primaryOrSecondary = "Secondary"
	if ($isPrimary)
	{
		$primaryOrSecondary = "Primary"
	}
	return "Test-Certificate-{0}-{1}-{2}" -f $certType, $primaryOrSecondary, $checkName
}

Function Create-CertificateCheckResult
{
	param (
		[System.Security.Cryptography.X509Certificates.X509Certificate2] 
		$cert,
		[string] 
		$testName,
		[ResultType]
		$result,
		[Parameter(Mandatory=$false)]
		[string]
		$detail = $null
	)
	
	$testResult = New-Object TestResult -ArgumentList($testName)
	$testResult.Result = $result
	$testResult.Detail = $detail
	if ($cert)
	{
		$testResult.Output = @{$tpKey = $cert.Thumbprint}
	}
	return $testResult
}

function Verify-IsCertExpired 
{
	param (
		[System.Security.Cryptography.X509Certificates.X509Certificate2] 
		$cert
	)
	
	return ($cert.NotAfter - (Get-Date)).TotalDays -le 0
}

function Verify-IsCertSelfSigned
{
	param (
		[System.Security.Cryptography.X509Certificates.X509Certificate2] 
		$cert
	)

	return $cert.Subject -eq $cert.IssuerName.Name
}

function Generate-NotRunResults
{
	param(
		[string]
		$certificateType,
		[string]
		$notRunReason,
		[bool]
		$isPrimary = $true
	)
	
	$results = @()
	
	$results += Test-CertificateAvailable -adfsCertificate $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason
	$results += Test-CertificateSelfSigned -cert $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason
	$results += Test-CertificateHasPrivateKey -cert $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason -storeName "" -storeLocation ""
	$results += Test-CertificateExpired -cert $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason
	$results += Test-CertificateCRL -cert $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason
	$results += Test-CertificateAboutToExpire -cert $null -certificateType $certType -isPrimary $isPrimary -notRunReason $notRunReason

	return $results
}

Function Get-AdfsCertificateList([switch] $RemovePrivateKey)
{
    $adfsCertificateCollection = @()

    $adfsTokenCerts = Get-AdfsCertificate

    foreach($adfsTokenCert in $adfsTokenCerts)
    {
        $certToAdd = new-Object PSObject
		if ($RemovePrivateKey)
		{
			$tokenCert = GetNormalizedCert $adfsTokenCert.Certificate
        }
		else
		{
			$tokenCert = $adfsTokenCert.Certificate
		}
		$certToAdd | Add-Member -NotePropertyName "Certificate" -NotePropertyValue $tokenCert
        $certToAdd | Add-Member -NotePropertyName "CertificateType" -NotePropertyValue $adfsTokenCert.CertificateType
        $certToAdd | Add-Member -NotePropertyName "IsPrimary" -NotePropertyValue $adfsTokenCert.IsPrimary
        $certToAdd | Add-Member -NotePropertyName "StoreName" -NotePropertyValue $adfsTokenCert.StoreName
        $certToAdd | Add-Member -NotePropertyName "StoreLocation" -NotePropertyValue $adfsTokenCert.StoreLocation
        $certToAdd | Add-Member -NotePropertyName "Thumbprint" -NotePropertyValue $adfsTokenCert.Thumbprint
        $adfsCertificateCollection += $certToAdd
    }

    $adfsSslBinding = GetSslBinding
    $sslCertToAdd = new-Object PSObject
	if ($RemovePrivateKey)
	{
		$sslCert = GetNormalizedCert $adfsSslBinding.Certificate
    }
	else
	{
		$sslCert = $adfsSslBinding.Certificate
	}
	$sslCertToAdd | Add-Member -NotePropertyName "Certificate" -NotePropertyValue $sslCert
    $sslCertToAdd | Add-Member -NotePropertyName "CertificateType" -NotePropertyValue "SSL"
    $sslCertToAdd | Add-Member -NotePropertyName "IsPrimary" -NotePropertyValue $true
    $sslCertToAdd | Add-Member -NotePropertyName "StoreName" -NotePropertyValue ([System.Security.Cryptography.X509Certificates.StoreName]::My)
    $sslCertToAdd | Add-Member -NotePropertyName "StoreLocation" -NotePropertyValue ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $sslCertToAdd | Add-Member -NotePropertyName "Thumbprint" -NotePropertyValue ($adfsSslBinding.Thumbprint)
            
    $adfsCertificateCollection += $sslCertToAdd

    return $adfsCertificateCollection
}

Function Get-AdfsCertificatesToTest()
{

    $endpoints = Get-AdfsEndpoint | where {$_.SecurityMode -eq 'Message' -and $_.Enabled -eq $true -and $_.AddressPath -ne '/adfs/services/trusttcp/windows'}
    $skipCommCert = ($endpoints -eq $null) 

    $adfsCertificateCollection = Get-AdfsCertificateList
     
    if ($skipCommCert)
    {    
         $adfsCertificateCollection = $adfsCertificateCollection | where {$_.CertificateType -ne "Service-Communications"}
    }
	
	return $adfsCertificateCollection
}

####################
# Individual Certificate Checks
####################
Function Test-CertificateAvailable
{
	param(
		$adfsCertificate, # Single element of list Generated by Get-AdfsCertificatesToTest
		[string]
		$certificateType,
		[bool]
		$isPrimary = $true,
		[string]
		$notRunReason
	)
	
	$testName = Create-CertCheckName -certType $certificateType -checkName "NotFoundInStore" -isPrimary $isPrimary

	if (-not $adfsCertificate -and [String]::IsNullOrEmpty($notRunReason))
	{
		$notRunReason = "Certificate object is null."
	}
	
	if (-not [String]::IsNullOrEmpty($notRunReason))
	{
		return Create-CertificateCheckResult -cert $null -testName $testName -result NotRun -detail $notRunReason
	}

	
	try
	{
		$thumbprint = $adfsCertificate.Thumbprint
		$testResult = New-Object TestResult -ArgumentList($testName)
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Output = @{$tpKey = $thumbprint}
		
		if ($adfsCertificate.StoreLocation -eq "LocalMachine")
		{
			$certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($adfsCertificate.StoreName,`
				[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
			try
			{
				$certStore.Open("IncludeArchived")
				
				$certSearchResult = $certStore.Certificates | where {$_.Thumbprint -eq $thumbprint}
				if (($certSearchResult | measure).Count -eq 0)
				{
					$testResult.Detail = "$certificateType certificate with thumbprint $thumbprint not found in LocalMachine\{0} store.`n" -f $adfsCertificate.StoreName
					$testResult.Result = [ResultType]::Fail
				}
				else
				{
					$testResult.Result = [ResultType]::Pass
				}
			}
			catch
			{
				$testResult.Result = [ResultType]:: NotRun;
				$testResult.Detail = "$certificateType certificate with thumbprint $thumbprint encountered exception with message`n" + $_.Exception.Message
			}
			finally
			{
				$certStore.Close()
			}
		}
		else
		{
			$testResult.Result = [ResultType]:: NotRun;
			$testResult.Detail = "$certificateType certificate with thumbprint $thumbprint not checked for availability because it is in store: " + $adfsCertificate.StoreLocation
		}
		
		return $testResult
	}
	catch [Exception]
	{
		return Create-NotRunExceptionTestResult $testName $_.Exception.Message
	}
}

function Test-CertificateExpired
{
	param (
		[System.Security.Cryptography.X509Certificates.X509Certificate2] 
		$cert,
		[string]
		$certificateType,
		[bool]
		$isPrimary = $true,
		[string]
		$notRunReason
	)
	
	$checkName = "Expired"
	
	$testName = Create-CertCheckName -certType $certificateType -checkName $checkName -isPrimary $isPrimary
	
	if (-not $cert -and [String]::IsNullOrEmpty($notRunReason))
	{
		$notRunReason = "Certificate object is null."
	}
	if (-not [String]::IsNullOrEmpty($notRunReason))
	{
		return Create-CertificateCheckResult -cert $null -testName $testName -result NotRun -detail $notRunReason
	}
	
	try
	{
		if (Verify-IsCertExpired -cert $cert)
		{
			$tp = $cert.Thumbprint

			$certificateExpiredTestDetail = "$certificateType certificate with thumbprint $tp has expired.`n";
			$certificateExpiredTestDetail += "Valid From: " + $cert.NotBefore.ToString() + "`nValid To: " + $cert.NotAfter.ToString();
			$certificateExpiredTestDetail += "`nAutoCertificateRollover Enabled: " + (Retrieve-AdfsProperties).AutoCertificateRollover + "`n";
			return Create-CertificateCheckResult -cert $cert -testName $testName -result Fail -detail $certificateExpiredTestDetail 
		}
		else
		{	
			return Create-CertificateCheckResult -cert $cert -testName $testName -result Pass
		}
	}
	catch [Exception]
	{
		return Create-NotRunExceptionTestResult $testName $_.Exception.Message
	}
}

function Test-CertificateAboutToExpire
{

	param (
		[System.Security.Cryptography.X509Certificates.X509Certificate2] 
		$cert,
		[string]
		$certificateType,
		[bool]
		$isPrimary = $true,
		[string]
		$notRunReason
	)
	$checkName = "AboutToExpire"
	
	$testName = Create-CertCheckName -certType $certificateType -checkName $checkName -isPrimary $isPrimary
	
	$expiryLimitInDays = 90;

	
	if (-not $cert -and [String]::IsNullOrEmpty($notRunReason))
	{
		$notRunReason = "Certificate object is null."
	}
	if (-not [String]::IsNullOrEmpty($notRunReason))
	{
		return Create-CertificateCheckResult -cert $null -testName $testName -result NotRun -detail $notRunReason
	}
	
	try
	{
		$properties = Retrieve-AdfsProperties
		if ($properties.AutoCertificateRollover -and ($certificateType -eq "Token-Decrypting" -or $certificateType -eq "Token-Signing"))
		{
			return Create-CertificateCheckResult -cert $cert -testName $testName -result NotRun -detail "Check Skipped when AutoCertificateRollover is enabled"
		}

		$expirtyMinusToday = [System.Convert]::ToInt32(($cert.NotAfter - (Get-Date)).TotalDays);
		if ($expirtyMinusToday -le $expiryLimitInDays)
		{
			$tp = $cert.Thumbprint

			$certificateAboutToExpireTestDetail = "$certificateType certificate with thumbprint $tp is about to expire in $expirtyMinusToday days.`n"
			$certificateAboutToExpireTestDetail += "Valid From: " + $cert.NotBefore.ToString() + "`nValid To: " + $cert.NotAfter.ToString();
			$certificateAboutToExpireTestDetail += "`nAutoCertificateRollover Enabled: " + (Retrieve-AdfsProperties).AutoCertificateRollover + "`n";
			return Create-CertificateCheckResult -cert $cert -testName $testName -result Fail -detail $certificateAboutToExpireTestDetail 
		}
		else
		{	
			return Create-CertificateCheckResult -cert $cert -testName $testName -result Pass
		}
	}
	catch [Exception]
	{
		return Create-NotRunExceptionTestResult $testName $_.Exception.Message
	}
}

function Test-CertificateHasPrivateKey
{
	param (
		[System.Security.Cryptography.X509Certificates.X509Certificate2] 
		$cert,
		[string]
		$certificateType,
		[bool]
		$isPrimary = $true,
		[string]
        $storeName,
        [string]
        $storeLocation,
        [string]
		$notRunReason
	)
	
	$checkName = "PrivateKeyAbsent"
	
	$testName = Create-CertCheckName -certType $certificateType -checkName $checkName -isPrimary $isPrimary

	if (-not $cert -and [String]::IsNullOrEmpty($notRunReason))
	{
		$notRunReason = "Certificate object is null."
	}
	
	if (-not [String]::IsNullOrEmpty($notRunReason))
	{
		return Create-CertificateCheckResult -cert $null -testName $testName -result NotRun -detail $notRunReason
	}
	
	try
	{
		$properties = Retrieve-AdfsProperties
		if ($properties.AutoCertificateRollover -and ($certificateType -eq "Token-Decrypting" -or $certificateType -eq "Token-Signing"))
		{
			return Create-CertificateCheckResult -cert $cert -testName $testName -result NotRun -detail "Check Skipped when AutoCertificateRollover is enabled"
		}	
        
        #special consideration to the corner case where auto certificate rollover was on, then turned off, leaving behind some certificates in the CU\MY store   
        #in which case, we cannot ascertain whether the private key is present or not
        if ($storeLocation -eq "CurrentUser")
        {
            return Create-CertificateCheckResult -cert $cert -testName $testName -result NotRun -detail "Check Skipped because the certificate is in the CU\MY store"
        }   

		if ($cert.HasPrivateKey)
		{
			return Create-CertificateCheckResult -cert $cert -testName $testName -result Pass
		}
		else
		{
			$tp = $cert.Thumbprint
			$detail = "$certificateType certificate with thumbprint $tp does not have a private key."
			return Create-CertificateCheckResult -cert $cert -testName $testName -result Fail -detail $detail 
		}
	}
	catch [Exception]
	{
		return Create-NotRunExceptionTestResult $testName $_.Exception.Message
	}
}

function Test-CertificateSelfSigned
{
	param (
		[System.Security.Cryptography.X509Certificates.X509Certificate2] 
		$cert,
		[string]
		$certificateType,
		[bool]
		$isPrimary = $false,
		[string]
		$notRunReason
	)
	
	$checkName = "IsSelfSigned"
	
	$testName = Create-CertCheckName -certType $certificateType -checkName $checkName -isPrimary $isPrimary
	
	if (-not $cert -and [String]::IsNullOrEmpty($notRunReason))
	{
		$notRunReason = "Certificate object is null."
	}
	
	if (-not [String]::IsNullOrEmpty($notRunReason))
	{
		return Create-CertificateCheckResult -cert $null -testName $testName -result NotRun -detail $notRunReason
	}
	
	try
	{
		$properties = Retrieve-AdfsProperties
		if ($properties.AutoCertificateRollover -and ($certificateType -eq "Token-Decrypting" -or $certificateType -eq "Token-Signing"))
		{
			return Create-CertificateCheckResult -cert $cert -testName $testName -result NotRun -detail "Check Skipped when AutoCertificateRollover is enabled"
		}
		if (Verify-IsCertSelfSigned $cert)
		{
			$tp = $cert.Thumbprint
			$detail = "$certificateType certificate with thumbprint $tp is self-signed."
			return Create-CertificateCheckResult -cert $cert -testName $testName -result Fail -detail $detail 
		}
		else
		{
			return Create-CertificateCheckResult -cert $cert -testName $testName -result Pass
		}
	}
	catch [Exception]
	{
		return Create-NotRunExceptionTestResult $testName $_.Exception.Message
	}
}

function Test-CertificateCRL
{
	param (
		[System.Security.Cryptography.X509Certificates.X509Certificate2] 
		$cert,
		[string]
		$certificateType,
		[bool]
		$isPrimary = $false,
		[string]
		$notRunReason
	)
	
	$checkName = "Revoked"
	$chainStatusKey = "ChainStatus"
	
	$testName = Create-CertCheckName -certType $certificateType -checkName $checkName -isPrimary $isPrimary
	
	if (-not $cert -and [String]::IsNullOrEmpty($notRunReason))
	{
		$notRunReason = "Certificate object is null."
	}
	
	if (-not [String]::IsNullOrEmpty($notRunReason))
	{
		return Create-CertificateCheckResult -cert $null -testName $testName -result NotRun -detail $notRunReason
	}
	
	try
	{
		$crlResult = VerifyCertificateCRL -cert $cert 
        $passFail = [ResultType]::Pass
		if (($crlResult.ChainBuildResult -eq $false) -and ($crlResult.IsSelfSigned -eq $false))
		{
			$passFail = [ResultType]::Fail            
		}
		$testResult = Create-CertificateCheckResult -cert $cert -testName $testName -result $passFail
		$testDetail = "Thumbprint: " + $crlResult.Thumbprint + "`n"
		
		$testResult.Output.Add($chainStatusKey, "NONE")
		if ($crlResult.ChainStatus)
		{
			$testResult.Output.Set_Item($chainStatusKey, $crlResult.ChainStatus)
			foreach($chainStatus in $crlResult.ChainStatus)
			{
				$testDetail = $testDetail + $chainStatus.Status + "-" + $chainStatus.StatusInformation + [System.Environment]::NewLine
			}
		}
		
		$testResult.Detail = $testDetail
		return $testResult
	}
	catch [Exception]
	{
		return Create-NotRunExceptionTestResult $testName $_.Exception.Message
	}
}

####################
# Aggregate Certificate Checks
####################
function Test-AdfsCertificates ()
{
	
	$primaryCertificateTypes = @("Service-Communications", "Token-Decrypting", "Token-Signing", "SSL")
	$secondaryCerticateTypes = $primaryCertificateTypes | ? {$_ -ne "Service-Communications" -and $_ -ne "SSL"}
	
	$primaryValues = @{$true=$primaryCertificateTypes; $false = $secondaryCerticateTypes}
	
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
            
            foreach($adfsCert in $adfsCerts)
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

##################################
# End Certificate Checks Section
##################################

Function TestSslBindings()
{
    $osVersion = [System.Environment]::OSVersion.Version
    $adfsVersion = Get-AdfsVersion -osVersion $osVersion

    $testName = "CheckAdfsSslBindings"
	$sslBindingsKey = "SSLBindings"
	$sslOutputs = @{$sslBindingsKey = $none}

	$sslBindingsTestResult = New-Object TestResult -ArgumentList $testName
	$isAdfsServiceRunning = IsAdfsServiceRunning;
		
	if(Test-RunningOnAdfsSecondaryServer)
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
			$sslOutputs.Set_Item($sslBindingsKey,$adfsSslBindings)
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
                    $sslOutputs.Set_Item($sslBindingsKey,$sslBinding)
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
	catch [Exception] {
        $testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
	}
}

#This function gets the public version of the certificate and returns the base 64 version of it
Function GetNormalizedCert([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert)
{    
	if ($null -eq $cert)
	{
		return $null
	}
	
    $publicCertPortionBytes = [Byte[]]$cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certToReturn = New-Object -Type System.Security.Cryptography.X509Certificates.X509Certificate2
    $certToReturn.Import($publicCertPortionBytes)

    return $certToReturn
}

<#
.SYNOPSIS
Retrieves overall details of the AD FS farm.

.DESCRIPTION
The Get-ADFSServerConfiguration takes a snapshot of the AD FS farm configuration and relevant dependencies.

.PARAMETER IncludeTrusts
When set, the output of the commandlet will include infromation about the Relying Party trusts and Claims Provider Trusts.

.EXAMPLE
Get-AdfsServerConfiguration -IncludeTrusts | ConvertTo-Json | Out-File ".\ADFSFarmDetails.txt"
Gets the snapshot of the configuration of the AD FS farm, and save it in JSON format

.NOTES
When run against a secondary computer on a Windows Internal Database AD FS farm, the result of this commandlet is expected to be significantly reduced.
If an exception occurs when attempting to get a configuration value, the respective property of the returned object will contain the exception message.
#>
Function Get-AdfsServerConfiguration
{
	[CmdletBinding()]
	Param(
		[switch]$IncludeTrusts
	)
	
	$role = Get-ADFSRole
	
	if ($role -ne "STS")
	{
		return
	}
	
	$configurationOutput = New-Object PSObject;
	
	# Get OS Version to determine ADFS Version
	$OSVersion = [System.Environment]::OSVersion.Version
	$ADFSVersion = Get-AdfsVersion($OSVersion);

	Import-ADFSAdminModule

	$adfsSyncProperties = $null

	try {
		$adfsSyncProperties = Get-AdfsSyncProperties -ErrorVariable adfsSyncProperties;
		$configurationOutput | Add-Member NoteProperty -name "ADFSSyncProperties" -value $adfsSyncProperties -Force;
	}
	catch [Exception] {
		$configurationOutput | Add-Member NoteProperty -name "ADFSSyncProperties" -value "SCRIPTERROR: $_.Exception.Message" -Force;
	}

	if ( $null -eq $adfsSyncProperties ) 
	{
	   return $configurationOutput
	}

	If ($adfsSyncProperties.Role -eq "PrimaryComputer")
	{
		# Common to All Versions of ADFS
		
		If ($IncludeTrusts)
		{
			try {
				$adfsClaimsProviderTrust = Get-AdfsClaimsProviderTrust -ErrorVariable adfsClaimsProviderTrust;
				$configurationOutput | Add-Member NoteProperty -name "ADFSClaimsProviderTrust" -value $AdfsClaimsProviderTrust -Force;
			}
			catch [Exception] {
				$configurationOutput | Add-Member NoteProperty -name "ADFSClaimsProviderTrust" -value "SCRIPTERROR: $_.Exception.Message" -Force;
			}
			try {
				$adfsRelyingPartyTrust = Get-AdfsRelyingPartyTrust -ErrorVariable adfsRelyingPartyTrust;
				$configurationOutput | Add-Member NoteProperty -name "ADFSRelyingPartyTrust" -value $adfsRelyingPartyTrust -Force;
			}
			catch [Exception] {
				$configurationOutput | Add-Member NoteProperty -name "ADFSRelyingPartyTrust" -value "SCRIPTERROR: $_.Exception.Message" -Force;
			}
		}       
		try {
			$adfsAttributeStore = Get-AdfsAttributeStore -ErrorVariable adfsAttributeStore;
			$configurationOutput | Add-Member NoteProperty -name "ADFSAttributeStore" -value $adfsAttributeStore -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "ADFSAttributeStore" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}

		try {
			$adfsCertificateCollection = Get-AdfsCertificateList -RemovePrivateKey
			$configurationOutput | Add-Member NoteProperty -name "ADFSCertificate" -value $adfsCertificateCollection -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "ADFSCertificate" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}

		try {
			$adfsClaimDescription = Get-AdfsClaimDescription -ErrorVariable adfsClaimDescription;
			$configurationOutput | Add-Member NoteProperty -name "ADFSClaimDescription" -value $adfsClaimDescription -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "ADFSClaimDescription" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}
		try {
			$adfsEndpoint = Get-AdfsEndpoint -ErrorVariable adfsEndpoint;
			$configurationOutput | Add-Member NoteProperty -name "ADFSEndpoint" -value $adfsEndpoint -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "ADFSEndpoint" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}
		try {
			$adfsProperties = Retrieve-AdfsProperties
			$configurationOutput | Add-Member NoteProperty -name "ADFSProperties" -value $adfsProperties -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "ADFSProperties" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}
		
		try {
			$adfsClaimsProviderTrustCount = 0
			$adfsRelyingPartyTrustCount = (Get-AdfsRelyingPartyTrust).Count;
			
			$configurationOutput | Add-Member NoteProperty -name "ADFSRelyingPartyTrustCount" -value $adfsRelyingPartyTrustCount -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "ADFSRelyingPartyTrustCount" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}
		try {
			$adfsClaimsProviderTrustCount = 0
			$adfsClaimsProviderTrustCount = (Get-AdfsClaimsProviderTrust).Count;
			
			$configurationOutput | Add-Member NoteProperty -name "ADFSClaimsProviderTrustCount" -value $adfsClaimsProviderTrustCount -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "ADFSClaimsProviderTrustCount" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}
		
		try {
			$adfSConfigurationDatabaseConnectionString = (Get-WmiObject -namespace root/ADFS -class SecurityTokenService).Properties["ConfigurationDatabaseConnectionString"].Value
			$configurationOutput | Add-Member NoteProperty -name "ADFSConfigurationDatabaseConnectionString" -value $adfSConfigurationDatabaseConnectionString -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "ADFSConfigurationDatabaseConnectionStringy" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}
		
		$adfsServiceAccount = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).StartName;
		$configurationOutput | Add-Member NoteProperty -name "AdfssrvServiceAccount" -value $adfsServiceAccount -Force;

		$ADFSVersion = Get-AdfsVersion($OSVersion);
		$configurationOutput | Add-Member NoteProperty -name "AdfsVersion" -value $ADFSVersion -Force;
		
		try {
			$aadRpId = "urn:federation:MicrosoftOnline";
			$aadRp =  Get-ADFSRelyingPartyTrust -Identifier $aadRpId;
			$aadRpStatus = ""		

			if ($aadRp -eq $null)
			{
				$aadRpStatus = "Not Configured";
			}
			else
			{
				if (-not $aadRp.Enabled)
				{
					$aadRpStatus = "Configured but disabled";
				}
				else
				{
					$aadRpStatus = "Configured";
				}
			}
			$configurationOutput | Add-Member NoteProperty -name "AadTrustStatus" -value $aadRpStatus -Force;
		}
		catch [Exception] {
			$configurationOutput | Add-Member NoteProperty -name "AadTrustStatus" -value "SCRIPTERROR: $_.Exception.Message" -Force;
		}
	
		Switch ($ADFSVersion)
		{
			$adfs3
			{
				try {
					$adfsAdditionalAuthenticationRule = Get-AdfsAdditionalAuthenticationRule -ErrorVariable adfsAdditionalAuthenticationRule;
					$configurationOutput | Add-Member NoteProperty -name "ADFSAdditionalAuthenticationRule" -value $adfsAdditionalAuthenticationRule -Force;
				}
				catch [Exception] {
					$configurationOutput | Add-Member NoteProperty -name "ADFSAdditionalAuthenticationRule" -value "SCRIPTERROR: $_.Exception.Message" -Force;
				}
				try {
					$adfsClient = Get-AdfsClient -ErrorVariable adfsClient;
					$configurationOutput | Add-Member NoteProperty -name "ADFSClient" -value $adfsClient -Force;
				}
				catch [Exception] {
					$configurationOutput | Add-Member NoteProperty -name "ADFSClient" -value "SCRIPTERROR: $_.Exception.Message" -Force;
				}


				try {
					$adfsGlobalAuthenticationPolicy = Get-AdfsGlobalAuthenticationPolicy -ErrorVariable adfsGlobalAuthenticationPolicy;
					$configurationOutput | Add-Member NoteProperty -name "ADFSGlobalAuthenticationPolicy" -value $adfsGlobalAuthenticationPolicy -Force;
				}
				catch [Exception] {
					$configurationOutput | Add-Member NoteProperty -name "ADFSGlobalAuthenticationPolicy" -value "SCRIPTERROR: $_.Exception.Message" -Force;
				}

				try {
					$adfsDeviceRegistration = Get-AdfsDeviceRegistration -ErrorVariable adfsDeviceRegistration;
					$configurationOutput | Add-Member NoteProperty -name "ADFSDeviceRegistration" -value $adfsDeviceRegistration -Force;
				}
				catch [Exception] {
					$configurationOutput | Add-Member NoteProperty -name "ADFSDeviceRegistration" -value "SCRIPTERROR: $_.Exception.Message" -Force;
				}
			}
			$adfs2x
			{
				try
				{
					Import-Module WebAdministration
					$adfsGlobalAuthenticationPolicy = @{};
					$iisSites = Get-ChildItem IIS:\Sites
					$webConfigPath = $null
					foreach($site in $iisSites)
					{
						$name = $site.Name
						$adfsDefaultSite = dir IIS:\Sites\$name | where {$_.Name -eq 'adfs\ls'}
						if ($adfsDefaultSite -ne $null)
						{
							$webConfigPath = $adfsDefaultSite.PhysicalPath
							break
						}
					}
					if ($webConfigPath -ne $null)
					{
						$adfsLsWebConfig = [xml](get-content -Path "$webConfigPath\web.config")
						if ($adfsLsWebConfig -ne $null)
						{
							$authMethods = $adfsLsWebConfig.SelectNodes("//localAuthenticationTypes/add")
							if ($authMethods -ne $null)
							{
								Foreach($authenticationMethod in $authMethods)
								{
									if (!($adfsGlobalAuthenticationPolicy.ContainsKey($authenticationMethod.name)))
									{
										$adfsGlobalAuthenticationPolicy.Add($authenticationMethod.name, $authenticationMethod.page);
									}
								}
							}
						}
					}
					$configurationOutput | Add-Member NoteProperty -name "ADFSGlobalAuthenticationPolicy" -value $adfsGlobalAuthenticationPolicy -Force;
				}
				catch [Exception] {
					$configurationOutput | Add-Member NoteProperty -name "ADFSGlobalAuthenticationPolicy" -value "SCRIPTERROR: $_.Exception.Message" -Force;
				}
			}
		}
	}

	$configurationOutput;
}

function GetAdHealthAgentRegistryKeyValue($valueName, $defaultValue)
{
    $agentRegistryValue = Get-ItemProperty -path $AdHealthAgentRegistryKeyPath -Name $valueName -ErrorAction SilentlyContinue
    if($agentRegistryValue -eq $null)
    {
        return $defaultValue;
    }
    else
    {
        return $agentRegistryValue.$valueName;
    }
}

<#
.SYNOPSIS
Retrieves overall details of the computer

.DESCRIPTION
The Get-AdfsSystemConfiguration gathers information regarding operating system and hardware

.EXAMPLE
Get-AdfsSystemConfiguration | ConvertTo-Json | Out-File ".\ADFSFarmDetails.txt"
Get the operating system data of the server and save it in JSON format
#>
Function Get-AdfsSystemInformation()
{
	[CmdletBinding()]
	Param()
	
	$role = Get-ADFSRole
	
	
	$systemOutput = New-Object PSObject;

	$OSVersion = [System.Environment]::OSVersion.Version
	$systemOutput | Add-Member NoteProperty -name "OSVersion" -value $OSVersion -Force;
	
	$computerSystem = Get-WmiObject -class win32_computersystem;
	$operatingSystem = Get-WmiObject -Class Win32_OperatingSystem;
	$timeZone = [System.TimeZone]::CurrentTimeZone.StandardName;
	$systemOutput | Add-Member NoteProperty -name "OSName" -value (Get-WmiObject Win32_OperatingSystem).Caption -Force;
	$systemOutput | Add-Member NoteProperty -name "MachineDomain" -value (Get-WmiObject Win32_ComputerSystem).Domain -Force;
    $systemOutput | Add-Member NoteProperty -name "IPAddress" -value (Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{$_.IPEnabled -eq "True"}).IPAddress[0] -Force;
	$systemOutput | Add-Member NoteProperty -name "TimeZone" -value $timeZone -Force;
	$systemOutput | Add-Member NoteProperty -name "LastRebootTime" -value $operatingSystem.ConvertToDateTime($operatingSystem.LastBootUpTime).ToUniversalTime() -Force;
	$systemOutput | Add-Member NoteProperty -name "MachineType" -value $computerSystem.Model -Force;

	$processor = Get-WmiObject -class win32_processor;
	$systemOutput | Add-Member NoteProperty -name "NumberOfLogicalProcessors" -value $processor.NumberOfLogicalProcessors -Force;
	$systemOutput | Add-Member NoteProperty -name "MaxClockSpeed" -value $processor.MaxClockSpeed -Force;

    $totalMemory = (get-ciminstance -class "cim_physicalmemory" | Measure-Object -Property Capacity -Sum | Select-Object -ExpandProperty Sum)
    $totalMemoryInMb = $totalMemory / 1Mb

	$systemOutput | Add-Member NoteProperty -name "PhsicalMemory" -value $totalMemoryInMb
	
	$hostsEntry = @{};
	$hostsFile = [system.environment]::getenvironmentvariable("SystemDrive") + "\windows\system32\drivers\etc\hosts";
	foreach ($line in Get-Content $hostsFile)
	{
		$ipAddress = "";
		$dnsName = "";
		if (!($line.StartsWith("#")) -and !($line.Trim() -eq ""))
		{
			If ($line.Trim().Split("`t").Count -eq 2)
			{
				$ipAddress = $line.Trim().Split("`t")[0];
				$dnsName = $line.Trim().Split("`t")[1];
			}
			Else
			{
				$regex = [regex] "\s+";
				If ($regex.Split($line).Count -eq 2)
				{
					$ipAddress = $regex.Split($line)[0];
					$dnsName = $regex.Split($line)[1];
				}
			}
			if ($ipAddress -ne "" -and $dnsName -ne "")
			{
				if (!($hostsEntry.ContainsKey($dnsName)))
				{
					$hostsEntry.Add($dnsName, $ipAddress);
				}
			}
		}
	}
	$systemOutput | Add-Member NoteProperty -name "Hosts" -value $hostsEntry -Force;

	$hotFixEntries = @{};
	$hotFixes = Get-WmiObject Win32_QuickFixEngineering | Select HotfixId, InstalledOn;
	foreach ($hotFix in $hotFixes)
	{
		if (!($hotFixEntries.ContainsKey($hotFix.HotfixId)))
		{
			$hotFixEntries.Add($hotFix.HotfixId, $hotFix.InstalledOn);
		}
	}
	$systemOutput | Add-Member NoteProperty -name "Hotfixes" -value $hotFixEntries -Force;
	
	$adfsWmiProperties = @{};
	
	if ($role -eq "STS")
	{
		Foreach ($adfsWmiProperty in (Get-WmiObject -namespace root/ADFS -class SecurityTokenService).Properties)
		{
			if (!($adfsWmiProperties.ContainsKey($adfsWmiProperty.Name)))
			{
				$adfsWmiProperties.Add($adfsWmiProperty.Name, $adfsWmiProperty.Value);
			}
		}
	}
	
	$systemOutput | Add-Member NoteProperty -name "AdfsWmiProperties" -value $adfsWmiProperties -Force;
	

	$bindings = @(@{});
	$bindingCount = -1;
	$bindingsStr = netsh http show sslcert 
	
	#remove all title/extra lines 
	$bindingsStr = $bindingsStr | Foreach{$tok = $_.Split(":"); IF ($tok.Length -gt 1 -and $tok[1].TrimEnd() -ne "" -and $tok[0].StartsWith(" ")){$_}}
	
	foreach ($bindingLine in $bindingsStr)
	{
		If ($bindingLine.Trim().ToLower().StartsWith("ip:port"))
		{
			$bindings += @{};
			$bindingCount = $bindingCount + 1;
			$bindings[$bindingCount].Add("IPPort", $bindingLine.Trim().Split(':')[2].Trim() + ":" + $bindingLine.Trim().Split(':')[3].Trim());
			Continue;
		}
		If ($bindingLine.Trim().ToLower().StartsWith("hostname:port"))
		{
			$bindings += @{};
			$bindingCount = $bindingCount + 1;
			$bindings[$bindingCount].Add("HostnamePort", $bindingLine.Trim().Split(':')[2].Trim() + ":" + $bindingLine.Trim().Split(':')[3].Trim());
			Continue;
		}
		$bindings[$bindingCount].Add($bindingLine.Trim().Split(':')[0].Trim(), $bindingLine.Trim().Split(':')[1].Trim());
	}
	$systemOutput | Add-Member NoteProperty -name "SslBindings" -value $bindings -Force;

	if ($role -ne "none")
	{
		$adfsServiceAccount = (Get-WmiObject win32_service | Where-Object {$_.name -eq "adfssrv"}).StartName;
		$systemOutput | Add-Member NoteProperty -name "AdfssrvServiceAccount" -value $adfsServiceAccount -Force;
	}
	
	$ADFSVersion = Get-AdfsVersion($OSVersion);
	$systemOutput | Add-Member NoteProperty -name "AdfsVersion" -value $ADFSVersion -Force;
	
	$systemOutput | Add-Member NoteProperty -name "Role" -value $role -Force;

    #Get the top 10 with the highest private working set memory, adding the percentage of total
    $processes = gwmi -Class Win32_PerfRawData_PerfProc_Process -Property @("Name","WorkingSetPrivate")
    $top10ProcessesByMemory = $processes | sort WorkingSetPrivate -Descending | Where-Object {$_.Name -ne "_Total"} | Select-Object -First 10 Name,@{Name="MemoryInMB";Expression = {$_.WorkingSetPrivate / 1Mb}},@{Name="MemoryPercentOfTotal";Expression = {100 * $_.WorkingSetPrivate / $totalMemory}}
    $systemOutput | Add-Member NoteProperty -name "Top10ProcessesByMemory" -value $top10ProcessesByMemory -Force;
    
    #get ADHealthAgent update information
    $agentInformation = New-Object AdHealthAgentInformation
    $systemOutput | Add-Member NoteProperty -Name "AdHealthAgentInformation" -Value $agentInformation

    $systemOutput.AdHealthAgentInformation.Version = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::CurrentVersion) -DefaultValue "Unknown")
    $systemOutput.AdHealthAgentInformation.UpdateState = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::UpdateState) -DefaultValue "None")
    $systemOutput.AdHealthAgentInformation.LastUpdateAttemptVersion = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::VersionOfUpdate) -DefaultValue "None")
    $systemOutput.AdHealthAgentInformation.NumberOfFailedAttempts = (GetAdHealthAgentRegistryKeyValue  -ValueName ([RegistryValueName]::NumberOfFailedAttempts)  -DefaultValue 0)
    $systemOutput.AdHealthAgentInformation.InstallerExitCode = (GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::InstallerExitCode) -DefaultValue "Unknown").ToString()
    
	$NotFound = "NotFound";
    $LastUpdateAttemptTimeLong = GetAdHealthAgentRegistryKeyValue -ValueName ([RegistryValueName]::LastUpdateAttempt) -DefaultValue $NotFound
    if($LastUpdateAttemptTimeLong -eq $NotFound)
    {
        #use DateTime.min as LastUpdateAttempt value if it is not found in registry
        $systemOutput.AdHealthAgentInformation.LastUpdateAttemptTime = [dateTime]::MinValue
    }
    else
    {
        #convert from filetime to utc
        $LastUpdateAttemptUTC =  [datetime]::FromFileTime($LastUpdateAttemptTimeLong).ToUniversalTime()
        $systemOutput.AdHealthAgentInformation.LastUpdateAttemptTime = $LastUpdateAttemptUTC
    }
    
	$systemOutput;
}

function VerifyCertificateCRL($cert, $revocationCheckSetting)
{
	if ( $null -eq $cert )
	{
	  return $null
	}

	$certSubject = $cert.Subject
	$isSelfSigned =  $certSubject -eq $cert.IssuerName.Name 

	if ($isSelfSigned)
	{
		#mark the test as passing for self-signed certificates
		$result = new-Object -TypeName PSObject    
		$result | Add-Member -MemberType NoteProperty -Name Subject -Value $cert.Subject  
		$result | Add-Member -MemberType NoteProperty -Name IsSelfSigned -Value $isSelfSigned
		$result | Add-Member -MemberType NoteProperty -Name Thumbprint -Value $cert.Thumbprint
		$result | Add-Member -MemberType NoteProperty -Name VerifyResult -Value "N/A"
		$result | Add-Member -MemberType NoteProperty -Name ChainBuildResult -Value @()
		$result | Add-Member -MemberType NoteProperty -Name ChainStatus -Value $true
		return $result
	}    

	$chainBuildResult = $true
	$chainStatus = $null

	$verifyResult = $cert.Verify()
	
	#If set to none, ADFS will not even check this so ... scrap the results
	#to avoid surfacing noise to the user

	if ($revocationCheckSetting -ne "None")
	{    
		$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
		$chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds 10
		$chain.ChainPolicy.VerificationFlags = "AllowUnknownCertificateAuthority"

		switch($revocationCheckSetting)
		{
			"CheckEndCert"
			{  
				$chain.ChainPolicy.RevocationFlag = "EndCertificateOnly"  
				$chain.ChainPolicy.RevocationMode = "Online"  
			}  
			"CheckEndCertCacheOnly"
			{
				$chain.ChainPolicy.RevocationFlag = "EndCertificateOnly"  
				$chain.ChainPolicy.RevocationMode = "Offline"  
			}
			"CheckChain"
			{
				$chain.ChainPolicy.RevocationFlag = "EntireChain"  
				$chain.ChainPolicy.RevocationMode = "Online"  
			}
				  
			"CheckChainCacheOnly"
			{
				$chain.ChainPolicy.RevocationFlag = "EntireChain"  
				$chain.ChainPolicy.RevocationMode = "Offline"  
			}
			"CheckChainExcludeRoot"
			{
				$chain.ChainPolicy.RevocationFlag = "ExcludeRoot"  
				$chain.ChainPolicy.RevocationMode = "Online"  
			}
			"CheckChainExcludeRootCacheOnly"
			{
				$chain.ChainPolicy.RevocationFlag = "ExcludeRoot"  
				$chain.ChainPolicy.RevocationMode = "Offline"  
			}
			default
			{
				$chain.ChainPolicy.RevocationFlag = "EntireChain"  
				$chain.ChainPolicy.RevocationMode = "Online"  
			}
		}

		$chainBuildResult = $chain.Build($cert)
		$chainStatus = $chain.ChainStatus
	}

	$certSubject = $cert.Subject
	$isSelfSigned =  $certSubject -eq $cert.IssuerName.Name   

	$result = new-Object -TypeName PSObject    
	$result | Add-Member -MemberType NoteProperty -Name Subject -Value $cert.Subject  
	$result | Add-Member -MemberType NoteProperty -Name IsSelfSigned -Value $isSelfSigned
	$result | Add-Member -MemberType NoteProperty -Name Thumbprint -Value $cert.Thumbprint
	$result | Add-Member -MemberType NoteProperty -Name VerifyResult -Value $verifyResult
	$result | Add-Member -MemberType NoteProperty -Name ChainBuildResult -Value $chainBuildResult
	$result | Add-Member -MemberType NoteProperty -Name ChainStatus -Value $chainStatus
	return $result    
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
        $testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::Fail;
		$testResult.Detail = "Could not resolve the farm name {0} with exception '{1}'" -f $farmName,$_.Exception.Message;
        $testResult.Output = @{$farmNameKey = $farmName; $serviceAccountKey = $serviceAccountName; $errorKey = $_.Exception.ToString()}
		return $testResult;
   }
   catch [Exception] 
   {
		$testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
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
			$testResult.Detail = "Current user "+ $env:USERNAME + " is not a domain account. Cannot execute this test"
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
			
			for($i = 0; $i -lt $spnResults.Count; $i++)
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
		$testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = "Exception Occurred: " + [System.Environment]::NewLine + $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
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
			$rpIdKey = $aadRpId ;`
			$rpNameKey = $none ;`
			$rpEnabledKey = $none ;`
			$rpSignAlgKey = $none}

		$isAdfsServiceRunning = IsAdfsServiceRunning
 
		if ($isAdfsServiceRunning -eq $false)
		{
			$testResult.Result = [ResultType]::NotRun;
			$testResult.Detail = "AD FS service is not running";
			return $testResult;
		}
		$aadRpName = "Microsoft Office 365 Identity Platform"

		$aadRp =  Get-ADFSRelyingPartyTrust -Identifier $aadRpId

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
			$testResult.Detail += "Relying Party Trust Display Name: " + $aadRp.Name +"`n";
			$testResult.Detail += "Relying Party Trust Identifier: " + $aadRp.Identifier +"`n";
			$aadRpDetail = $true
			$testPassed = $false
		}

		if ($aadRp.SignatureAlgorithm  -ne "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
		{
			$testResult.Result = [ResultType]::Fail;
			$testResult.Detail += $aadRpName + " Relying Party token signature algorithm is not SHA1`n";
			if (-not $aadRpDetail)
			{
				$testResult.Detail += "Relying Party Trust Display Name: " + $aadRp.Name +"`n";
				$testResult.Detail += "Relying Party Trust Identifier: " + $aadRp.Identifier +"`n";
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
		$testResult= New-Object TestResult -ArgumentList($testName);
		$testResult.Result = [ResultType]::NotRun;
		$testResult.Detail = $_.Exception.Message;
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult;
   }
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

<#
.SYNOPSIS
Performs a synthetic transaction to get a token against an AD FS farm

.DESCRIPTION
If a credential  is provided, then the 2005/usernamemixed Endpoint will be used to get the token.
Otherwise, the 2005/windowstransport endpoint will be used with the windows identity of the logged on user.
The token is returned in XML format

.PARAMETER FederationServer 
Federation Server (Farm) host name

.PARAMETER AppliesTo
Identifier of the target relying party

.PARAMETER Credential
Optional Username Credential used to retrieve the token 

.EXAMPLE
Test-AdfsServerToken -FederationServer sts.contoso.com -AppliesTo urn:payrollapp
Retrieves a token for the relying party with identifier urn:payrollapp against the farm 'sts.contoso.com' with logged on user windows credentials

.EXAMPLE
Test-AdfsServerToken -FederationServer sts.contoso.com -AppliesTo urn:payrollapp -Credential (Get-Credential)
Retrieves a token for the relying party with identifier urn:payrollapp against the farm 'sts.contoso.com' using a UserName/Password credential

.EXAMPLE
$tokenString = Test-AdfsServerToken -FederationServer sts.contoso.com -AppliesTo urn:payrollapp 
$tokenXml = [Xml]$tokenString
$tokenXml.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion.AttributeStatement.Attribute | ft 

Retrieves a token, and see the claims in the attribute statement in a table format


.NOTES
If credential parameter is provided, then the 2005/usernamemixed Endpoint needs to be enabled
Otherwise, the 2005/windowstransport endpoint needs to be enabled

#>
Function Test-AdfsServerToken
{
	param
	(
		[ValidateNotNullOrEmpty()] 
		[string] 
		$FederationServer,

		[ValidateNotNullOrEmpty()] 
		[string]
		$AppliesTo,
		
		[Parameter(Mandatory=$false)]
		$Credential
	)
    $rst = $null
    $endpoint = $null

    if ($credential -ne $null)
    {
        $endpoint = "https://" + $federationServer + "/adfs/services/trust/2005/usernamemixed"
        $username = $credential.UserName
        $password = $credential.GetNetworkCredential().Password 
        $rst= [String]::Format(
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">{0}</a:To><o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:UsernameToken u:Id="uuid-52bba51d-e0c7-4bb1-8c99-6f97220eceba-5"><o:Username>{1}</o:Username><o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{2}</o:Password></o:UsernameToken></o:Security></s:Header><s:Body><t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><a:EndpointReference><a:Address>{3}</a:Address></a:EndpointReference></wsp:AppliesTo><t:KeySize>0</t:KeySize><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType></t:RequestSecurityToken></s:Body></s:Envelope>', `
            $endpoint,
            $username,
            $password,
            $appliesTo)
    }
    else
    {
        $endpoint = "https://" + $federationServer + "/adfs/services/trust/2005/windowstransport"
        $rst= [String]::Format(
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">{0}</a:To></s:Header><s:Body><t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><a:EndpointReference><a:Address>{1}</a:Address></a:EndpointReference></wsp:AppliesTo><t:KeySize>0</t:KeySize><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType></t:RequestSecurityToken></s:Body></s:Envelope>', `
            $endpoint,
            $appliesTo)
    }

	$webresp = Invoke-WebRequest $endpoint -Method Post -Body $rst -ContentType "application/soap+xml" -UseDefaultCredentials
	$tokenXml = [xml]$webresp.Content
	return $tokenXml.OuterXml
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
			if($synthTxErrVar -ne $null)
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

Function TestSSLCertSubjectContainsADFSFarmName()
{
	$adfsVersion = Get-AdfsVersionEx
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
		switch($adfsVersion)
		{
			$adfs3
			{
				foreach ($sslCert in (Get-AdfsSslCertificate))
				{
					if(-not $sslCertHashes.Contains($sslCert.CertificateHash))
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
				$altNamesStr=[System.Convert]::ToBase64String($sanExt.RawData)
				$sanObjs.InitializeDecode(1, $altNamesStr)
				Foreach ($SAN in $sanObjs.AlternativeNames)
				{
					$strValue = $SAN.strValue
					$searchFilter = $strValue -replace "\*", "[\w-]+"
					$searchFilter = "^" + $searchFilter + "$"
					if($farmName -match $searchFilter)
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
					if($farmName -match $searchFilter)
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
		$testResult.Result = [ResultType]::NotRun
		$testResult.Detail = $_.Exception.Message
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult
	}
}

Function TestSSLUsingADFSPort()
{
    $adfsVersion = Get-AdfsVersionEx
	$testName = "TestSSLUsingADFSPort"
	$testResult = New-Object TestResult -ArgumentList ($testName)
	
	$sslTpKey = "AdfsSSLCertThumbprint"
	$httpsPortKey = "AdfsHttpsPort"
	$sslBindingsKey = "AdfsSSLBindings"
	
	
	$testResult.Output = @{$sslTpKey = $none; $httpsPortKey = $none; $sslBindingsKey = $none}
	
	try
	{
		if($adfsVersion -ne $adfs2x)
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
		
		if(($SSLPortMatch | measure).Count -gt 0)
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
		$testResult.Result = [ResultType]::NotRun
		$testResult.Detail = $_.Exception.Message
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult
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
		$testResult.Result = [ResultType]::NotRun
		$testResult.Detail = $_.Exception.Message
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult
	}
}

Function TestAppPoolIDMatchesServiceID()
{
	$adfsVersion = Get-AdfsVersionEx
    $testName = "TestAppPoolIDMatchesServiceID"
	$testResult = New-Object TestResult -ArgumentList ($testName)
	$pipelineModeKey = "AdfsAppPoolPipelineMode"
	
	if($adfsVersion -ne $adfs2x)
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
		$testResult.Result = [ResultType]::NotRun
		$testResult.Detail = $_.Exception.Message
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult
	}
	finally
	{
		Pop-Location
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
		$serviceAcctKey = $none;`
		$userAcctCtrlKey = $none;`
		$acctDisabledKey = $none;`
		$acctPwdExpKey = $none;`
		$acctLockedKey = $none}
	
	try
	{
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
			$testResult.Output.Set_Item($acctDisabledKey,$accountDisabled)
			
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
		$testResult.Result = [ResultType]::NotRun
		$testResult.Detail = $_.Exception.Message
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult
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
        $stsAuditSetting = $none;
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
       if ($role -eq "STS")
       {
           $adfsSyncSetting = (Get-ADFSSyncProperties).Role
           if (IsAdfsSyncPrimaryRole)
           {
                $audits = (Retrieve-AdfsProperties).LogLevel | where {$_ -like "*Audits"} | Sort-Object

                $auditsStr = ""
                foreach($audit in $audits)
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
		$testResult.Result = [ResultType]::NotRun
		$testResult.Detail = $_.Exception.Message
		$testResult.ExceptionMessage = $_.Exception.Message
		return $testResult
	}  
}

Function Invoke-TestFunctions($role, [array]$functionsToRun)
{
    $results = @()
    $totalFunctions = $functionsToRun.Count
    $functionCount = 0
    foreach($function in $functionsToRun)
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
		$verifyO365 = $true
	)
	
	$role = Get-ADFSRole
	
	if ($role -ne "STS")
	{
		return
	}
	
	# Get OS Version to determine ADFS Version
	$OSVersion = [System.Environment]::OSVersion.Version
	$ADFSVersion = Get-AdfsVersion -OSVersion $OSVersion

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
	    "TestAdfsRequestToken");
    
	if ($verifyO365 -eq $true)
	{   
        $functionsToRun = $functionsToRun + @( `
		"TestOffice365Endpoints"
		"TestADFSO365RelyingParty"
		"TestNtlmOnlySupportedClientAtProxyEnabled" )
	}

    Invoke-TestFunctions -role "STS" -functionsToRun $functionsToRun
}

Function TestAdfsProxyHealth()
{	
	$functionsToRun = @("TestIsAdfsRunning", "TestSTSReachableFromProxy")
    Invoke-TestFunctions -role "Proxy" -functionsToRun $functionsToRun
}

<#
.SYNOPSIS
Performs applicable health checks on the AD FS server (Proxy or STS)

.DESCRIPTION
The health checks generated by the Test-AdfsServerHealth cmdlet return a list of results with the following properties:
* Name : Mnemonic identifier for the test
* Result : One value of 'Pass','Fail','NotRun'
* Detail : Explanation of the 'Fail' and 'NotRun' result. It is typically empty when the check passes.
* Output : Data collected for the specific test. It is a list of Key value pairs
* ExceptionMessage: If the test encountered an exception, this property contains the exception message.

.PARAMETER VerifyO365 
Boolean parameter that will enable Office 365 targeted checks. It is true by default.

.PARAMETER VerifyTrustCerts
Boolean parameter that will enable additional checks for relying party trust and claims provider trust certificates. It is false by default.


.EXAMPLE
Test-AdfsServerHealth | Where-Object {$_.Result -ne "Pass"}
Execute test suite and get only the tests that did not pass

.EXAMPLE
Test-AdfsServerHealth -VerifyOffice365:$false
Execute test suite in an AD FS farm where Office 365 is not configured

.EXAMPLE
Test-AdfsServerHealth -VerifyTrustCerts:$true
Execute test suite in an AD FS farm and examine the relying party trust and claims provider trust certificates

.NOTES
Most of the checks require executing AD FS cmdlets. As a result:
1. The most comprehensive analysis occurs when running from the Primary Computer in a Windows Internal Database farm. 
2. For secondary computers in a Windows Internal Database farm, the majority of checks will be marked as "NotRun"
3. For a SQL Server farm, all applicable tests will run succesfully.
4. If the AD FS service is stopped, the majority of checks will be returned as 'NotRun'
#>
Function Test-AdfsServerHealth()
{
	[CmdletBinding()]
	Param
	(
		$verifyO365 = $true,
		$verifyTrustCerts = $false
	)
	
	$role = Get-ADFSRole
	
	if ($role -eq "STS")
	{
		TestAdfsSTSHealth -verifyO365 $verifyO365 -verifyTrustCerts $verifyTrustCerts
	}

    if ($role -eq "Proxy")
    {
        TestAdfsProxyHealth
    }
}


Function Test-AdfsServerHealthSingleCheck
{
    [CmdletBinding()]
	param
	(
        [ValidateNotNullOrEmpty()] 
		[string]
        $testFunctionName
    )

	Import-ADFSAdminModule
    $props = Retrieve-AdfsProperties -force;
    Invoke-TestFunctions -Role "Tests" -functionsToRun @($testFunctionName)
}


<#
.SYNOPSIS
Starts background jobs to search events based on AD FS Activity ID accross different computers

.DESCRIPTION
The Start-AdfsServerTrace cmdlet queries all computers' event logs for the activity ID supplied in parallel as background jobs.
Use the Receive-AdfsServerTrace cmdlet to retrieve and combine the results
This cmdlets works in AD FS 2.0 and later.

.PARAMETER activityId 
Activity ID to search for. This typically comes from an AD FS error page.

.PARAMETER ComputerName
It is an array of computers, which represents the AD FS servers to try.

.EXAMPLE
Start-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Servers ADFSSRV1 and ADFSSRV2

.EXAMPLE
Start-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName (Get-Content .\Servers.txt)
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df from servers in a text file

.EXAMPLE
Start-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -IncludeDebug -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Server ADFSSRV1 and ADFSSRV2, including debug traces

.NOTES
You need to run this function using an account that has permissions to read the event logs in all computers supplied.
This is typically achieved having the account be part of the "Event Log Readers" Local Security Group.
The computers supplied also should have firewall rules configured to allow remote readings.
#>
Function Start-AdfsServerTrace
{
    [CmdletBinding()]
    param
	(
        [Parameter(Mandatory=$true)] 
        [ValidateNotNullOrEmpty()] 
		[string]
		$ActivityId,
		
        [switch]
        $IncludeDebug,

        [Parameter(Mandatory=$true)] 
        [string[]]
        $ComputerName
	)
    
    #script block that gathers events from Debug and Admin logs
    $getEventWorker = {
        param([string]$sourceType, [string]$activityId, [string]$computerName)

        #common columns to return
        $idExpression = @{ label='EventId'; Expression={$_.Id } }
	    $timeExpression = @{ label='TimeCreated'; Expression={ $_.TimeCreated } }
	    $eventRecordIDExpression = @{ label='EventRecordID'; Expression={[System.Convert]::ToInt32((([xml]$_.ToXml()).Event.System.EventRecordId)) } }
	    $messageExpression = @{ label='Message'; Expression={$_.Message} }
	    $detailsExpression = @{ label='Details'; Expression={if ($_.Message -ne $_.properties[0].value) { $_.properties[0].value } else { "" } } }
	    $details2Expression = @{ label='Details2'; Expression={$_.properties[1].value } } 
        $computerNameExpression = @{ label='ComputerName'; Expression={ $computerName } }
        $sourceExpression = @{ label='Source'; Expression={$sourceType} }
        $activityIdExpression = @{ label='ActivityId'; Expression={$_.ActivityId} }

        if ($sourceType -eq "Admin")
        {
            $sortKeyExpression= @{ label='SortKey'; Expression={ 2 } }  
            $adfs2SourceName = "AD FS 2.0/Admin"
            $adfs3SourceName = "AD FS/Admin"
            $oldest = $false
        } 

        if ($sourceType -eq "Debug")
        {
            $sortKeyExpression= @{ label='SortKey'; Expression={ 3 } }  
            $adfs2SourceName = "AD FS 2.0 Tracing/Debug"
            $adfs3SourceName = "AD FS Tracing/Debug"
            $oldest = $true
        } 

        [System.Guid]$activityGuid = [System.Guid]::Parse($activityId)
	    $normalizedGuid =  $activityGuid.ToString("B").ToUpper()
        $xpathFilter = "*[System/Correlation[@ActivityID='$normalizedGuid']]"

        $results = Get-WinEvent -LogName $adfs2SourceName -Oldest:$oldest -FilterXPath $xpathFilter -MaxEvents 100 -ErrorAction SilentlyContinue -ComputerName $computerName -ErrorVariable $errorVar
        $results = $results + [array](Get-WinEvent -LogName $adfs3SourceName -Oldest:$oldest -FilterXPath $xpathFilter -MaxEvents 100 -ErrorAction SilentlyContinue -ComputerName $computerName -ErrorVariable $errorVar)

        Write-Output $results | Select-Object $computerNameExpression,
                                              $sourceExpression, 
                                              $sortKeyExpression, 
                                              $idExpression, 
                                              $timeExpression, 
                                              $eventRecordIDExpression, 
                                              $messageExpression,
                                              $detailsExpression, 
                                              $details2Expression 
    }
     
    #script block that gathers security audits
    $getAuditsWorker = {
        param([string]$activityId, [string]$computerName)
        [System.Guid]$activityGuid = [System.Guid]::Parse($activityId)
	    $normalizedGuidForAudits =  $activityGuid.ToString()
        $xpathFilterAudits = "*[EventData[Data='$normalizedGuidForAudits']]"

        $idExpression = @{ label='EventId'; Expression={$_.Id } }
	    $timeExpression = @{ label='TimeCreated'; Expression={ $_.TimeCreated } }
	    $eventRecordIDExpression = @{ label='EventRecordID'; Expression={[System.Convert]::ToInt32((([xml]$_.ToXml()).Event.System.EventRecordId)) } }
	    $messageExpression = @{ label='Message'; Expression={$_.Message} }
	    $detailsExpression = @{ label='Details'; Expression={if ($_.Message -ne $_.properties[0].value) { $_.properties[0].value } else { "" } } }
	    $details2Expression = @{ label='Details2'; Expression={$_.properties[1].value } } 
        $computerNameExpression = @{ label='ComputerName'; Expression={ $computerName } }
        $sourceAuditExpression = @{ label='Source'; Expression={"Audits"} }
        $sortKeyExpression= @{ label='SortKey'; Expression={ 1 } }  

        $auditTraces = Get-WinEvent -LogName "Security" -Oldest -FilterXPath $xpathFilterAudits -ErrorAction SilentlyContinue -ComputerName $computerName 

        $results = $auditTraces

	    #audits also have instance ID. To harvest those, let's find the data1 fields that are like a guid and are not the activity id
	    $instanceIds = $auditTraces | where { $_.Details -match "[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}" -and $_.Details -ne $normalizedGuidForAudits } | Select-Object  -ExpandProperty Details -Unique
	    foreach ($instanceId in $instanceIds)
	    {
		    $xpathFilterAuditsByInstId = "*[EventData[Data='$instanceId']]" 
		    $results = $results + [array](Get-WinEvent -LogName "Security" -Oldest -FilterXPath $xpathFilterAuditsByInstId -ErrorAction SilentlyContinue -ComputerName $computerName)
	    }

        Write-Output $results | Select-Object $computerNameExpression,
                                              $sourceAuditExpression, 
                                              $sortKeyExpression, 
                                              $idExpression, 
                                              $timeExpression, 
                                              $eventRecordIDExpression, 
                                              $messageExpression,
                                              $detailsExpression, 
                                              $details2Expression 
    }
    $jobs=@()
    
    $activity = "Getting AD FS request details for ActivityId=$activityId"
    
    Write-Progress -Activity $activity -Status "Querying event logs in parallel"
    foreach($server in $computerName)
    {   
        $jobs = [array]$jobs + (Start-Job -Name $server+"-Admin" -ScriptBlock $getEventWorker -ArgumentList @("Admin", $activityId, $server))

        if ($includeDebug)
        {
	        $jobs = [array]$jobs + (Start-Job -Name $server+"-Trace" -ScriptBlock $getEventWorker -ArgumentList @("Debug", $activityId, $server))
        }

	    $jobs = [array]$jobs + [array](Start-Job -Name $server+"-Audit" -ScriptBlock $getAuditsWorker -ArgumentList @($activityId, $server))
    }
    
    Write-Output $jobs
}

<#
.SYNOPSIS
Combines and sorts all the AD FS events generated given an activity ID from background jobs

.DESCRIPTION
The Receive-AdfsServerTrace them combines and sorts the results of each background job created with Start-AdfsServerTrace. 
If the jobs have not completed, the commandlet will wait until completion of all jobs.
At the end, the jobs will be removed

.PARAMETER Jobs 
Background jobs generated with the Start-AdfsServerTrace cmdlet

.EXAMPLE
$jobs = Start-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Servers ADFSSRV1 and ADFSSRV2

On a regular basis, check how many have completed and how many are running
$jobs | Get-Job -IncludeChildJob | Group-Object State

At any point, receive the jobs
$results = Receive-AdfsServerTrace -Jobs $jobs

.NOTES
The cmdlet sorts the events based on event timestamp first, then the source of the event (Audit, Admin, and Debug), and then the sequencing within the event source the event came from.
#>
Function Receive-AdfsServerTrace
{
    [CmdletBinding()]
    param
	(
        [Parameter(Mandatory=$true)]
        [array]$Jobs
	)

    try
    {
        $activity = "Retrieving AD FS Server Trace"
    
        Write-Progress -Activity $activity -Status "Waiting for all jobs to finish"    
        $jobs | Get-Job -IncludeChildJob | Wait-Job | Out-Null

        Write-Progress -Activity $activity -Status "Merging and sorting events found"
        $combined = @()
        foreach($job in $jobs)
        {
            $result = $job | Get-Job -IncludeChildJob | Receive-Job -ErrorAction SilentlyContinue
            $combined = $combined + [array]$result
        }
	
        $combinedSorted = $combined | Sort-Object TimeCreated,SortKey,EventRecordID | Select-Object ComputerName,Source,TimeCreated,EventId,Message,Details,Details2

	    Write-Output $combinedSorted
    }
    finally
    {
        #Clean after the jobs generated
        $Jobs | Get-Job | Remove-Job
    }
}


<#
.SYNOPSIS
Retrieves all the AD FS events generated given an Activity ID ID accross different computers

.DESCRIPTION
The Get-ADFSActivityIdRecords cmdlet queries all computers' event logs for the activity ID supplied in parallel, and them combines and sorts the results.
This cmdlets works in AD FS 2.0 and later.


.PARAMETER ActivityId 
Activity ID to search for. This typically comes from an AD FS error page.

.PARAMETER ComputerName
It is an array of computers, which represents the AD FS servers to try. If omitted, the local machine will be used

.PARAMETER OutHtmlFilePath
If supplied, the results will be generated in an html table format, saved in the path specified and opened in the internet browser.

.EXAMPLE
Get-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Servers ADFSSRV1 and ADFSSRV2

.EXAMPLE
Get-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -ComputerName (Get-Content .\Servers.txt)
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df from servers in a text file

.EXAMPLE
Get-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -IncludeDebug -ComputerName @("ADFSSRV1","ADFSSRV2")
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Server ADFSSRV1 and ADFSSRV2, including debug traces

.EXAMPLE
Get-AdfsServerTrace -ActivityId 00000000-0000-0000-9701-0080000000df -IncludeDebug -ComputerName @("ADFSSRV1","ADFSSRV2") -OutHtmlFilePath ".\ActivityIdReport.htm"
Get Admin and Audits for activity ID 00000000-0000-0000-9701-0080000000df on Server ADFSSRV1 and ADFSSRV2, including debug traces and save the result in an HTML file.

.NOTES
You need to run this function using an account that has permissions to read the event logs in all computers supplied.
This is typically achieved having the account be part of the "Event Log Readers" Local Security Group.
The computers supplied also should have firewall rules configured to allow remote readings.
#>
Function Get-AdfsServerTrace
{
    [CmdletBinding()]
    param
	(
        [Parameter(Mandatory=$true)] 
        [ValidateNotNullOrEmpty()] 
		[string]
		$ActivityId,
		
        [switch]
        $IncludeDebug,

        [string]
        $OutHtmlFilePath,

        [string[]]
        $ComputerName = @("localhost")
	)

    #Get the background jobs to search all computers in parallel, and retrieve the results
    $jobs = Start-AdfsServerTrace -ActivityId $ActivityId -IncludeDebug:$IncludeDebug -ComputerName $ComputerName
    $results = Receive-AdfsServerTrace -Jobs $jobs

    if ($OutHtmlFilePath)
	{
		$results | ConvertTo-Html | Out-File $OutHtmlFilePath -Force
		Write-Output "Report Generated at $OutHtmlFilePath"  
		Start $OutHtmlFilePath 
	}
	else
	{
	    Write-Output $results	
	}
}


Function Get-AdfsVersionEx
{    
    [CmdletBinding()]
    param()

    $OSVersion = [Environment]::OSVersion.Version

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

Export-ModuleMember -Function Get-AdfsSystemInformation;
Export-ModuleMember -Function Get-AdfsServerConfiguration;

Export-ModuleMember -Function Start-AdfsServerTrace;
Export-ModuleMember -Function Receive-AdfsServerTrace;
Export-ModuleMember -Function Get-AdfsServerTrace;

Export-ModuleMember -Function Test-AdfsServerHealth;
Export-ModuleMember -Function Test-AdfsServerToken;

#for testing
Export-ModuleMember -Function Set-ADFSDiagTestMode;
Export-ModuleMember -Function Get-AdfsVersionEx;
Export-ModuleMember -Function Test-AdfsServerHealthSingleCheck;
# SIG # Begin signature block
# MIIauQYJKoZIhvcNAQcCoIIaqjCCGqYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8I7HpuEuQ80UFIHeH40aFrdK
# c+GgghWCMIIEwzCCA6ugAwIBAgITMwAAAGJBL8dNiq4TJgAAAAAAYjANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTUwMjEwMTgzMzM3
# WhcNMTYwNTEwMTgzMzM3WjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkMwRjQtMzA4Ni1ERUY4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzpcpEnjOg16e
# fCoOjWmTxe4NOad07kj+GNlAGb0eel7cppX64uGPcUvvOPSAmxheqTjM2PBEtHGN
# qjqD6M7STHM5hsVJ0dWsK+5KEY8IbIYHIxJJrNyF5rDLJ3lKlKFVo1mgn/oZM4cM
# CgfokLOayjIvyxuJIFrFbpO+nF+PhuI3MYT+lsHKdg2ErCNF0Y3KNvmDtP9XBiRK
# iGS7pVlKB4oaueB+94csweq7LXrUTrOcP8a6hRKzNqjR4pAcybwv508B4otK+jbX
# lmE2ldsEysu9mwjN1fyDVSnWheoGZiXw3pxG9FeeXsOkNLibTtUVrjkcohq6hvb7
# 7q4dco7enQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFJsuiFXbFF3ayMLtg9j5aH6D
# oTnHMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAAytzvTw859N7K64VMzmnhXGV4ZOeMnn/AJgqOUGsIrVqmth
# oqscqKq9fSnj3QlC3kyXFID7S69GmvDfylA/mu6HSe0mytg8svbYu7p6arQWe8q1
# 2kdagS1kFPBqUySyEx5pdI0r+9WejW98lNiY4PNgoqdvFZaU4fp1tsbJ8f6rJZ7U
# tVCLOYHbDvlhU0LjKpbCgZ0VlR4Kk1SUuclxtIVETpHS5ToC1EzQRIGLsvkOxg7p
# Kf/MkuGM4R4dYIVZpPQYLeTb0o0hdnXXez1za9a9zaa/imKXyiV53z1loGFVVYqH
# AnYnCMw5M16oWdKeG7OaT+qFQL5aK0SaoZSHpuswggTsMIID1KADAgECAhMzAAAA
# ymzVMhI1xOFVAAEAAADKMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTE0MDQyMjE3MzkwMFoXDTE1MDcyMjE3MzkwMFowgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJZxXe0GRvqEy51bt0bHsOG0ETkDrbEVc2Cc66e2bho8
# P/9l4zTxpqUhXlaZbFjkkqEKXMLT3FIvDGWaIGFAUzGcbI8hfbr5/hNQUmCVOlu5
# WKV0YUGplOCtJk5MoZdwSSdefGfKTx5xhEa8HUu24g/FxifJB+Z6CqUXABlMcEU4
# LYG0UKrFZ9H6ebzFzKFym/QlNJj4VN8SOTgSL6RrpZp+x2LR3M/tPTT4ud81MLrs
# eTKp4amsVU1Mf0xWwxMLdvEH+cxHrPuI1VKlHij6PS3Pz4SYhnFlEc+FyQlEhuFv
# 57H8rEBEpamLIz+CSZ3VlllQE1kYc/9DDK0r1H8wQGcCAwEAAaOCAWAwggFcMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQfXuJdUI1Whr5KPM8E6KeHtcu/
# gzBRBgNVHREESjBIpEYwRDENMAsGA1UECxMETU9QUjEzMDEGA1UEBRMqMzE1OTUr
# YjQyMThmMTMtNmZjYS00OTBmLTljNDctM2ZjNTU3ZGZjNDQwMB8GA1UdIwQYMBaA
# FMsR6MrStBZYAck3LjMWFrlMmgofMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8w
# OC0zMS0yMDEwLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzA4LTMx
# LTIwMTAuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQB3XOvXkT3NvXuD2YWpsEOdc3wX
# yQ/tNtvHtSwbXvtUBTqDcUCBCaK3cSZe1n22bDvJql9dAxgqHSd+B+nFZR+1zw23
# VMcoOFqI53vBGbZWMrrizMuT269uD11E9dSw7xvVTsGvDu8gm/Lh/idd6MX/YfYZ
# 0igKIp3fzXCCnhhy2CPMeixD7v/qwODmHaqelzMAUm8HuNOIbN6kBjWnwlOGZRF3
# CY81WbnYhqgA/vgxfSz0jAWdwMHVd3Js6U1ZJoPxwrKIV5M1AHxQK7xZ/P4cKTiC
# 095Sl0UpGE6WW526Xxuj8SdQ6geV6G00DThX3DcoNZU6OJzU7WqFXQ4iEV57MIIF
# vDCCA6SgAwIBAgIKYTMmGgAAAAAAMTANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQD
# EyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwODMx
# MjIxOTMyWhcNMjAwODMxMjIyOTMyWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJyWVwZMGS/HZpgICBC
# mXZTbD4b1m/My/Hqa/6XFhDg3zp0gxq3L6Ay7P/ewkJOI9VyANs1VwqJyq4gSfTw
# aKxNS42lvXlLcZtHB9r9Jd+ddYjPqnNEf9eB2/O98jakyVxF3K+tPeAoaJcap6Vy
# c1bxF5Tk/TWUcqDWdl8ed0WDhTgW0HNbBbpnUo2lsmkv2hkL/pJ0KeJ2L1TdFDBZ
# +NKNYv3LyV9GMVC5JxPkQDDPcikQKCLHN049oDI9kM2hOAaFXE5WgigqBTK3S9dP
# Y+fSLWLxRT3nrAgA9kahntFbjCZT6HqqSvJGzzc8OJ60d1ylF56NyxGPVjzBrAlf
# A9MCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMsR6MrS
# tBZYAck3LjMWFrlMmgofMAsGA1UdDwQEAwIBhjASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBT90TFO0yaKleGYYDuoMW+mPLzYLTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAWgBQOrIJgQFYnl+UlE/wq4QpTlVnk
# pDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEE
# SDBGMEQGCCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY3Jvc29mdFJvb3RDZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAgEAWTk+
# fyZGr+tvQLEytWrrDi9uqEn361917Uw7LddDrQv+y+ktMaMjzHxQmIAhXaw9L0y6
# oqhWnONwu7i0+Hm1SXL3PupBf8rhDBdpy6WcIC36C1DEVs0t40rSvHDnqA2iA6VW
# 4LiKS1fylUKc8fPv7uOGHzQ8uFaa8FMjhSqkghyT4pQHHfLiTviMocroE6WRTsgb
# 0o9ylSpxbZsa+BzwU9ZnzCL/XB3Nooy9J7J5Y1ZEolHN+emjWFbdmwJFRC9f9Nqu
# 1IIybvyklRPk62nnqaIsvsgrEA5ljpnb9aL6EiYJZTiU8XofSrvR4Vbo0HiWGFzJ
# NRZf3ZMdSY4tvq00RBzuEBUaAF3dNVshzpjHCe6FDoxPbQ4TTj18KUicctHzbMrB
# 7HCjV5JXfZSNoBtIA1r3z6NnCnSlNu0tLxfI5nI3EvRvsTxngvlSso0zFmUeDord
# EN5k9G/ORtTTF+l5xAS00/ss3x+KnqwK+xMnQK3k+eGpf0a7B2BHZWBATrBC7E7t
# s3Z52Ao0CW0cgDEf4g5U3eWh++VHEK1kmP9QFi58vwUheuKVQSdpw5OPlcmN2Jsh
# rg1cnPCiroZogwxqLbt2awAdlq3yFnv2FoMkuYjPaqhHMS+a3ONxPdcAfmJH0c6I
# ybgY+g5yjcGjPa8CQGr/aZuW4hCoELQ3UAjWwz0wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBKEwggSd
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAymzVMhI1xOFV
# AAEAAADKMAkGBSsOAwIaBQCggbowGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIGi
# PW3bAJH0CV+yCeec79yXN3F2MFoGCisGAQQBgjcCAQwxTDBKoCqAKABBAEQARgBT
# AEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAHAAcwBtADGhHIAaaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tLyAwDQYJKoZIhvcNAQEBBQAEggEASK/g5ifsJa59qZGBhW9X
# 8bxqqLSM1vP1vDY/TmIPjjY30KE3w+rJyAAJv0iNxqp/bNbfKGp7uF6aMqabAdZI
# CfK8hhJ8MzRn+nFkt0lT+dnPep/3nUWzNlnjbE8x1/BLxQsSSM9Iz7ZZAU/kcNXP
# /DnpkT1C99zSW6w35Si17Js0zA9F2MLH58omuYYBpEiqSvx7NXL7hyoqzfoSUcK9
# ykuKjKmhX6zpWsMiJfMETWyRalBdtbgMKCo12CpFBCKdNov8AFWOi9Sv+Qu12Mtv
# IQ2iwiQIlZ8aBqv6I9U9qNHxsXJyzmCxbMjsd2R1KH0Wm1R5Xte8bc0PfV3F5f/H
# AqGCAigwggIkBgkqhkiG9w0BCQYxggIVMIICEQIBATCBjjB3MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0ECEzMAAABiQS/HTYquEyYAAAAAAGIwCQYFKw4DAhoFAKBdMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE1MDIxMTE5
# MTgwOVowIwYJKoZIhvcNAQkEMRYEFA4OrG5IpMYabAUgHsOtfHE5G/96MA0GCSqG
# SIb3DQEBBQUABIIBAK/fdAku29gcf8DqG9x6/Gu7JZk/ejISCrlkoa9WW/2KQUdS
# TyIlBCHYvg5ReY2a5L8pncWydw8kXfNojET7zb55Q7xBcw8xmTH2M1m89pq1wDKS
# z/ogFvE5TTYq5so/Gxr0DPVlEceLVercXl2HljvMofm5MPAJQweJ9xNBktBoza8h
# X+FCwKG6tzful3PinnYV/jaCKIG+sVtHNIiMzfDWAjkrKBa2CzyixI0YQlD1l5+W
# 826/Wn9V0NU60CG7EcR8O0FWYUE7y9oWhllsBfrIbTTGE16KEh39FEw7nglM0Bs2
# RscvVUzWx84IfiSAPV832w8khx1Kzv07V7EUGq4=
# SIG # End signature block
