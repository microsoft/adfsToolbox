function AdfsConfiguration
{
    $configurationOutput = New-Object PSObject;
    $ErrorActionPreference = "SilentlyContinue"

    # Get Major value of the operating system 
    $MajorOsVersion = ([environment]::OSVersion.Version).Major;
    $configurationOutput | Add-Member NoteProperty -name "MajorOsVersion" -value $MajorOsVersion -Force;

    # Get Farm Behavior Level and ADFS Servers
    $adfsFarmInformation = Get-AdfsFarmInformation;
    [array]$adfsServers = $adfsFarmInformation.FarmNodes.FQDN;
    $configurationOutput | Add-Member NoteProperty -name "CurrentFarmBehavior" -value $adfsFarmInformation.CurrentFarmBehavior -Force;
    $configurationOutput | Add-Member NoteProperty -name "AdfsServers" -value $adfsServers -Force;

    #Get the connected WAP servers
    [array]$wapServers = (Get-WebApplicationProxyConfiguration).ConnectedServersName;
    $configurationOutput | Add-Member NoteProperty -name "WapServers" -value $wapServers -Force;

    # Get Operating system
    $operatingSystem =  (Get-WmiObject -class Win32_OperatingSystem).Caption;
    $configurationOutput | Add-Member NoteProperty -name "OperatingSystem" -value $operatingSystem -Force;

    # Get Adfs Properties
    $adfsProperties =   Get-AdfsProperties;

    # Get Database
    $database = $adfsProperties.ArtifactDbConnection;
    if($database.ToLower().Contains("wid") -or $database.ToLower().Contains("ssee"))
    {
        $database  = "Windows Internal Database";
    }else{
        $database  = "External SQL Server";
    }
    $configurationOutput | Add-Member NoteProperty -name "Database" -value $database -Force;

    # Get Federation service name
    $configurationOutput | Add-Member NoteProperty -name "FederationServiceName" -value $adfsProperties.Hostname -Force;

    # Get Service account and Service type
    $serviceAccount = (gwmi win32_service -filter "name='adfssrv'").StartName;
    if($serviceAccount.EndsWith("$")){
        $serviceType = "GMSA"; 
    }else{
        $serviceType = "Standard service account";
    }
    $configurationOutput | Add-Member NoteProperty -name "ServiceAccount" -value $serviceAccount -Force;
    $configurationOutput | Add-Member NoteProperty -name "ServiceAccountType" -value $serviceType -Force;

    # Get Service account SPN
    if($null -ne $serviceAccount){
        $serviceAccountSPN = setspn -L $serviceAccount;
    }
    $configurationOutput | Add-Member NoteProperty -name "ServiceAccountSpn" -value $serviceAccountSPN -Force;

    # Get ADFS Global authentication policy
    $globalAuthenticationPolicyOuput = New-Object PSObject;
    $globalAuthenticationPolicy = Get-AdfsGlobalAuthenticationPolicy;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "AdditionalAuthenticationProvider" -value $globalAuthenticationPolicy.AdditionalAuthenticationProvider -Force;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "DeviceAuthenticationEnabled" -value $globalAuthenticationPolicy.DeviceAuthenticationEnabled -Force;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "AllowAdditionalAuthenticationAsPrimary" -value $globalAuthenticationPolicy.AllowAdditionalAuthenticationAsPrimary -Force;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "EnablePaginatedAuthenticationPages" -value $globalAuthenticationPolicy.EnablePaginatedAuthenticationPages -Force;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "DeviceAuthenticationMethod" -value $globalAuthenticationPolicy.DeviceAuthenticationMethod -Force;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "TreatDomainJoinedDevicesAsCompliant" -value $globalAuthenticationPolicy.TreatDomainJoinedDevicesAsCompliant -Force;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "PrimaryIntranetAuthenticationProvider" -value $globalAuthenticationPolicy.PrimaryIntranetAuthenticationProvider -Force;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "PrimaryExtranetAuthenticationProvider" -value $globalAuthenticationPolicy.PrimaryExtranetAuthenticationProvider -Force;
    $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "WindowsIntegratedFallbackEnabled" -value $globalAuthenticationPolicy.WindowsIntegratedFallbackEnabled -Force;
    try{
        $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "ClientAuthenticationMethods" -value $globalAuthenticationPolicy.ClientAuthenticationMethods.ToString() -Force; 
    }
    catch [Exception]
    {
        $globalAuthenticationPolicyOuput | Add-Member NoteProperty -name "ClientAuthenticationMethods" -value $globalAuthenticationPolicy.ClientAuthenticationMethods -Force; 
    }
    $configurationOutput | Add-Member NoteProperty -name "AdfsGlobalAuthenticationPolicy" -value $globalAuthenticationPolicyOuput -Force;
    
    # Get ADFS SSL Certificates
    $sslCertificateHash = Get-AdfsSslCertificate | Select-Object CertificateHash;
    $sslCertificate = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object Thumbprint -contains $sslCertificateHash[0].CertificateHash | Select-Object Issuer, NotBefore, NotAfter, Thumbprint    
    $configurationOutput | Add-Member NoteProperty -name "AdfsSslCertificate" -value $sslCertificate -Force;

    # Get ADFS Cerificates
    [array]$certificates = Get-AdfsCertificate -CertificateType "Token-Signing" | Select-Object -Property IsPrimary, CertificateType, @{Name="Certificate"; Expression={$_.Certificate | Select-Object Issuer, NotBefore, NotAfter, Thumbprint}}
    $configurationOutput | Add-Member NoteProperty -name "AdfsCertificate" -value $certificates -Force;

    # Get ADFS Relying party trust
    [array]$relyingPartyTrust = Get-AdfsRelyingPartyTrust | Select-Object -Property Name, Identifier, ProtocolProfile, AccessControlPolicyName, IssuanceAuthorizationRules, AdditionalAuthenticationRules, IssuanceTransformRules;
    $configurationOutput | Add-Member NoteProperty -name "AdfsRelyingPartyTrust" -value $relyingPartyTrust -Force;
    
    $ErrorActionPreference = "Continue"
    return $configurationOutput;
}