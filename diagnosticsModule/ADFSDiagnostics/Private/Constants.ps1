####################################
# Constants
####################################
$adfs3 = "3.0";
$adfs2x = "2.0";
$adfsRoleSTS = "STS";
$adfsRoleProxy = "Proxy";
$tpKey = "Thumbprint";
$sslCertType = "SSL";
$adfsServiceName = "adfssrv";
$adfsProxyServiceName = "appproxysvc";
$adfsApplicationId = "{5d89a20c-beab-4389-9447-324788eb944a}";
$TlsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS {0}";
$TlsServerPath = "{0}\Server";
$TlsClientPath = "{0}\Client";
$timeDifferenceMaximum = 300; #seconds

$none = "NONE";
$script:adfsProperties = $null;
$script:isAdfsSyncPrimaryRole = $null;

# Email address regex taken from MSDN: http://msdn.microsoft.com/en-us/library/01escwtf.aspx
$EmailAddressRegex = "^(?("")("".+?(?<!\\)""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-0-9a-z]*[0-9a-z]*\.)+[a-z0-9][\-a-z0-9]{0,22}[a-z0-9]))$";

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