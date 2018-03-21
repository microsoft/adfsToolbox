####################################
# Constants
####################################
$adfs3 = "3.0"
$adfs2x = "2.0"
$tpKey = "Thumbprint"
$sslCertType = "SSL"

$none = "NONE"
$script:adfsProperties = $null
$script:isAdfsSyncPrimaryRole = $null

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