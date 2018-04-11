# AD FS Environment Diagnostics

## Overview

This module provides cmdlets that can be used to perform various tests on AD FS and WAP servers. The tests can help ensure that the AD FS / WAP service are up and running. Using the cmdlets in the module, you can root cause a service level issue faster.

## Requirements

1. AD FS environment (2012R2 or higher) or WAP environment

## Getting Started

### Install through PowerShell Gallery (Recommended)

1. Install the PowerShell Module

    In a PowerShell window, run the following:

    `Install-Module -Name ADFSDiagnostics -Force`

2. Import the PowerShell Module

    In a PowerShell window, run the following:

    `Import-Module ADFSDiagnostics`

3. Run the cmdlet of your choice, with the required parameters (see below for details)


### Install manually

1. [Download the repository](https://github.com/Microsoft/adfsManagementTools/zipball/master)
2. Unzip the download and copy `ADFSDiagnostics` folder to `C:\Program Files\WindowsPowerShell\Modules\`
3. Import the PowerShell Module

    In a PowerShell window, run the following:

    `Import-Module ADFSDiagnostics`

4. Run the cmdlet of your choice, with the required parameters (see below for details)

## Available Cmdlets

1. `Get-AdfsSystemInformation`: This command gathers information regarding operating system and hardware
2. `Get-AdfsServerConfiguration`: This command takes a snapshot of the AD FS farm configuration and relevant dependencies
3. `Test-AdfsServerToken`: This command verifies if you can reach AD FS service and get a token issued for the credentials supplied or the identity under which the cmdlet is run
4. `Test-AdfsServerHealth`: This command performs health checks of the server. The health checks are role-specific (WAP or AD FS)

## Get-AdfsSystemInformation

* **No parameters**

**Usage**: `Get-AdfsSystemInformation`

```
    PS > Get-AdfsSystemInformation


        OSVersion                 : 10.0.16257.0
        OSName                    : Microsoft Windows Server Standard
        MachineDomain             : CONTOSO.com
        IPAddress                 : 1.2.3.4
        TimeZone                  : Pacific Standard Time
        LastRebootTime            : 2/8/2018 7:23:17 PM
        MachineType               : Virtual Machine
        NumberOfLogicalProcessors : 8
        MaxClockSpeed             : 3591
        PhsicalMemory             : 4096
        Hosts                     : {}
        Hotfixes                  : {}
        AdfsWmiProperties         : {ConfigurationDatabaseConnectionString, ConfigurationServiceAddress, ConfigurationChannelMaxMessageSizeInBytes}
        SslBindings               : {System.Collections.Hashtable, System.Collections.Hashtable, System.Collections.Hashtable, System.Collections.Hashtable...}
        AdfssrvServiceAccount     : CONTOSO\FsSvcAcct
        AdfsVersion               : 3.0
        Role                      : STS
        Top10ProcessesByMemory    : {@{Name=dns; MemoryInMB=447.75390625; MemoryPercentOfTotal=10.9314918518066}, @{Name=Microsoft.IdentityServer.ServiceHost;
                                    MemoryInMB=270.51953125; MemoryPercentOfTotal=6.6044807434082}, @{Name=sqlservr; MemoryInMB=227.234375;
                                    MemoryPercentOfTotal=5.54771423339844}, @{Name=MsMpEng; MemoryInMB=98.8359375; MemoryPercentOfTotal=2.41298675537109}...}
        AdHealthAgentInformation  : AdHealthAgentInformation
```

## Get-AdfsServerConfiguration

* **IncludeTrusts**: Boolean switch to indicate whether trusts (claims provider and relying party) configuration is also to be retrieved

**Usage**: `$res = Get-AdfsServerConfiguration –IncludeTrusts`

```
    PS > $res.ADFSRelyingPartyTrustCount
    0
    PS > $res.ADFSClaimDescription


        ClaimType  : http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
        IsAccepted : True
        IsOffered  : True
        IsRequired : False
        Name       : E-Mail Address
        ShortName  : email
        Notes      : The e-mail address of the user

        ClaimType  : http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
        IsAccepted : True
        IsOffered  : True
        IsRequired : False
        Name       : Given Name
        ShortName  : given_name
        Notes      : The given name of the user

        ClaimType  : http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
        IsAccepted : True
        IsOffered  : True
        IsRequired : False
        Name       : Name
        ShortName  : unique_name
        Notes      : The unique name of the user

        ClaimType  : http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn
        IsAccepted : True
        IsOffered  : True
        IsRequired : False
        Name       : UPN
        ShortName  : upn
        Notes      : The user principal name (UPN) of the user

        ClaimType  : http://schemas.xmlsoap.org/claims/CommonName
        IsAccepted : True
        IsOffered  : True
        IsRequired : False
        Name       : Common Name
        ShortName  : commonname
        Notes      : The common name of the user

        (more info) ...



        PS > $res.ADFSDeviceRegistration


        DrsObjectDN                          : CN=DeviceRegistrationService,CN=Device Registration Services,CN=Device Registration
                                            Configuration,CN=Services,CN=Configuration,DC=CONTOSO,DC=com
        DevicesPerUser                       : 10
        MaximumInactiveDays                  : 90
        DeviceObjectLocation                 : CN=RegisteredDevices,DC=CONTOSO,DC=com
        IsAdfsServiceAuthorizationReady      : True
        IsDirectoryConfigured                : True

        (more info) ...
```

## Test-AdfsServerToken
* **FederationServer**: Federation Server (Farm) host name Federation Server (Farm) host name
* **AppliesTo**: Identifier of the target relying party
* **Credential**: Optional Username Credential used to retrieve the token

**Usage**: `Test-AdfsServerToken -FederationServer sts.contoso.com -AppliesTo urn:examplerpt`

## Test-AdfsServerHealth
* **verifyO365**: Boolean parameter that will enable Office 365 targeted checks. It is true by default
* **verifyTrustCerts**: Boolean parameter that will enable additional checks for relying party trust and claims provider trust certificates. It is false by default
* **sslThumbprint**: String parameter that is the thumbprint of the AD FS SSL certificate. This is required while running health checks on a proxy server.
* **adfsServers**: Array of fully qualified domain names (FQDN) of all of the AD FS STS servers that you want to run health checks on. For Windows Server 2016 this is automatically populated using Get-AdfsFarmInformation. By default the tests are already run on the local machine, so it is not necessary to include the FQDN of the current machine in this parameter.
* **local**: Switch to indicate that you only want to run the health checks on the local machine.

### AD FS STS servers
**Important**: To get the most diagnosability you should run the health checks from your primary AD FS server.

**Example Usage**

*Running health checks on specific servers:*

`$ret = Test-AdfsServerHealth -VerifyOffice365:<$true / $false> -VerifyTrustCerts:<$true / $false> -adfsServers @("sts1.contoso.com", "sts2.contoso.com", "sts3.contoso.com")`

*Running health checks only on the local server:*

`$ret = Test-AdfsServerHealth -VerifyOffice365:<$true / $false> -VerifyTrustCerts:<$true / $false> -local`

*Running health checks on farm nodes automatically enumerated (Only applicable for WS2016 farms):*

`$ret = Test-AdfsServerHealth -VerifyOffice365:<$true / $false> -VerifyTrustCerts:<$true / $false>`

### AD FS Proxy servers
**Usage**: `$ret = Test-AdfsServerHealth -sslThumbprint <AD FS SSL thumbprint>`

### Understanding the results

####  General Information
Run the cmdlet with the parameters as necessary and save the return value in a variable (in this case it is $ret). This variable will expose the following properties.

* `AllTests`: This is a list of all of the tests that were run.
* `PassedTests`: This is a list of all of the tests that passed.
* `WarningTests`: This is a list of all of the tests that resulted in a warning.
* `FailedTests`: This is a list of all of the tests that failed.
* `ErrorTests`: This is a list of all of the tests that threw an exception due to a test configuration problem or a bug. This should not occur.
* `NotRunTests`: This is a list of all of the tests that were not run because they were not applicable.

Additionally, you are also able to search for a specific test case by its name using the [] operator on the return value. [See example usage >](#Searching-for-a-specific-test-case)

```
    PS > $ret = Test-AdfsServerHealth
    PS > $ret

        AllTests     : {IsAdfsRunning, IsWidRunning, PingFederationMetadata, CheckAdfsSslBindings...}
        PassedTests  : {IsAdfsRunning, IsWidRunning, PingFederationMetadata, CheckAdfsSslBindings...}
        WarningTests : {}
        FailedTests  : {TestAdfsAuditPolicyEnabled}
        ErrorTests   : {}
        NotRunTests  : {Test-Certificate-Token-Decrypting-Primary-NotFoundInStore, Test-Certificate-Token-Decrypting-Primary-IsSelfSigned,
                    Test-Certificate-Token-Decrypting-Primary-PrivateKeyAbsent, Test-Certificate-Token-Decrypting-Primary-AboutToExpire...}
```

Each health check that were run return a class that contains the following.
* `Name`: Mnemonic identifier for the test.
* `ComputerName`: The name of the computer the test was run on.
* `Result`: One value of 'Pass','Fail','NotRun','Error','Warning'.
* `Detail`: Explanation of the 'Fail', 'NotRun', and 'Warning' result. It is typically empty when the check passes.
* `Output`: Data collected for the specific test. It is a list of Key value pairs.
* `ExceptionMessage`: If the test encountered an exception, this property contains the exception message.
* `Exception`: If the test encountered an exception, this property contains the exception.

```
    PS > $ret.AllTests[0]

        Name             : IsAdfsRunning
        ComputerName     : Localhost
        Result           : Pass
        Detail           :
        Output           : {ADFSServiceState}
        ExceptionMessage :
        Exception        :
```

### Examples of using the results
#### Enumerating all of the results
```
    PS > $ret.AllTests

        Name             : IsAdfsRunning
        ComputerName     : Localhost
        Result           : Pass
        Detail           :
        Output           : {ADFSServiceState}
        ExceptionMessage :
        Exception        :

        Name             : IsWidRunning
        ComputerName     : Localhost
        Result           : Pass
        Detail           :
        Output           : {WIDServiceState, WIDServiceStartMode}
        ExceptionMessage :
        Exception        :

        (more info) ...
```

#### Enumerating all of the failed health checks

```
    PS > $ret.FailedTests

        Name             : TestAdfsAuditPolicyEnabled
        ComputerName     : Localhost
        Result           : Fail
        Detail           : Audits are not configured for Usage data collection : Expected 'Success and Failure', Actual='No Auditing'
        Output           : {StsAuditConfig, MachineAuditPolicy}
        ExceptionMessage :
        Exception        :

        (more info) ...

```

#### Searching for a specific test case

```
    PS > $ret["Test-Certificate-Token-Decrypting-Primary-IsSelfSigned"]

        Name             : Test-Certificate-Token-Decrypting-Primary-IsSelfSigned
        ComputerName     : Localhost
        Result           : NotRun
        Detail           : Check Skipped when AutoCertificateRollover is enabled
        Output           : {Thumbprint}
        ExceptionMessage :
        Exception        :

        Name             : Test-Certificate-Token-Decrypting-Primary-IsSelfSigned
        ComputerName     : AADTESTINGADFS2.AADTESTING.INFO
        Result           : NotRun
        Detail           : This check does not run on AD FS Secondary Server
        Output           :
        ExceptionMessage :
        Exception        :

        (more info) ...
```

## Contributing
You are welcome to contribute to the module and provide suggestions. We encourage you to fork this project, include any scripts you
use for managing AD FS, and then do a pull request to master. If your scripts work,
we'll include them so everyone can benefit.

Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the
right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.