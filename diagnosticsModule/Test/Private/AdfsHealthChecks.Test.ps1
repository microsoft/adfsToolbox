# Determine our script root
$parent = Split-Path $PSScriptRoot -Parent
$script:root = Split-Path $parent -Parent
# Load module via definition
Import-Module $root\ADFSDiagnosticsModule.psm1 -Force

InModuleScope ADFSDiagnosticsModule {
    # Shared constants
    $sharedError = "Error message"
    $sharedErrorException = "System.Management.Automation.RuntimeException: Error message"

    Describe "TestTrustedDevicesCertificateStore" {
        It "should pass" {
            # Arrange
            Mock -CommandName Get-Item -MockWith { return New-Object PSObject -Property @{
                    "StoreNames" = @{"AdfsTrustedDevices" = $true}
                }}

            # Act
            $ret = TestTrustedDevicesCertificateStore

            # Assert
            $ret.Result | should beexactly Pass
        }

        It "should fail" {
            # Arrange
            Mock -CommandName Get-Item -MockWith { return New-Object PSObject -Property @{
                    "StoreNames" = @{}
                }}

            # Act
            $ret = TestTrustedDevicesCertificateStore

            # Assert
            $ret.Result | should beexactly Fail
            $ret.Detail | should beexactly "The AdfsTrustedDevices certificate store does not exist."
        }

        It "should error" {
            Mock -CommandName Get-Item -MockWith { throw $sharedError }

            # Act
            $ret = TestTrustedDevicesCertificateStore

            # Assert
            $ret.Result | should beexactly Error
            $ret.ExceptionMessage | should beexactly $sharedError
            $ret.Exception | should beexactly $sharedErrorException
        }
    }

    Describe "TestAdfsPatches" {
        It "should pass" {
            # Arrange
            Mock -CommandName Get-OsVersion -MockWith { return [OSVersion]::WS2012R2 }
            Mock -CommandName Get-HotFix -MockWith { return $true }

            # Act
            $ret = TestAdfsPatches

            # Assert
            $ret.Result | should beexactly Pass
        }

        It "should fail" {
            # Arrange
            Mock -CommandName Get-OsVersion -MockWith { return [OSVersion]::WS2012R2 }
            Mock -CommandName Get-HotFix -MockWith { return $false }

            # Act
            $ret = TestAdfsPatches

            # Assert
            $ret.Result | should beexactly Fail
            $ret.Detail | should beexactly "There were missing patches that are not installed."

            $ret.Output.MissingAdfsPatches | should not benullorempty
        }

        It "should not run" {
            # Arrange
            Mock -CommandName Get-OsVersion -MockWith { return [OSVersion]::WS2016 }

            # Act
            $ret = TestAdfsPatches

            # Assert
            $ret.Result | should beexactly NotRun
        }


        It "should error" {
            # Arrange
            Mock -CommandName Get-OsVersion -MockWith { throw $sharedError }

            # Act
            $ret = TestAdfsPatches

            # Assert
            $ret.Result | should beexactly Error
            $ret.ExceptionMessage | should beexactly $sharedError
            $ret.Exception | should beexactly $sharedErrorException
        }
    }

    Describe "TestServicePrincipalName" {

        BeforeAll {
            $_upnServiceAccount = "aadcsvc@contoso.com"
            $_samServiceAccount = "contoso\aadcsvc"
            $_path = "CN=aadcsvc,CN=Managed Service Accounts,DC=contoso,DC=com"
            $_fullPath = "LDAP://$_path"
            $_incorrectLdapPath = "LDAP://CN=badAccount,CN=Managed Service Accounts,DC=contoso,DC=com"
            $_hostname = "sts.contoso.com"
        }

        Context "should pass" {
            BeforeAll {
                Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
                Mock -CommandName IsLocalUser -MockWith { return $false }
                Mock -CommandName IsAdfsServiceRunning -MockWith { return $true }
                Mock -CommandName GetObjectsFromAD -MockWith { return New-Object PSObject -Property @{ "Path" = $_fullPath } }
                Mock -CommandName Retrieve-AdfsProperties -MockWith { return New-Object PSObject -Property @{ "Hostname" = $_hostname }}
                Mock -CommandName Invoke-Expression -MockWith { return @("Existing SPN found!", $_path) } -ParameterFilter { $Command -eq "setspn -f -q HOST/$_hostname"}
                Mock -CommandName Invoke-Expression -MockWith { return @("Existing SPN found!", $_path) } -ParameterFilter { $Command -eq "setspn -f -q HTTP/$_hostname"}
            }

            It "should pass when service account is in UPN format" {
                # Arrange
                Mock -CommandName Get-WmiObject -MockWith { return New-Object PSObject -Property @{ "StartName" = $_upnServiceAccount; "Name" = $adfsServiceName } }

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly Pass
            }

            It "should pass when service account is in SAM format" {
                # Arrange
                Mock -CommandName Get-WmiObject -MockWith { return New-Object PSObject -Property @{ "StartName" = $_samServiceAccount; "Name" = $adfsServiceName } }

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly Pass
            }

            It "should pass when no HTTP SPN is found" {
                # Arrange
                Mock -CommandName Invoke-Expression -MockWith { return @("No such SPN found.") } -ParameterFilter { $Command -eq "setspn -f -q HTTP/$_hostname"}
                Mock -CommandName Get-WmiObject -MockWith { return New-Object PSObject -Property @{ "StartName" = $_upnServiceAccount; "Name" = $adfsServiceName } }

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly Pass
            }
        }

        Context "should fail" {
            BeforeAll {
                Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
                Mock -CommandName IsLocalUser -MockWith { return $false }
                Mock -CommandName IsAdfsServiceRunning -MockWith { return $true }
                Mock -CommandName GetObjectsFromAD -MockWith { return New-Object PSObject -Property @{ "Path" = $_fullPath } }
                Mock -CommandName Retrieve-AdfsProperties -MockWith { return New-Object PSObject -Property @{ "Hostname" = $_hostname }}
                Mock -CommandName Get-WmiObject -MockWith { return New-Object PSObject -Property @{ "StartName" = $_upnServiceAccount; "Name" = $adfsServiceName } }
            }

            It "when no HOST SPN is found" {
                # Arrange
                Mock -CommandName Invoke-Expression -MockWith { return ("No such SPN found.") } -ParameterFilter { $Command -eq "setspn -f -q HOST/$_hostname"}

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly Fail
                $ret.Detail | should beexactly "No such SPN was found for $_hostname"
            }

            It "when HOST SPN resolved service account does not match" {
                # Arrange
                Mock -CommandName Invoke-Expression -MockWith { return ("Existing SPN found!" + [Environment]::NewLine + "$_incorrectLdapPath") } -ParameterFilter { $Command -eq "setspn -f -q HOST/$_hostname"}

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly Fail
                $ret.Detail | should beexactly "An existing SPN was found for HOST/$_hostname but it did not resolve to the ADFS service account."
            }

            It "when HTTP SPN resolved service account does not match" {
                # Arrange
                Mock -CommandName Invoke-Expression -MockWith { return ("Existing SPN found!" + [Environment]::NewLine + "$_path") } -ParameterFilter { $Command -eq "setspn -f -q HOST/$_hostname"}
                Mock -CommandName Invoke-Expression -MockWith { return ("Existing SPN found!" + [Environment]::NewLine + "$_incorrectLdapPath") } -ParameterFilter { $Command -eq "setspn -f -q HTTP/$_hostname"}

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly Fail
                $ret.Detail | should beexactly "An existing SPN was found for HTTP/$_hostname but it did not resolve to the ADFS service account."
            }
        }

        Context "should not run" {
            It "when on secondary server" {
                # Arrange
                Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $true }

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly NotRun
                $ret.Detail | should beexactly "This check runs only on Primary Nodes."
            }

            It "when local user" {
                # Arrange
                Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
                Mock -CommandName IsLocalUser -MockWith { return $true }

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly NotRun
                $ret.Detail | should beexactly "Current user $env:USERNAME is not a domain account. Cannot execute this test"
            }

            It "when AD FS is not running" {
                # Arrange
                Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
                Mock -CommandName IsLocalUser -MockWith { return $false }
                Mock -CommandName IsAdfsServiceRunning -MockWith { return $false }

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly NotRun
                $ret.Detail | should beexactly "AD FS service is not running"
            }
        }

        Context "should error" {
            BeforeAll {
                Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
                Mock -CommandName IsLocalUser -MockWith { return $false }
                Mock -CommandName IsAdfsServiceRunning -MockWith { return $true }
            }

            It "when service account is empty" {
                # Arrange
                Mock -CommandName Get-WmiObject -MockWith { return New-Object PSObject -Property @{"Name" = $adfsServiceName; "StartName" = $null}}

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly Error
                $ret.ExceptionMessage | should beexactly "ADFS Service account is null or empty. The WMI configuration is in an inconsistent state"
                $ret.Exception | should beexactly "System.Management.Automation.RuntimeException: ADFS Service account is null or empty. The WMI configuration is in an inconsistent state"
            }

            It "when service account is not in expected SAM format" {
                # Arrange
                Mock -CommandName Get-WmiObject -MockWith { return New-Object PSObject -Property @{"Name" = $adfsServiceName; "StartName" = "badAccount"}}

                # Act
                $ret = TestServicePrincipalName

                # Assert
                $ret.Result | should beexactly Error
                $ret.ExceptionMessage | should beexactly "Unexpected value of the service account badAccount. Expected in DOMAIN\\User format or UPN:User@Domain"
                $ret.Exception | should beexactly "System.Management.Automation.RuntimeException: Unexpected value of the service account badAccount. Expected in DOMAIN\\User format or UPN:User@Domain"
            }
        }
    }

    Describe "TestProxyTrustPropagation" {

        BeforeAll {
            $_adfsServers = @("sts1.contoso.com", "sts2.contoso.com", "sts3.contoso.com")
            $_primaryCertificates = @("Cert1", "Cert2", "Cert3")
            $_missingCertificates = @("Cert2", "Cert3")

            # since we have to mock out the remote PSSessions that gets created we just return the a PSSession to localhost
            # we create these session before the actual test because once we mock New-PSSession we cannot unmock it
            $localPSForPassTest = @()
            $localPSForFailTest = @()

            for ($i = 0; $i -lt $_adfsServers.Count; $i++)
            {
                $localPSForPassTest += New-PSSession -ComputerName localhost -ErrorAction Stop
                $localPSForFailTest += New-PSSession -ComputerName localhost -ErrorAction Stop
            }
        }

        It "should pass" {
            # Arrange
            Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
            Mock -CommandName GetCertificatesFromAdfsTrustedDevices -MockWith { return $_primaryCertificates }
            $script:itr = 0
            Mock -CommandName New-PSSession -MockWith {
                $session = $localPSForPassTest[$script:itr]
                $script:itr += 1
                return $session
            }

            # Since we get all of the functions from the private folder and run Invoke-Expression on them; that replaces the function's mock with the original function.
            # We avoid this by setting the invoke expression within this script block to do nothing.
            Mock Invoke-Command {
                Return $ScriptBlock.InvokeWithContext(@{"Invoke-Expression" = {}; "VerifyCertificatesArePresent" = { return @() }}, @())
            }

            # Act
            $ret = TestProxyTrustPropagation $_adfsServers

            # Assert
            $ret.Result | should beexactly Pass
        }

        It "should warn because no AD FS farm information was provided" {
            # Arrange
            Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
            Mock -CommandName Out-Warning -MockWith { }

            # Act
            $ret = TestProxyTrustPropagation

            # Assert
            Assert-MockCalled Out-Warning
            $ret.Result | should beexactly Warning
            $ret.Detail | should beexactly "No AD FS farm information was provided. Specify the list of servers in your farm using the -adfsServers flag."
        }

        It "should warn because it cannot connect to an AD FS server" {
            # Arrange
            Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
            Mock -CommandName GetCertificatesFromAdfsTrustedDevices -MockWith { return $_primaryCertificates }
            Mock -CommandName New-PSSession -MockWith { $null }
            Mock -CommandName Out-Warning -MockWith { }

            # Act
            $ret = TestProxyTrustPropagation $_adfsServers

            # Assert
            Assert-MockCalled Out-Warning 3
        }

        It "should fail" {
            # Arrange
            Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $false }
            Mock -CommandName GetCertificatesFromAdfsTrustedDevices -MockWith { return $_primaryCertificates }

            $script:itr = 0
            Mock -CommandName New-PSSession -MockWith {
                $session = $localPSForPassTest[$script:itr]
                $script:itr += 1
                return $session
            }

            # Since we get all of the functions from the private folder and run Invoke-Expression on them; that replaces the function's mock with the original function.
            # We avoid this by setting the invoke expression within this script block to do nothing.
            Mock Invoke-Command {
                Return $ScriptBlock.InvokeWithContext(@{"Invoke-Expression" = {}; "VerifyCertificatesArePresent" = { return $_missingCertificates }}, @())
            }

            # Act
            $ret = TestProxyTrustPropagation $_adfsServers

            # Assert
            $ret.Result | should beexactly Fail
            $ret.Detail | should beexactly "There were missing certificates on some of the secondary servers. There may be an issue with proxy trust propogation."\
            Foreach ($server in $_adfsServers)
            {
                $ret.Output.ErroneousCertificates[$server] | should be $_missingCertificates
            }
        }

        It "should not run when on secondary server" {
            # Arrange
            Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { return $true }

            # Act
            $ret = TestProxyTrustPropagation

            # Assert
            $ret.Result | should beexactly NotRun
            $ret.Detail | should beexactly "This check runs only on Primary Nodes."
        }

        It "should error" {
            # Arrange
            Mock -CommandName Test-RunningOnAdfsSecondaryServer -MockWith { throw $sharedError }

            # Act
            $ret = TestProxyTrustPropagation

            # Assert
            $ret.Result | should beexactly Error
            $ret.ExceptionMessage | should beexactly $sharedError
            $ret.Exception | should beexactly $sharedErrorException
        }
    }
}
